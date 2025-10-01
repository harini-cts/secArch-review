#!/usr/bin/env python3
"""
Enhanced SecureArch Portal with Real-time Workflow Features
This is a simplified version that focuses on the enhanced workflow features
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import check_password_hash
from app.database import get_db, init_db
from app.workflow import workflow_engine
from app.security import login_required, role_required
from datetime import datetime
import json
import uuid
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database
with app.app_context():
    init_db()

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected')
    emit('status', {'message': 'Connected to real-time server'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

@socketio.on('join_room')
def handle_join_room(data):
    """Handle joining a room"""
    room = data.get('room')
    if room:
        join_room(room)
        logger.info(f"Client joined room: {room}")
        emit('room_status', {'message': f'Joined room {room}'}, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    """Handle leaving a room"""
    room = data.get('room')
    if room:
        leave_room(room)
        logger.info(f"Client left room: {room}")
        emit('room_status', {'message': f'Left room {room}'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a message"""
    logger.info('Received message:', data)
    # Broadcast message to all connected clients
    emit('new_message', data, broadcast=True)

# Basic routes
@app.route('/')
def home():
    """Home page"""
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        email = request.form['email'].lower().strip()
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute(
            'SELECT id, email, password_hash, first_name, last_name, role FROM users WHERE email = ?', 
            (email,)
        ).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            session['role'] = user['role']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('enhanced_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/register')
def register():
    """Register page - placeholder"""
    flash('Registration is currently disabled. Please contact your administrator.', 'info')
    return redirect(url_for('login'))

@app.route('/enhanced-dashboard')
def enhanced_dashboard():
    """Enhanced dashboard with real-time features"""
    return render_template('enhanced_dashboard_simple.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# API endpoints for enhanced workflow
@app.route('/api/workflow/notifications')
@login_required
def api_get_notifications():
    """Get notifications for current user"""
    conn = get_db()
    notifications = conn.execute('''
        SELECT id, title, message, type, application_id, created_at, read_at
        FROM notifications
        WHERE user_id = ? OR (user_id IS NULL AND target_role = ?)
        ORDER BY created_at DESC
        LIMIT 50
    ''', (session['user_id'], session.get('role', 'user'))).fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'notifications': [dict(notif) for notif in notifications]
    })

@app.route('/api/workflow/notifications/<notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark notification as read"""
    conn = get_db()
    notification = conn.execute(
        'SELECT user_id FROM notifications WHERE id = ?', 
        (notification_id,)
    ).fetchone()
    
    if not notification or notification[0] != session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    conn.execute(
        'UPDATE notifications SET read_at = ? WHERE id = ?', 
        (datetime.now().isoformat(), notification_id)
    )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Notification marked as read'})

@app.route('/api/workflow/request-clarification', methods=['POST'])
@role_required('security_analyst', 'admin')
def request_clarification():
    """Request clarification with real-time notification"""
    data = request.get_json()
    application_id = data.get('application_id')
    question_id = data.get('question_id')
    message = data.get('message')
    
    if not all([application_id, message]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    # Create clarification request using workflow engine
    success, error = workflow_engine.create_clarification_request(
        application_id, session['user_id'], question_id, message
    )
    
    if success:
        # Emit real-time notification
        emit('new_notification', {
            'title': 'Clarification Requested',
            'message': f'Clarification requested for application {application_id}',
            'type': 'info',
            'application_id': application_id,
            'timestamp': datetime.now().isoformat()
        }, room=f"app_{application_id}")
        
        return jsonify({'success': True, 'message': 'Clarification request sent'})
    else:
        return jsonify({'success': False, 'error': error}), 400

@app.route('/api/workflow/respond-clarification', methods=['POST'])
@login_required
def respond_clarification():
    """Respond to clarification request"""
    data = request.get_json()
    application_id = data.get('application_id')
    response_message = data.get('response_message')
    
    if not all([application_id, response_message]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    # Respond to clarification using workflow engine
    success, error = workflow_engine.respond_to_clarification(
        application_id, session['user_id'], response_message
    )
    
    if success:
        # Emit real-time notification
        emit('new_notification', {
            'title': 'Clarification Response',
            'message': f'Response provided for application {application_id}',
            'type': 'success',
            'application_id': application_id,
            'timestamp': datetime.now().isoformat()
        }, room=f"app_{application_id}")
        
        return jsonify({'success': True, 'message': 'Response sent'})
    else:
        return jsonify({'success': False, 'error': error}), 400

@app.route('/api/workflow/collaboration-history/<app_id>')
@login_required
def collaboration_history(app_id):
    """Get collaboration history for an application"""
    history = workflow_engine.get_collaboration_history(app_id)
    return jsonify({'success': True, 'history': history})

@app.route('/api/workflow/assign-analyst', methods=['POST'])
@role_required('admin')
def assign_analyst():
    """Assign analyst to application"""
    data = request.get_json()
    application_id = data.get('application_id')
    analyst_id = data.get('analyst_id')
    assignment_type = data.get('assignment_type', 'manual')
    
    if not application_id:
        return jsonify({'success': False, 'error': 'Application ID required'}), 400
    
    if assignment_type == 'automatic':
        # Use automatic assignment
        success, error, assigned_analyst = workflow_engine.assign_analyst_automatically(application_id)
        if success:
            analyst_id = assigned_analyst
        else:
            return jsonify({'success': False, 'error': error}), 400
    elif not analyst_id:
        return jsonify({'success': False, 'error': 'Analyst ID required for manual assignment'}), 400
    
    # Update application assignment
    conn = get_db()
    conn.execute(
        'UPDATE applications SET assigned_analyst_id = ? WHERE id = ?',
        (analyst_id, application_id)
    )
    conn.commit()
    conn.close()
    
    # Emit real-time notification
    emit('new_notification', {
        'title': 'Analyst Assigned',
        'message': f'Analyst assigned to application {application_id}',
        'type': 'info',
        'application_id': application_id,
        'timestamp': datetime.now().isoformat()
    }, room=f"app_{application_id}")
    
    return jsonify({'success': True, 'message': 'Analyst assigned successfully'})

# Helper function to emit notifications
def emit_notification(user_id, notification_data):
    """Emit notification to specific user"""
    socketio.emit('new_notification', notification_data, room=f'user_{user_id}')

def emit_application_update(application_id, update_data):
    """Emit application update to relevant users"""
    socketio.emit('application_update', update_data, room=f'application_{application_id}')

if __name__ == '__main__':
    print("🚀 Starting Enhanced SecureArch Portal...")
    print("📡 Real-time features enabled")
    print("🌐 WebSocket server running")
    print("🔗 Access the application at: http://localhost:5001")
    print("📊 Enhanced dashboard: http://localhost:5001/enhanced-dashboard")
    
    # Run with eventlet for WebSocket support
    socketio.run(app, debug=True, host='0.0.0.0', port=5001, allow_unsafe_werkzeug=True)
