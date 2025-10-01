"""
Enhanced Flask Application with Real-time Workflow Features
This is an enhanced version of app_web.py with real-time capabilities
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit
from app.database import get_db, init_db
from app.workflow import workflow_engine
from app.realtime import init_realtime, get_realtime_manager
from app.security import login_required, role_required
from datetime import datetime
import json
import uuid
import logging

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize real-time manager
realtime_manager = init_realtime(socketio)

# Import existing routes from app_web.py
from app_web import *

# Enhanced routes with real-time features
@app.route('/enhanced-dashboard')
@login_required
def enhanced_dashboard():
    """Enhanced dashboard with real-time features"""
    conn = get_db()
    
    # Get user applications with real-time data
    user_id = session['user_id']
    role = session.get('role', 'user')
    
    applications = conn.execute('''
        SELECT a.*, u.first_name, u.last_name,
               COUNT(wn.id) as notification_count,
               COUNT(cc.id) as comment_count,
               MAX(a.last_activity_at) as last_activity
        FROM applications a
        LEFT JOIN users u ON a.author_id = u.id
        LEFT JOIN workflow_notifications wn ON a.id = wn.application_id
        LEFT JOIN collaboration_comments cc ON a.id = cc.application_id
        WHERE a.author_id = ?
        GROUP BY a.id
        ORDER BY a.last_activity_at DESC
    ''', (user_id,)).fetchall()
    
    # Get real-time notifications
    notifications = conn.execute('''
        SELECT * FROM workflow_notifications 
        WHERE to_user_id = ? OR (to_user_id IS NULL AND target_role = ?)
        ORDER BY created_at DESC
        LIMIT 20
    ''', (user_id, role)).fetchall()
    
    conn.close()
    
    return render_template('enhanced_dashboard.html', 
                         applications=applications,
                         notifications=notifications,
                         role=role)

@app.route('/api/workflow/real-time-status/<app_id>')
@login_required
def get_realtime_status(app_id):
    """Get real-time status for an application"""
    conn = get_db()
    
    # Get application status and progress
    app = conn.execute('''
        SELECT a.*, aa.analyst_id, aa.assigned_at, aa.started_at,
               u.first_name, u.last_name as analyst_name
        FROM applications a
        LEFT JOIN analyst_assignments aa ON a.id = aa.application_id
        LEFT JOIN users u ON aa.analyst_id = u.id
        WHERE a.id = ? AND a.author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    
    if not app:
        return jsonify({'error': 'Application not found'}), 404
    
    # Get recent activity
    activity = conn.execute('''
        SELECT * FROM activity_feed 
        WHERE application_id = ? 
        ORDER BY created_at DESC 
        LIMIT 10
    ''', (app_id,)).fetchall()
    
    # Get progress milestones
    progress = conn.execute('''
        SELECT * FROM review_progress 
        WHERE application_id = ? 
        ORDER BY created_at DESC
    ''', (app_id,)).fetchall()
    
    conn.close()
    
    return jsonify({
        'application': dict(app),
        'activity': [dict(a) for a in activity],
        'progress': [dict(p) for p in progress]
    })

@app.route('/api/workflow/send-message', methods=['POST'])
@login_required
def send_realtime_message():
    """Send real-time message"""
    data = request.get_json()
    application_id = data.get('application_id')
    message = data.get('message')
    
    if not all([application_id, message]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Store message in database
    conn = get_db()
    message_id = str(uuid.uuid4())
    
    conn.execute('''
        INSERT INTO collaboration_comments (id, application_id, user_id, comment, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (message_id, application_id, session['user_id'], message, datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    # Emit real-time message
    realtime_manager.socketio.emit('new_message', {
        'id': message_id,
        'application_id': application_id,
        'user_id': session['user_id'],
        'message': message,
        'timestamp': datetime.now().isoformat()
    }, room=f"app_{application_id}")
    
    return jsonify({'success': True, 'message_id': message_id})

@app.route('/api/workflow/request-clarification', methods=['POST'])
@role_required('security_analyst', 'admin')
def request_clarification_realtime():
    """Request clarification with real-time notification"""
    data = request.get_json()
    application_id = data.get('application_id')
    question_id = data.get('question_id')
    message = data.get('message')
    
    if not all([application_id, question_id, message]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Create clarification request
    conn = get_db()
    clarification_id = str(uuid.uuid4())
    
    # Get application author
    app = conn.execute('SELECT author_id FROM applications WHERE id = ?', (application_id,)).fetchone()
    if not app:
        return jsonify({'error': 'Application not found'}), 404
    
    conn.execute('''
        INSERT INTO clarification_requests 
        (id, application_id, question_id, analyst_id, user_id, request_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (clarification_id, application_id, question_id, session['user_id'], 
          app[0], message, datetime.now().isoformat()))
    
    # Update application status
    conn.execute('''
        UPDATE applications 
        SET status = 'pending_clarification', last_activity_at = ?
        WHERE id = ?
    ''', (datetime.now().isoformat(), application_id))
    
    conn.commit()
    conn.close()
    
    # Emit real-time notification
    realtime_manager.notify_clarification_request(application_id, question_id, message, app[0])
    
    return jsonify({'success': True, 'clarification_id': clarification_id})

@app.route('/api/workflow/respond-clarification', methods=['POST'])
@login_required
def respond_clarification_realtime():
    """Respond to clarification with real-time notification"""
    data = request.get_json()
    application_id = data.get('application_id')
    clarification_id = data.get('clarification_id')
    response = data.get('response')
    
    if not all([application_id, clarification_id, response]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Update clarification request
    conn = get_db()
    
    # Get clarification details
    clarification = conn.execute('''
        SELECT analyst_id FROM clarification_requests 
        WHERE id = ? AND application_id = ? AND user_id = ?
    ''', (clarification_id, application_id, session['user_id'])).fetchone()
    
    if not clarification:
        return jsonify({'error': 'Clarification not found'}), 404
    
    conn.execute('''
        UPDATE clarification_requests 
        SET response_message = ?, responded_at = ?, status = 'responded'
        WHERE id = ?
    ''', (response, datetime.now().isoformat(), clarification_id))
    
    # Update application status
    conn.execute('''
        UPDATE applications 
        SET status = 'in_review', last_activity_at = ?
        WHERE id = ?
    ''', (datetime.now().isoformat(), application_id))
    
    conn.commit()
    conn.close()
    
    # Emit real-time notification
    realtime_manager.notify_clarification_response(application_id, clarification[0], response)
    
    return jsonify({'success': True})

@app.route('/api/workflow/update-progress', methods=['POST'])
@analyst_required
def update_progress_realtime():
    """Update review progress with real-time notification"""
    data = request.get_json()
    application_id = data.get('application_id')
    review_id = data.get('review_id')
    progress_percentage = data.get('progress_percentage')
    milestone = data.get('milestone')
    notes = data.get('notes')
    
    if not all([application_id, review_id, progress_percentage]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Store progress update
    conn = get_db()
    progress_id = str(uuid.uuid4())
    
    conn.execute('''
        INSERT INTO review_progress 
        (id, application_id, review_id, milestone, progress_percentage, notes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (progress_id, application_id, review_id, milestone, 
          progress_percentage, notes, datetime.now().isoformat()))
    
    # Update application last activity
    conn.execute('''
        UPDATE applications 
        SET last_activity_at = ?
        WHERE id = ?
    ''', (datetime.now().isoformat(), application_id))
    
    conn.commit()
    conn.close()
    
    # Emit real-time progress update
    realtime_manager.notify_progress_update(application_id, progress_percentage, milestone)
    
    return jsonify({'success': True, 'progress_id': progress_id})

@app.route('/api/workflow/assign-analyst-realtime', methods=['POST'])
@role_required('admin')
def assign_analyst_realtime():
    """Assign analyst with real-time notification"""
    data = request.get_json()
    application_id = data.get('application_id')
    analyst_id = data.get('analyst_id')
    assignment_type = data.get('assignment_type', 'manual')
    
    if not all([application_id, analyst_id]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Create assignment
    conn = get_db()
    assignment_id = str(uuid.uuid4())
    
    conn.execute('''
        INSERT INTO analyst_assignments 
        (id, application_id, analyst_id, assigned_by, assignment_type, assigned_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (assignment_id, application_id, analyst_id, session['user_id'], 
          assignment_type, datetime.now().isoformat()))
    
    # Update application status
    conn.execute('''
        UPDATE applications 
        SET status = 'in_review', assigned_analyst_id = ?, last_activity_at = ?
        WHERE id = ?
    ''', (analyst_id, datetime.now().isoformat(), application_id))
    
    conn.commit()
    conn.close()
    
    # Emit real-time assignment notification
    realtime_manager.notify_assignment(application_id, analyst_id, assignment_type)
    
    return jsonify({'success': True, 'assignment_id': assignment_id})

# WebSocket event handlers
@socketio.on('join_application')
def handle_join_application(data):
    """Handle joining application room for real-time updates"""
    application_id = data.get('application_id')
    user_id = session.get('user_id')
    
    if application_id and user_id:
        join_room(f"app_{application_id}")
        emit('joined_application', {'application_id': application_id})
        
        # Send recent messages
        messages = realtime_manager.get_application_messages(application_id)
        emit('recent_messages', messages)

@socketio.on('leave_application')
def handle_leave_application(data):
    """Handle leaving application room"""
    application_id = data.get('application_id')
    user_id = session.get('user_id')
    
    if application_id and user_id:
        leave_room(f"app_{application_id}")
        emit('left_application', {'application_id': application_id})

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the enhanced application
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
