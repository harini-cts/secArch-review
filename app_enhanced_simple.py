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
import pytz
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'your-secret-key-here')
app.config['TIMEZONE'] = 'Asia/Kolkata'

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database
with app.app_context():
    init_db()

# Timezone configuration
IST = pytz.timezone('Asia/Kolkata')

def get_india_time():
    """Get current time in India timezone"""
    return datetime.now(IST)

def format_india_time(dt_string):
    """Format datetime string to India timezone"""
    if not dt_string:
        return None
    try:
        # Parse the datetime string
        dt = datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        # Convert to IST
        ist_dt = dt.astimezone(IST)
        return ist_dt.strftime('%Y-%m-%d %H:%M:%S IST')
    except:
        return dt_string

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
            return redirect(url_for('dashboard'))
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

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard showing recent applications (last 2)"""
    # Get user stats and recent applications
    conn = get_db()
    
    # Get all user applications for stats
    all_applications_raw = conn.execute('''
        SELECT a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
               a.status, a.created_at, a.assigned_analyst_id,
               COUNT(sr.id) as review_count
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        WHERE a.author_id = ?
        GROUP BY a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
                 a.status, a.created_at, a.assigned_analyst_id
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get recent applications (last 2)
    recent_applications_raw = conn.execute('''
        SELECT a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
               a.status, a.created_at, a.assigned_analyst_id,
               COUNT(sr.id) as review_count
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        WHERE a.author_id = ?
        GROUP BY a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
                 a.status, a.created_at, a.assigned_analyst_id
        ORDER BY a.created_at DESC
        LIMIT 2
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    # Convert all applications to list of dictionaries for stats
    all_applications = []
    for app in all_applications_raw:
        app_dict = dict(app)
        app_dict['review_count'] = app_dict['review_count'] or 0
        all_applications.append(app_dict)
    
    # Convert recent applications to list of dictionaries
    recent_applications = []
    for app in recent_applications_raw:
        app_dict = dict(app)
        app_dict['review_count'] = app_dict['review_count'] or 0
        recent_applications.append(app_dict)
    
    # Get basic stats from all applications
    app_stats = {
        'total': len(all_applications),
        'submitted': len([app for app in all_applications if app['status'] == 'submitted']),
        'in_review': len([app for app in all_applications if app['status'] == 'in_review']),
        'completed': len([app for app in all_applications if app['status'] == 'completed'])
    }
    
    return render_template('dashboard.html', 
                         applications=recent_applications,
                         app_stats=app_stats,
                         role=session.get('role', 'user'))


@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    # Fetch user data from database
    conn = get_db()
    user = conn.execute('''
        SELECT id, first_name, last_name, email, role, created_at
        FROM users WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get user stats
    applications_count = conn.execute('''
        SELECT COUNT(*) FROM applications WHERE author_id = ?
    ''', (session['user_id'],)).fetchone()[0]
    
    reviews_count = conn.execute('''
        SELECT COUNT(*) FROM security_reviews WHERE author_id = ?
    ''', (session['user_id'],)).fetchone()[0]
    
    conn.close()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    
    stats = {
        'applications': applications_count,
        'reviews': reviews_count
    }
    
    return render_template('profile.html', 
                         user=dict(user),
                         stats=stats,
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/edit-profile')
@login_required
def edit_profile():
    """Edit profile page"""
    # Fetch user data from database
    conn = get_db()
    user = conn.execute('''
        SELECT id, first_name, last_name, email, role, created_at
        FROM users WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    conn.close()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_profile.html', 
                         user=dict(user),
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/change-password')
@login_required
def change_password():
    """Change password page"""
    return render_template('change_password.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/applications')
@login_required
def applications():
    """Applications page - shows all user applications"""
    # Fetch all user applications
    conn = get_db()
    applications_raw = conn.execute('''
        SELECT a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
               a.status, a.created_at, a.assigned_analyst_id,
               COUNT(sr.id) as review_count
        FROM applications a
        LEFT JOIN security_reviews sr ON a.id = sr.application_id
        WHERE a.author_id = ?
        GROUP BY a.id, a.name, a.description, a.technology_stack, a.business_criticality, 
                 a.status, a.created_at, a.assigned_analyst_id
        ORDER BY a.created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    # Convert to list of dictionaries
    applications = []
    for app in applications_raw:
        app_dict = dict(app)
        app_dict['review_count'] = app_dict['review_count'] or 0
        applications.append(app_dict)
    
    # Get basic stats
    app_stats = {
        'total': len(applications),
        'submitted': len([app for app in applications if app['status'] == 'submitted']),
        'in_review': len([app for app in applications if app['status'] == 'in_review']),
        'completed': len([app for app in applications if app['status'] == 'completed']),
        'draft': len([app for app in applications if app['status'] == 'draft'])
    }
    
    return render_template('applications.html', 
                         applications=applications,
                         app_stats=app_stats,
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/create-application')
@login_required
def create_application():
    """Create application page - placeholder"""
    return render_template('create_application.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/results')
@login_required
def results():
    """Results page - placeholder"""
    return render_template('results.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Admin routes
@app.route('/admin/users')
@login_required
@role_required('admin')
def admin_users():
    """Admin users management - placeholder"""
    return render_template('admin/users.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/admin/applications')
@login_required
@role_required('admin')
def admin_applications():
    """Admin applications management - placeholder"""
    return render_template('admin/applications.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/admin/reports')
@login_required
@role_required('admin')
def admin_reports():
    """Admin reports - placeholder"""
    return render_template('admin/reports.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Additional admin routes
@app.route('/admin/dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    """Admin dashboard"""
    return render_template('admin/dashboard.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/admin/settings')
@login_required
@role_required('admin')
def admin_settings():
    """Admin settings page"""
    return render_template('admin/settings.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/admin/audit-logs')
@login_required
@role_required('admin')
def admin_audit_logs():
    """Admin audit logs page"""
    return render_template('admin/audit_logs.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/admin/reviews')
@login_required
@role_required('admin')
def admin_reviews():
    """Admin reviews management page"""
    return render_template('admin/reviews.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Application detail routes
@app.route('/applications/<app_id>')
@login_required
def application_detail(app_id):
    """Application detail page - placeholder"""
    # Fetch application data
    conn = get_db()
    application = conn.execute('''
        SELECT * FROM applications WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found or access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_application.html', 
                         application=dict(application),
                         app_id=app_id,
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/security-assessment/<app_id>')
@login_required
def security_assessment(app_id):
    """Security assessment page - placeholder"""
    # Fetch application data
    conn = get_db()
    application = conn.execute('''
        SELECT * FROM applications WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found or access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Set up review requirements and status
    # For now, we'll set all reviews as required and not completed
    # In a real implementation, this would check the database for actual review status
    
    # Review requirements (all reviews are required by default)
    app_review_required = True
    cloud_review_required = True
    database_review_required = True
    infrastructure_review_required = True
    compliance_review_required = True
    api_review_required = True
    
    # Review completion status (all set to not completed for now)
    app_review_completed = False
    cloud_review_completed = False
    database_review_completed = False
    infrastructure_review_completed = False
    compliance_review_completed = False
    api_review_completed = False
    
    # Review status (for display)
    app_review_status = 'pending'
    cloud_review_status = 'pending'
    database_review_status = 'pending'
    infrastructure_review_status = 'pending'
    compliance_review_status = 'pending'
    api_review_status = 'pending'
    
    return render_template('security_assessment.html', 
                         application=dict(application),
                         app_id=app_id,
                         user_name=session.get('user_name'),
                         role=session.get('role'),
                         # Review requirements
                         app_review_required=app_review_required,
                         cloud_review_required=cloud_review_required,
                         database_review_required=database_review_required,
                         infrastructure_review_required=infrastructure_review_required,
                         compliance_review_required=compliance_review_required,
                         api_review_required=api_review_required,
                         # Review completion status
                         app_review_completed=app_review_completed,
                         cloud_review_completed=cloud_review_completed,
                         database_review_completed=database_review_completed,
                         infrastructure_review_completed=infrastructure_review_completed,
                         compliance_review_completed=compliance_review_completed,
                         api_review_completed=api_review_completed,
                         # Review status
                         app_review_status=app_review_status,
                         cloud_review_status=cloud_review_status,
                         database_review_status=database_review_status,
                         infrastructure_review_status=infrastructure_review_status,
                         compliance_review_status=compliance_review_status,
                         api_review_status=api_review_status)

@app.route('/review-results/<app_id>')
@login_required
def review_results(app_id):
    """Review results page - placeholder"""
    # Fetch application data
    conn = get_db()
    application = conn.execute('''
        SELECT * FROM applications WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found or access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    # Create a placeholder review object
    review = {
        'risk_score': None,
        'status': 'pending',
        'created_at': None,
        'completed_at': None
    }
    
    return render_template('review_results.html', 
                         application=dict(application),
                         review=review,
                         app_id=app_id,
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Analyst routes
@app.route('/analyst/reviews')
@login_required
@role_required('security_analyst', 'admin')
def analyst_reviews():
    """Analyst reviews page - placeholder"""
    return render_template('analyst/reviews.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

@app.route('/analyst/review/<review_id>')
@login_required
@role_required('security_analyst', 'admin')
def analyst_review_detail(review_id):
    """Analyst review detail page - placeholder"""
    return render_template('analyst/review_detail.html', 
                         review_id=review_id,
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Additional analyst routes
@app.route('/analyst/dashboard')
@login_required
@role_required('security_analyst', 'admin')
def analyst_dashboard():
    """Analyst dashboard"""
    return render_template('analyst/dashboard.html', 
                         user_name=session.get('user_name'),
                         role=session.get('role'))

# Questionnaire routes
@app.route('/questionnaire/<app_id>/<review_type>')
@login_required
def questionnaire(app_id, review_type):
    """Questionnaire page for different review types"""
    # Validate review type
    valid_types = ['application_review', 'cloud_review', 'database_review', 
                   'infrastructure_review', 'compliance_review', 'api_review']
    
    if review_type not in valid_types:
        flash('Invalid review type.', 'error')
        return redirect(url_for('dashboard'))
    
    # Fetch application data
    conn = get_db()
    application = conn.execute('''
        SELECT * FROM applications WHERE id = ? AND author_id = ?
    ''', (app_id, session['user_id'])).fetchone()
    conn.close()
    
    if not application:
        flash('Application not found or access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('questionnaire.html', 
                         application=dict(application),
                         review_type=review_type,
                         app_id=app_id,
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

# New notification and chat endpoints
@app.route('/api/notifications')
@login_required
def get_notifications():
    """Get notifications for current user"""
    try:
        conn = get_db()
        notifications = conn.execute('''
            SELECT id, title, message, type, read_by, created_at, read_at
            FROM notifications 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (session['user_id'],)).fetchall()
        conn.close()
        
        notifications_list = []
        for notif in notifications:
            # Check if current user has read this notification
            read_by = notif['read_by'] or '[]'
            try:
                read_by_list = eval(read_by) if read_by else []
                is_read = session['user_id'] in read_by_list
            except:
                is_read = False
                
        notifications_list.append({
            'id': notif['id'],
            'title': notif['title'],
            'message': notif['message'],
            'type': notif['type'],
            'is_read': is_read,
            'created_at': format_india_time(notif['created_at']),
            'read_at': format_india_time(notif['read_at'])
        })
        
        return jsonify({
            'success': True,
            'notifications': notifications_list
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/notifications/<notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    """Mark notification as read"""
    try:
        conn = get_db()
        
        # Get current read_by list
        notification = conn.execute('''
            SELECT read_by FROM notifications WHERE id = ? AND user_id = ?
        ''', (notification_id, session['user_id'])).fetchone()
        
        if not notification:
            return jsonify({'success': False, 'error': 'Notification not found'}), 404
        
        # Update read_by list
        read_by = notification['read_by'] or '[]'
        try:
            read_by_list = eval(read_by) if read_by else []
        except:
            read_by_list = []
            
        if session['user_id'] not in read_by_list:
            read_by_list.append(session['user_id'])
            
        conn.execute('''
            UPDATE notifications 
            SET read_by = ?, read_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND user_id = ?
        ''', (str(read_by_list), notification_id, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/chat/messages')
@login_required
def get_chat_messages():
    """Get recent chat messages"""
    try:
        conn = get_db()
        messages = conn.execute('''
            SELECT cm.id, cm.message, cm.created_at, u.first_name, u.last_name
            FROM chat_messages cm
            JOIN users u ON cm.user_id = u.id
            ORDER BY cm.created_at DESC
            LIMIT 50
        ''').fetchall()
        conn.close()
        
        messages_list = []
        for msg in messages:
            messages_list.append({
                'id': msg['id'],
                'message': msg['message'],
                'created_at': format_india_time(msg['created_at']),
                'user_name': f"{msg['first_name']} {msg['last_name']}"
            })
        
        return jsonify({
            'success': True,
            'messages': messages_list
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/chat/send', methods=['POST'])
@login_required
def send_chat_message():
    """Send a chat message"""
    try:
        data = request.get_json()
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
        
        conn = get_db()
        message_id = str(uuid.uuid4())
        conn.execute('''
            INSERT INTO chat_messages (id, user_id, message)
            VALUES (?, ?, ?)
        ''', (message_id, session['user_id'], message))
        conn.commit()
        conn.close()
        
        # Emit to all connected users
        socketio.emit('new_chat_message', {
            'id': message_id,
            'message': message,
            'user_name': session.get('user_name', 'Unknown User'),
            'created_at': datetime.now().isoformat()
        })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

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
