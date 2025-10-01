"""
Real-time Communication Module for Enhanced Workflow
Handles WebSocket connections, notifications, and live updates
"""

from flask import request, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
import redis
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Initialize Redis for message handling
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

class RealtimeManager:
    """Manages real-time communication and notifications"""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            user_id = session.get('user_id')
            if user_id:
                join_room(f"user_{user_id}")
                logger.info(f"User {user_id} connected to WebSocket")
                emit('connection_status', {'status': 'connected'})
            else:
                emit('connection_status', {'status': 'unauthorized'})
                return False
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            user_id = session.get('user_id')
            if user_id:
                leave_room(f"user_{user_id}")
                logger.info(f"User {user_id} disconnected from WebSocket")
        
        @self.socketio.on('join_application')
        def handle_join_application(data):
            """Join application-specific room for real-time updates"""
            application_id = data.get('application_id')
            user_id = session.get('user_id')
            
            if application_id and user_id:
                room_name = f"app_{application_id}"
                join_room(room_name)
                emit('joined_application', {'application_id': application_id})
                logger.info(f"User {user_id} joined application room {room_name}")
        
        @self.socketio.on('leave_application')
        def handle_leave_application(data):
            """Leave application-specific room"""
            application_id = data.get('application_id')
            user_id = session.get('user_id')
            
            if application_id and user_id:
                room_name = f"app_{application_id}"
                leave_room(room_name)
                emit('left_application', {'application_id': application_id})
                logger.info(f"User {user_id} left application room {room_name}")
        
        @self.socketio.on('send_message')
        def handle_send_message(data):
            """Handle real-time messaging between users and analysts"""
            message = data.get('message')
            application_id = data.get('application_id')
            user_id = session.get('user_id')
            
            if not all([message, application_id, user_id]):
                emit('error', {'message': 'Missing required fields'})
                return
            
            # Store message in database
            message_data = {
                'id': f"msg_{datetime.now().timestamp()}",
                'application_id': application_id,
                'user_id': user_id,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
            
            # Emit to all users in the application room
            self.socketio.emit('new_message', message_data, room=f"app_{application_id}")
            
            # Store in Redis for persistence
            redis_client.lpush(f"messages:app_{application_id}", json.dumps(message_data))
            redis_client.expire(f"messages:app_{application_id}", 86400)  # 24 hours
        
        @self.socketio.on('request_clarification')
        def handle_request_clarification(data):
            """Handle clarification requests from analysts"""
            application_id = data.get('application_id')
            question_id = data.get('question_id')
            message = data.get('message')
            analyst_id = session.get('user_id')
            
            if not all([application_id, question_id, message, analyst_id]):
                emit('error', {'message': 'Missing required fields'})
                return
            
            # Create clarification request
            clarification_data = {
                'id': f"clar_{datetime.now().timestamp()}",
                'application_id': application_id,
                'question_id': question_id,
                'analyst_id': analyst_id,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
            
            # Notify user
            self.socketio.emit('clarification_request', clarification_data, 
                             room=f"app_{application_id}")
            
            # Store in Redis
            redis_client.lpush(f"clarifications:app_{application_id}", json.dumps(clarification_data))
    
    def notify_status_change(self, application_id, new_status, user_id, message=None):
        """Notify users of status changes"""
        notification_data = {
            'type': 'status_change',
            'application_id': application_id,
            'status': new_status,
            'message': message or f"Status changed to {new_status}",
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit to application room
        self.socketio.emit('status_update', notification_data, room=f"app_{application_id}")
        
        # Emit to specific user
        self.socketio.emit('status_update', notification_data, room=f"user_{user_id}")
    
    def notify_progress_update(self, application_id, progress_percentage, milestone=None):
        """Notify users of progress updates"""
        progress_data = {
            'type': 'progress_update',
            'application_id': application_id,
            'progress': progress_percentage,
            'milestone': milestone,
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit to application room
        self.socketio.emit('progress_update', progress_data, room=f"app_{application_id}")
    
    def notify_assignment(self, application_id, analyst_id, assignment_type='automatic'):
        """Notify analyst of new assignment"""
        assignment_data = {
            'type': 'assignment',
            'application_id': application_id,
            'assignment_type': assignment_type,
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit to analyst
        self.socketio.emit('new_assignment', assignment_data, room=f"user_{analyst_id}")
    
    def notify_clarification_response(self, application_id, analyst_id, response):
        """Notify analyst of clarification response"""
        response_data = {
            'type': 'clarification_response',
            'application_id': application_id,
            'response': response,
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit to analyst
        self.socketio.emit('clarification_response', response_data, room=f"user_{analyst_id}")
    
    def broadcast_system_notification(self, message, notification_type='info', target_roles=None):
        """Broadcast system-wide notifications"""
        notification_data = {
            'type': 'system_notification',
            'message': message,
            'notification_type': notification_type,
            'timestamp': datetime.now().isoformat()
        }
        
        if target_roles:
            for role in target_roles:
                self.socketio.emit('system_notification', notification_data, room=f"role_{role}")
        else:
            self.socketio.emit('system_notification', notification_data)
    
    def get_application_messages(self, application_id, limit=50):
        """Get recent messages for an application"""
        messages = redis_client.lrange(f"messages:app_{application_id}", 0, limit-1)
        return [json.loads(msg) for msg in messages]
    
    def get_application_clarifications(self, application_id, limit=20):
        """Get recent clarifications for an application"""
        clarifications = redis_client.lrange(f"clarifications:app_{application_id}", 0, limit-1)
        return [json.loads(clar) for clar in clarifications]

# Global realtime manager instance
realtime_manager = None

def init_realtime(socketio):
    """Initialize real-time communication"""
    global realtime_manager
    realtime_manager = RealtimeManager(socketio)
    return realtime_manager

def get_realtime_manager():
    """Get the global realtime manager instance"""
    return realtime_manager
