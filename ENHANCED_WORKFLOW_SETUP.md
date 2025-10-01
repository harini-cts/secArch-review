# Enhanced Workflow Setup Guide

## Overview

This guide will help you set up and run the enhanced workflow features that improve collaboration between users and analysts in the SecureArch Portal.

## Prerequisites

- Python 3.8+
- Redis server
- SQLite database (or PostgreSQL for production)
- Node.js (for frontend assets, optional)

## Quick Setup

### 1. Run the Setup Script

```bash
python setup_enhanced_workflow.py
```

This script will:
- Run database migrations
- Create demo data
- Install additional requirements
- Create configuration files

### 2. Install and Start Redis

**macOS:**
```bash
brew install redis
redis-server
```

**Ubuntu/Debian:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis-server
```

**Windows:**
Download Redis from https://redis.io/download

### 3. Run the Enhanced Application

```bash
python app_enhanced.py
```

The application will be available at `http://localhost:5000`

## Docker Setup (Recommended)

### 1. Using Docker Compose

```bash
docker-compose -f docker-compose.realtime.yml up -d
```

This will start:
- Main application with WebSocket support
- Redis for real-time communication
- PostgreSQL database
- Nginx reverse proxy

### 2. Access the Application

- Main application: `http://localhost`
- Enhanced dashboard: `http://localhost/enhanced-dashboard`

## Features Overview

### Real-time Communication
- **WebSocket Integration**: Live updates for status changes
- **Push Notifications**: Instant alerts for important events
- **In-app Messaging**: Direct communication between users and analysts
- **Email Notifications**: Backup notification system

### Collaborative Features
- **Clarification Requests**: Analysts can ask for additional information
- **Progress Tracking**: Real-time visibility into review progress
- **Collaboration History**: Complete audit trail of all interactions
- **File Sharing**: Enhanced document collaboration

### Smart Assignment
- **Auto-Assignment**: Automatic analyst assignment based on expertise
- **Workload Balancing**: Distribute reviews evenly across analysts
- **Priority Handling**: Critical applications get senior analysts
- **Escalation**: Automatic escalation for overdue reviews

## API Endpoints

### Real-time Communication
```
POST /api/workflow/send-message
POST /api/workflow/request-clarification
POST /api/workflow/respond-clarification
GET  /api/workflow/real-time-status/<app_id>
```

### Smart Assignment
```
POST /api/workflow/assign-analyst-realtime
GET  /api/workflow/available-analysts
```

### Notifications
```
GET  /api/workflow/notifications
POST /api/workflow/notifications/<id>/read
```

## Database Schema

The enhanced workflow adds several new tables:

- `workflow_notifications` - Enhanced notifications with collaboration support
- `collaboration_comments` - Comments and discussions
- `review_progress` - Progress tracking with milestones
- `clarification_requests` - Clarification workflow
- `analyst_assignments` - Assignment tracking
- `activity_feed` - Real-time activity feed

## Configuration

### Environment Variables

Create a `.env.enhanced` file:

```env
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
REDIS_URL=redis://localhost:6379/0
DATABASE_URL=sqlite:///securearch_portal.db

# WebSocket Configuration
SOCKETIO_ASYNC_MODE=eventlet
SOCKETIO_CORS_ALLOWED_ORIGINS=*

# Email Configuration (optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Redis Configuration

Default Redis configuration is suitable for development. For production:

```redis
# redis.conf
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

## Usage Examples

### 1. Real-time Status Updates

```javascript
// Listen for status updates
realtimeManager.on('statusUpdate', (data) => {
    console.log('Status changed:', data.status);
    updateStatusUI(data);
});

// Join application room
realtimeManager.joinApplication('app_123');
```

### 2. Send Messages

```javascript
// Send real-time message
realtimeManager.sendMessage('app_123', 'Hello, I have a question about the review');
```

### 3. Request Clarification

```javascript
// Request clarification from analyst
realtimeManager.requestClarification('app_123', 'question_456', 'Can you clarify the authentication requirements?');
```

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failed**
   - Check if Redis is running
   - Verify firewall settings
   - Check browser console for errors

2. **Database Migration Errors**
   - Ensure database file is writable
   - Check SQLite version compatibility
   - Run migration manually if needed

3. **Real-time Updates Not Working**
   - Check browser WebSocket support
   - Verify Socket.IO client is loaded
   - Check network connectivity

### Debug Mode

Enable debug mode by setting:

```env
FLASK_ENV=development
DEBUG=True
```

### Logs

Check application logs for detailed error information:

```bash
tail -f app.log
```

## Performance Considerations

### Production Settings

1. **Redis Configuration**
   - Use Redis Cluster for high availability
   - Configure memory limits appropriately
   - Enable persistence for message history

2. **WebSocket Scaling**
   - Use Redis adapter for multiple instances
   - Configure load balancer for sticky sessions
   - Monitor connection limits

3. **Database Optimization**
   - Add appropriate indexes
   - Use connection pooling
   - Monitor query performance

## Security Considerations

1. **WebSocket Authentication**
   - Validate user sessions
   - Implement rate limiting
   - Use secure cookies

2. **Data Privacy**
   - Encrypt sensitive messages
   - Implement data retention policies
   - Audit access logs

3. **Network Security**
   - Use WSS (WebSocket Secure) in production
   - Implement CORS properly
   - Use firewall rules

## Monitoring and Analytics

### Key Metrics

- WebSocket connection count
- Message throughput
- Response times
- Error rates
- User engagement

### Monitoring Tools

- Redis monitoring: `redis-cli info`
- Application metrics: Flask monitoring extensions
- WebSocket metrics: Custom dashboard

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review application logs
3. Check Redis and database status
4. Verify network connectivity

## Next Steps

After successful setup:

1. Test all real-time features
2. Configure email notifications
3. Set up monitoring
4. Deploy to production environment
5. Train users on new features

The enhanced workflow system provides a significant improvement in user-analyst collaboration, leading to faster, more efficient, and more transparent security review processes.
