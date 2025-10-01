/**
 * Real-time Communication JavaScript
 * Handles WebSocket connections and real-time updates
 */

class RealtimeManager {
    constructor() {
        this.socket = null;
        this.connected = false;
        this.currentApplicationId = null;
        this.messageHandlers = new Map();
        this.setupEventListeners();
    }

    init() {
        // Initialize Socket.IO connection
        this.socket = io();
        
        this.socket.on('connect', () => {
            this.connected = true;
            this.updateConnectionStatus(true);
            console.log('Connected to real-time server');
        });

        this.socket.on('disconnect', () => {
            this.connected = false;
            this.updateConnectionStatus(false);
            console.log('Disconnected from real-time server');
        });

        this.socket.on('connection_status', (data) => {
            if (data.status === 'connected') {
                this.connected = true;
                this.updateConnectionStatus(true);
            } else {
                this.connected = false;
                this.updateConnectionStatus(false);
            }
        });

        // Set up message handlers
        this.setupMessageHandlers();
    }

    setupMessageHandlers() {
        // Status updates
        this.socket.on('status_update', (data) => {
            this.handleStatusUpdate(data);
        });

        // Progress updates
        this.socket.on('progress_update', (data) => {
            this.handleProgressUpdate(data);
        });

        // New messages
        this.socket.on('new_message', (data) => {
            this.handleNewMessage(data);
        });

        // Clarification requests
        this.socket.on('clarification_request', (data) => {
            this.handleClarificationRequest(data);
        });

        // Clarification responses
        this.socket.on('clarification_response', (data) => {
            this.handleClarificationResponse(data);
        });

        // New assignments
        this.socket.on('new_assignment', (data) => {
            this.handleNewAssignment(data);
        });

        // System notifications
        this.socket.on('system_notification', (data) => {
            this.handleSystemNotification(data);
        });
    }

    setupEventListeners() {
        // Auto-join application room when page loads
        document.addEventListener('DOMContentLoaded', () => {
            const appId = this.getCurrentApplicationId();
            if (appId) {
                this.joinApplication(appId);
            }
        });

        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.pauseUpdates();
            } else {
                this.resumeUpdates();
            }
        });
    }

    getCurrentApplicationId() {
        // Try to get application ID from URL or data attributes
        const path = window.location.pathname;
        const appIdMatch = path.match(/\/applications\/([^\/]+)/);
        if (appIdMatch) {
            return appIdMatch[1];
        }

        // Check for data attribute
        const appElement = document.querySelector('[data-application-id]');
        if (appElement) {
            return appElement.getAttribute('data-application-id');
        }

        return null;
    }

    joinApplication(applicationId) {
        if (this.socket && this.connected) {
            this.currentApplicationId = applicationId;
            this.socket.emit('join_application', { application_id: applicationId });
        }
    }

    leaveApplication(applicationId) {
        if (this.socket && this.connected) {
            this.socket.emit('leave_application', { application_id: applicationId });
            this.currentApplicationId = null;
        }
    }

    sendMessage(applicationId, message) {
        if (this.socket && this.connected) {
            this.socket.emit('send_message', {
                application_id: applicationId,
                message: message
            });
        }
    }

    requestClarification(applicationId, questionId, message) {
        if (this.socket && this.connected) {
            this.socket.emit('request_clarification', {
                application_id: applicationId,
                question_id: questionId,
                message: message
            });
        }
    }

    // Message handlers
    handleStatusUpdate(data) {
        console.log('Status update received:', data);
        
        // Update status in UI
        const statusElement = document.querySelector(`[data-application-id="${data.application_id}"] .status-badge`);
        if (statusElement) {
            statusElement.textContent = data.status;
            statusElement.className = `badge bg-${this.getStatusColor(data.status)}`;
        }

        // Show notification
        this.showNotification('Status Update', data.message, 'info');
        
        // Trigger custom event
        this.triggerCustomEvent('statusUpdate', data);
    }

    handleProgressUpdate(data) {
        console.log('Progress update received:', data);
        
        // Update progress bar
        const progressElement = document.querySelector(`[data-application-id="${data.application_id}"] .progress-bar`);
        if (progressElement) {
            progressElement.style.width = `${data.progress}%`;
            progressElement.setAttribute('aria-valuenow', data.progress);
        }

        // Update progress text
        const progressText = document.querySelector(`[data-application-id="${data.application_id}"] .progress-text`);
        if (progressText) {
            progressText.textContent = `${data.progress}% Complete`;
        }

        // Show milestone notification
        if (data.milestone) {
            this.showNotification('Progress Update', `Milestone: ${data.milestone}`, 'success');
        }

        // Trigger custom event
        this.triggerCustomEvent('progressUpdate', data);
    }

    handleNewMessage(data) {
        console.log('New message received:', data);
        
        // Add message to chat
        this.addMessageToChat(data);
        
        // Show notification
        this.showNotification('New Message', 'You have a new message', 'info');
        
        // Trigger custom event
        this.triggerCustomEvent('newMessage', data);
    }

    handleClarificationRequest(data) {
        console.log('Clarification request received:', data);
        
        // Show clarification modal
        this.showClarificationModal(data);
        
        // Show notification
        this.showNotification('Clarification Request', 'Analyst needs clarification', 'warning');
        
        // Trigger custom event
        this.triggerCustomEvent('clarificationRequest', data);
    }

    handleClarificationResponse(data) {
        console.log('Clarification response received:', data);
        
        // Update UI to show response received
        this.updateClarificationStatus(data.application_id, 'responded');
        
        // Show notification
        this.showNotification('Clarification Response', 'User provided clarification', 'success');
        
        // Trigger custom event
        this.triggerCustomEvent('clarificationResponse', data);
    }

    handleNewAssignment(data) {
        console.log('New assignment received:', data);
        
        // Update assignment UI
        this.updateAssignmentStatus(data.application_id, 'assigned');
        
        // Show notification
        this.showNotification('New Assignment', 'You have been assigned a new review', 'info');
        
        // Trigger custom event
        this.triggerCustomEvent('newAssignment', data);
    }

    handleSystemNotification(data) {
        console.log('System notification received:', data);
        
        // Show system notification
        this.showNotification('System Notification', data.message, data.notification_type);
        
        // Trigger custom event
        this.triggerCustomEvent('systemNotification', data);
    }

    // UI Helper methods
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connectionStatus');
        if (statusElement) {
            if (connected) {
                statusElement.innerHTML = '<i class="fas fa-circle"></i> Connected';
                statusElement.className = 'badge bg-success';
            } else {
                statusElement.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
                statusElement.className = 'badge bg-danger';
            }
        }
    }

    getStatusColor(status) {
        const statusColors = {
            'draft': 'secondary',
            'submitted': 'warning',
            'in_review': 'primary',
            'pending_clarification': 'warning',
            'completed': 'success',
            'rejected': 'danger'
        };
        return statusColors[status] || 'secondary';
    }

    showNotification(title, message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.top = '20px';
        notification.style.right = '20px';
        notification.style.zIndex = '9999';
        notification.style.minWidth = '300px';
        
        notification.innerHTML = `
            <strong>${title}</strong><br>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }

    addMessageToChat(messageData) {
        const chatContainer = document.getElementById('chatMessages');
        if (chatContainer) {
            const messageElement = document.createElement('div');
            messageElement.className = 'message-item mb-2 p-2 border rounded';
            messageElement.innerHTML = `
                <div class="d-flex justify-content-between">
                    <strong>User ${messageData.user_id}</strong>
                    <small class="text-muted">${new Date(messageData.timestamp).toLocaleTimeString()}</small>
                </div>
                <div>${messageData.message}</div>
            `;
            
            chatContainer.appendChild(messageElement);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    }

    showClarificationModal(data) {
        // Update modal content
        document.getElementById('clarificationRequestText').textContent = data.message;
        document.getElementById('clarificationApplicationId').value = data.application_id;
        document.getElementById('clarificationQuestionId').value = data.question_id;
        
        // Show modal
        const modal = new bootstrap.Modal(document.getElementById('clarificationModal'));
        modal.show();
    }

    updateClarificationStatus(applicationId, status) {
        const statusElement = document.querySelector(`[data-application-id="${applicationId}"] .clarification-status`);
        if (statusElement) {
            statusElement.textContent = status;
            statusElement.className = `badge bg-${status === 'responded' ? 'success' : 'warning'}`;
        }
    }

    updateAssignmentStatus(applicationId, status) {
        const statusElement = document.querySelector(`[data-application-id="${applicationId}"] .assignment-status`);
        if (statusElement) {
            statusElement.textContent = status;
            statusElement.className = `badge bg-${status === 'assigned' ? 'success' : 'secondary'}`;
        }
    }

    pauseUpdates() {
        // Pause real-time updates when page is not visible
        console.log('Pausing real-time updates');
    }

    resumeUpdates() {
        // Resume real-time updates when page becomes visible
        console.log('Resuming real-time updates');
    }

    triggerCustomEvent(eventName, data) {
        // Trigger custom events for other parts of the application
        const event = new CustomEvent(eventName, { detail: data });
        document.dispatchEvent(event);
    }

    // Public API methods
    on(eventName, handler) {
        if (!this.messageHandlers.has(eventName)) {
            this.messageHandlers.set(eventName, []);
        }
        this.messageHandlers.get(eventName).push(handler);
    }

    off(eventName, handler) {
        if (this.messageHandlers.has(eventName)) {
            const handlers = this.messageHandlers.get(eventName);
            const index = handlers.indexOf(handler);
            if (index > -1) {
                handlers.splice(index, 1);
            }
        }
    }
}

// Global realtime manager instance
window.realtimeManager = new RealtimeManager();

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.realtimeManager.init();
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RealtimeManager;
}
