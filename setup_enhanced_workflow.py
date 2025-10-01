#!/usr/bin/env python3
"""
Setup script for Enhanced Workflow Features
This script sets up the database and initializes the enhanced workflow system
"""

import sqlite3
import os
import sys
from datetime import datetime

def run_database_migration():
    """Run database migration to add new tables"""
    print("🔄 Running database migration...")
    
    try:
        # Read migration script
        with open('database_migration.sql', 'r') as f:
            migration_sql = f.read()
        
        # Connect to database
        conn = sqlite3.connect('securearch_portal.db')
        cursor = conn.cursor()
        
        # Execute migration
        cursor.executescript(migration_sql)
        
        # Add columns to existing tables (with error handling for older SQLite)
        columns_to_add = [
            ("notifications", "read_at", "TIMESTAMP"),
            ("notifications", "notification_type", "TEXT DEFAULT 'info'"),
            ("notifications", "metadata", "TEXT"),
            ("applications", "assigned_analyst_id", "TEXT"),
            ("applications", "priority", "INTEGER DEFAULT 1"),
            ("applications", "due_date", "TIMESTAMP"),
            ("applications", "last_activity_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
            ("users", "specializations", "TEXT"),
            ("users", "max_concurrent_reviews", "INTEGER DEFAULT 5"),
            ("users", "is_available", "BOOLEAN DEFAULT TRUE"),
            ("users", "notification_preferences", "TEXT DEFAULT '{}'")
        ]
        
        for table, column, definition in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                print(f"✅ Added column {column} to {table}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e).lower():
                    print(f"ℹ️ Column {column} already exists in {table}")
                else:
                    print(f"⚠️ Could not add column {column} to {table}: {e}")
        
        conn.commit()
        print("✅ Database migration completed successfully")
        
    except Exception as e:
        print(f"❌ Database migration failed: {e}")
        return False
    finally:
        conn.close()
    
    return True

def create_demo_data():
    """Create demo data for testing enhanced workflow"""
    print("🔄 Creating demo data...")
    
    try:
        conn = sqlite3.connect('securearch_portal.db')
        cursor = conn.cursor()
        
        # Create demo analyst
        cursor.execute('''
            INSERT OR IGNORE INTO users 
            (id, email, password_hash, first_name, last_name, role, experience_level, specializations, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'demo_analyst_1',
            'analyst1@demo.com',
            'hashed_password_here',  # In real app, use proper password hashing
            'Sarah',
            'Chen',
            'security_analyst',
            'senior',
            '["web_security", "cloud_security", "mobile_security"]',
            1
        ))
        
        # Create demo admin
        cursor.execute('''
            INSERT OR IGNORE INTO users 
            (id, email, password_hash, first_name, last_name, role, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            'demo_admin_1',
            'admin@demo.com',
            'hashed_password_here',
            'John',
            'Admin',
            'admin',
            1
        ))
        
        # Create demo application
        cursor.execute('''
            INSERT OR IGNORE INTO applications 
            (id, name, description, technology_stack, business_criticality, author_id, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            'demo_app_1',
            'E-commerce Platform',
            'Online shopping platform with payment processing',
            'React, Node.js, PostgreSQL, AWS',
            'High',
            'demo_user_1',
            'submitted',
            datetime.now().isoformat()
        ))
        
        # Create demo notifications
        cursor.execute('''
            INSERT OR IGNORE INTO workflow_notifications 
            (id, application_id, to_user_id, notification_type, title, message, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            'demo_notification_1',
            'demo_app_1',
            'demo_user_1',
            'assignment',
            'Review Assigned',
            'Your application has been assigned to Sarah Chen for review',
            datetime.now().isoformat()
        ))
        
        conn.commit()
        print("✅ Demo data created successfully")
        
    except Exception as e:
        print(f"❌ Demo data creation failed: {e}")
        return False
    finally:
        conn.close()
    
    return True

def install_requirements():
    """Install additional requirements for real-time features"""
    print("🔄 Installing additional requirements...")
    
    try:
        import subprocess
        
        # Install real-time requirements
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements_realtime.txt'
        ], check=True)
        
        print("✅ Requirements installed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Requirements installation failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Requirements installation failed: {e}")
        return False
    
    return True

def create_config_files():
    """Create configuration files for enhanced workflow"""
    print("🔄 Creating configuration files...")
    
    try:
        # Create .env file for real-time features
        env_content = """# Enhanced Workflow Configuration
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

# Notification Configuration
PUSHBULLET_API_KEY=your-pushbullet-api-key
SENDGRID_API_KEY=your-sendgrid-api-key
"""
        
        with open('.env.enhanced', 'w') as f:
            f.write(env_content)
        
        # Create nginx configuration
        nginx_config = """events {
    worker_connections 1024;
}

http {
    upstream app {
        server app:5000;
    }
    
    upstream socketio {
        server app:5000;
    }
    
    server {
        listen 80;
        server_name localhost;
        
        location / {
            proxy_pass http://app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        location /socket.io/ {
            proxy_pass http://socketio;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
"""
        
        with open('nginx.conf', 'w') as f:
            f.write(nginx_config)
        
        print("✅ Configuration files created successfully")
        
    except Exception as e:
        print(f"❌ Configuration file creation failed: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up Enhanced Workflow Features")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not os.path.exists('app_web.py'):
        print("❌ Please run this script from the project root directory")
        sys.exit(1)
    
    # Run setup steps
    steps = [
        ("Database Migration", run_database_migration),
        ("Demo Data Creation", create_demo_data),
        ("Requirements Installation", install_requirements),
        ("Configuration Files", create_config_files)
    ]
    
    for step_name, step_function in steps:
        print(f"\n📋 {step_name}...")
        if not step_function():
            print(f"❌ {step_name} failed. Please check the errors above.")
            sys.exit(1)
    
    print("\n" + "=" * 50)
    print("🎉 Enhanced Workflow Setup Complete!")
    print("\nNext steps:")
    print("1. Install Redis: brew install redis (macOS) or apt-get install redis-server (Ubuntu)")
    print("2. Start Redis: redis-server")
    print("3. Run the enhanced application: python app_enhanced.py")
    print("4. Open http://localhost:5000/enhanced-dashboard")
    print("\nFor Docker setup:")
    print("1. docker-compose -f docker-compose.realtime.yml up -d")
    print("2. Open http://localhost")

if __name__ == "__main__":
    main()
