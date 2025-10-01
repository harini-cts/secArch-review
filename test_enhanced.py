#!/usr/bin/env python3
"""
Test script for enhanced workflow features
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app_enhanced_simple import app, socketio
from app.database import get_db
import json

def test_database_connection():
    """Test database connection and new tables"""
    print("🔍 Testing database connection...")
    
    try:
        with app.app_context():
            conn = get_db()
        
        # Check if new tables exist
        tables_to_check = [
            'workflow_notifications',
            'collaboration_comments', 
            'activity_feed',
            'workflow_assignments'
        ]
        
        for table in tables_to_check:
            result = conn.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table}'").fetchone()
            if result:
                print(f"✅ Table '{table}' exists")
            else:
                print(f"❌ Table '{table}' missing")
        
        # Check if new columns exist
        columns_to_check = [
            ('notifications', 'read_at'),
            ('notifications', 'notification_type'),
            ('applications', 'assigned_analyst_id'),
            ('users', 'specializations')
        ]
        
        for table, column in columns_to_check:
            try:
                result = conn.execute(f"PRAGMA table_info({table})").fetchall()
                columns = [row[1] for row in result]
                if column in columns:
                    print(f"✅ Column '{column}' exists in '{table}'")
                else:
                    print(f"❌ Column '{column}' missing in '{table}'")
            except Exception as e:
                print(f"⚠️ Could not check {table}.{column}: {e}")
        
            conn.close()
            print("✅ Database connection successful")
            return True
        
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

def test_workflow_engine():
    """Test workflow engine functionality"""
    print("\n🔍 Testing workflow engine...")
    
    try:
        from app.workflow import workflow_engine
        
        # Test getting collaboration history (should not crash)
        history = workflow_engine.get_collaboration_history("test-app-id")
        print(f"✅ Workflow engine collaboration history: {len(history)} items")
        
        # Test automatic assignment (should not crash)
        success, error, analyst = workflow_engine.assign_analyst_automatically("test-app-id")
        print(f"✅ Workflow engine automatic assignment: {success}")
        
        print("✅ Workflow engine functional")
        return True
        
    except Exception as e:
        print(f"❌ Workflow engine test failed: {e}")
        return False

def test_redis_connection():
    """Test Redis connection"""
    print("\n🔍 Testing Redis connection...")
    
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis connection successful")
        return True
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print("💡 Make sure Redis is running: redis-server")
        return False

def test_application_startup():
    """Test if the application can start"""
    print("\n🔍 Testing application startup...")
    
    try:
        # Test if we can create the app context
        with app.app_context():
            print("✅ Flask app context created successfully")
        
        # Test if SocketIO is properly initialized
        if socketio:
            print("✅ SocketIO initialized successfully")
        
        print("✅ Application startup test passed")
        return True
        
    except Exception as e:
        print(f"❌ Application startup test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Enhanced Workflow Test Suite")
    print("=" * 50)
    
    tests = [
        test_database_connection,
        test_workflow_engine,
        test_redis_connection,
        test_application_startup
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced workflow is ready to use.")
        print("\n📋 Next steps:")
        print("1. Start the application: python app_enhanced_simple.py")
        print("2. Open browser: http://localhost:5000")
        print("3. Login with demo credentials:")
        print("   - User: user@example.com / password123")
        print("   - Analyst: analyst@example.com / password123")
        print("   - Admin: admin@example.com / password123")
    else:
        print("⚠️ Some tests failed. Please fix the issues above.")
    
    return passed == total

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
