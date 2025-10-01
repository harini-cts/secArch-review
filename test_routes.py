#!/usr/bin/env python3
"""
Test script to check what routes are registered
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app_enhanced_simple import app

print("🔍 Registered Routes:")
print("=" * 50)

for rule in app.url_map.iter_rules():
    print(f"{rule.methods} {rule.rule} -> {rule.endpoint}")

print("\n🔍 Testing route registration...")

# Test if the enhanced_dashboard route exists
with app.test_client() as client:
    response = client.get('/enhanced-dashboard')
    print(f"Enhanced Dashboard Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ Enhanced dashboard route works!")
    else:
        print(f"❌ Enhanced dashboard route failed: {response.status_code}")
        print(f"Response: {response.get_data(as_text=True)[:200]}...")

print("\n🔍 Testing home route...")
with app.test_client() as client:
    response = client.get('/')
    print(f"Home Status: {response.status_code}")
    
    if response.status_code == 200:
        print("✅ Home route works!")
    else:
        print(f"❌ Home route failed: {response.status_code}")
