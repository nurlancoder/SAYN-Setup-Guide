#!/usr/bin/env python3
"""
Test script to add sample scan data for testing the web interface
"""
import sys
import os
from datetime import datetime, timedelta
import json

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager

def create_test_data():
    """Create sample scan data for testing"""
    db = DatabaseManager()
    
    # Create sample scans
    scan_data = [
        {
            'target': 'https://example.com',
            'scan_name': 'Test Web Security Scan',
            'scan_type': 'web',
            'scan_depth': 'normal',
            'threads': 10,
            'timeout': 30,
            'status': 'completed',
            'risk_score': 75
        },
        {
            'target': 'https://test-site.com',
            'scan_name': 'API Security Assessment',
            'scan_type': 'api',
            'scan_depth': 'deep',
            'threads': 15,
            'timeout': 45,
            'status': 'completed',
            'risk_score': 45
        },
        {
            'target': '192.168.1.100',
            'scan_name': 'Network Security Scan',
            'scan_type': 'network',
            'scan_depth': 'quick',
            'threads': 5,
            'timeout': 20,
            'status': 'running',
            'risk_score': 0
        }
    ]
    
    scan_ids = []
    
    for scan in scan_data:
        scan_id = db.create_scan_record(
            target=scan['target'],
            scan_name=scan['scan_name'],
            scan_type=scan['scan_type'],
            scan_depth=scan['scan_depth'],
            threads=scan['threads'],
            timeout=scan['timeout']
        )
        scan_ids.append(scan_id)
        
        # Update status and risk score
        with db._lock:
            import sqlite3
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE scans 
                    SET status = ?, risk_score = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (scan['status'], scan['risk_score'], scan_id))
                conn.commit()
    
    # Add sample vulnerabilities for completed scans
    vulnerabilities = [
        {
            'scan_id': scan_ids[0],
            'title': 'Cross-Site Scripting (XSS)',
            'severity': 'high',
            'vuln_type': 'xss',
            'description': 'Reflected XSS vulnerability found in search parameter',
            'location': 'https://example.com/search?q=<script>alert(1)</script>',
            'recommendation': 'Implement proper input validation and output encoding'
        },
        {
            'scan_id': scan_ids[0],
            'title': 'Missing Security Headers',
            'severity': 'medium',
            'vuln_type': 'headers',
            'description': 'X-Frame-Options header is missing',
            'location': 'https://example.com/',
            'recommendation': 'Add X-Frame-Options header to prevent clickjacking'
        },
        {
            'scan_id': scan_ids[1],
            'title': 'Weak Authentication',
            'severity': 'critical',
            'vuln_type': 'auth',
            'description': 'API endpoint allows weak password authentication',
            'location': 'https://test-site.com/api/auth',
            'recommendation': 'Implement strong password policy and rate limiting'
        },
        {
            'scan_id': scan_ids[1],
            'title': 'Information Disclosure',
            'severity': 'low',
            'vuln_type': 'info_disclosure',
            'description': 'Server version information exposed in headers',
            'location': 'https://test-site.com/',
            'recommendation': 'Remove or modify server version headers'
        }
    ]
    
    for vuln in vulnerabilities:
        with db._lock:
            import sqlite3
            with sqlite3.connect(db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (scan_id, vuln_type, severity, title, description, location, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln['scan_id'],
                    vuln['vuln_type'],
                    vuln['severity'],
                    vuln['title'],
                    vuln['description'],
                    vuln['location'],
                    vuln['recommendation']
                ))
                conn.commit()
    
    print("✅ Test data created successfully!")
    print(f"   Created {len(scan_ids)} scans")
    print(f"   Created {len(vulnerabilities)} vulnerabilities")
    print("\n📊 Sample Statistics:")
    print(f"   Total scans: {db.get_total_scans()}")
    print(f"   Completed scans: {db.get_completed_scans()}")
    print(f"   Total vulnerabilities: {db.get_total_vulnerabilities()}")
    print(f"   High risk vulnerabilities: {db.get_high_risk_vulnerabilities()}")

if __name__ == '__main__':
    create_test_data()
