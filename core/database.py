"""
SAYN Database Management
Enhanced database manager with better error handling and additional features
"""
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging
import threading

class DatabaseManager:
    """Enhanced database manager for SAYN scan results and history"""
    
    def __init__(self, db_path: str = "sayn_data.db"):
        self.db_path = db_path
        self.logger = logging.getLogger('SAYN.database')
        self._lock = threading.Lock()
        self.init_database()

    def init_database(self):
        """Initialize database tables with enhanced schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('PRAGMA foreign_keys = ON')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        scan_name TEXT,
                        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        modules_used TEXT,
                        risk_score INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        scan_type TEXT DEFAULT 'web',
                        scan_depth TEXT DEFAULT 'normal',
                        threads_used INTEGER DEFAULT 10,
                        timeout_seconds INTEGER DEFAULT 30,
                        results TEXT,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        vuln_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        location TEXT,
                        recommendation TEXT,
                        cve_id TEXT,
                        cvss_score REAL,
                        affected_component TEXT,
                        evidence TEXT,
                        false_positive BOOLEAN DEFAULT FALSE,
                        verified BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS configurations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key TEXT UNIQUE NOT NULL,
                        value TEXT,
                        description TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise

    def create_scan_record(self, target: str, scan_name: str = None, 
                          scan_type: str = 'web', scan_depth: str = 'normal',
                          threads: int = 10, timeout: int = 30) -> int:
        """Create new scan record and return scan ID"""
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO scans (target, scan_name, status, scan_type, scan_depth, threads_used, timeout_seconds)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (target, scan_name, 'running', scan_type, scan_depth, threads, timeout))
                    conn.commit()
                    scan_id = cursor.lastrowid
                    self.logger.info(f"Created scan record with ID: {scan_id}")
                    return scan_id
        except Exception as e:
            self.logger.error(f"Error creating scan record: {e}")
            raise

    def save_scan_results(self, scan_results: Dict[str, Any]):
        """Save complete scan results with enhanced error handling"""
        scan_id = scan_results.get('scan_id')
        if not scan_id:
            self.logger.error("No scan_id provided in scan results")
            return
        
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        UPDATE scans 
                        SET modules_used = ?, risk_score = ?, status = ?, results = ?, 
                            metadata = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                    ''', (
                        ','.join(scan_results.get('modules_executed', [])),
                        scan_results.get('risk_score', 0),
                        'completed',
                        json.dumps(scan_results),
                        json.dumps(scan_results.get('metadata', {})),
                        scan_id
                    ))
                    
                    for vuln in scan_results.get('vulnerabilities', []):
                        cursor.execute('''
                            INSERT INTO vulnerabilities 
                            (scan_id, vuln_type, severity, title, description, location, 
                             recommendation, cve_id, cvss_score, affected_component, evidence)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id,
                            vuln.get('type', ''),
                            vuln.get('severity', 'low'),
                            vuln.get('title', ''),
                            vuln.get('description', ''),
                            vuln.get('location', ''),
                            vuln.get('recommendation', ''),
                            vuln.get('cve_id', ''),
                            vuln.get('cvss_score', 0.0),
                            vuln.get('affected_component', ''),
                            json.dumps(vuln.get('evidence', {}))
                        ))
                    
                    for log_entry in scan_results.get('logs', []):
                        cursor.execute('''
                            INSERT INTO scan_logs (scan_id, level, message)
                            VALUES (?, ?, ?)
                        ''', (scan_id, log_entry.get('level', 'INFO'), log_entry.get('message', '')))
                    
                    conn.commit()
                    self.logger.info(f"Saved scan results for scan ID: {scan_id}")
                    
        except Exception as e:
            self.logger.error(f"Error saving scan results: {e}")
            raise

    def get_scan_history(self, limit: int = 50, offset: int = 0, 
                        status: str = None, scan_type: str = None) -> Dict[str, Any]:
        """Get scan history with optional filtering"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = """
                    SELECT s.*, COUNT(v.id) as vulnerability_count
                    FROM scans s
                    LEFT JOIN vulnerabilities v ON s.id = v.scan_id
                    WHERE 1=1
                """
                params = []
                
                if status:
                    query += " AND s.status = ?"
                    params.append(status)
                
                if scan_type:
                    query += " AND s.scan_type = ?"
                    params.append(scan_type)
                
                query += """
                    GROUP BY s.id
                    ORDER BY s.created_at DESC
                    LIMIT ? OFFSET ?
                """
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                scans = [dict(row) for row in cursor.fetchall()]
                
                return {"scans": scans}
                
        except Exception as e:
            self.logger.error(f"Error getting scan history: {e}")
            return {"scans": []}

    def get_scan_results(self, scan_id: int) -> Optional[Dict]:
        """Get specific scan results with full details"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
                scan = cursor.fetchone()
                
                if not scan:
                    return None
                
                scan_dict = dict(scan)
                
                if scan_dict['results']:
                    scan_dict['results'] = json.loads(scan_dict['results'])
                if scan_dict['metadata']:
                    scan_dict['metadata'] = json.loads(scan_dict['metadata'])
                
                cursor.execute('''
                    SELECT * FROM vulnerabilities 
                    WHERE scan_id = ? 
                    ORDER BY 
                        CASE severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            WHEN 'low' THEN 4 
                            ELSE 5 
                        END
                ''', (scan_id,))
                vulnerabilities = []
                for vuln in cursor.fetchall():
                    vuln_dict = dict(vuln)
                    if vuln_dict['evidence']:
                        vuln_dict['evidence'] = json.loads(vuln_dict['evidence'])
                    vulnerabilities.append(vuln_dict)
                
                scan_dict['vulnerabilities'] = vulnerabilities
                
                cursor.execute('''
                    SELECT level, message, timestamp 
                    FROM scan_logs 
                    WHERE scan_id = ? 
                    ORDER BY timestamp
                ''', (scan_id,))
                scan_dict['logs'] = [dict(row) for row in cursor.fetchall()]
                
                return scan_dict
                
        except Exception as e:
            self.logger.error(f"Error getting scan results: {e}")
            return None

    def get_vulnerability_stats(self, scan_id: int = None) -> Dict[str, Any]:
        """Get vulnerability statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if scan_id:
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM vulnerabilities
                        WHERE scan_id = ?
                        GROUP BY severity
                    ''', (scan_id,))
                else:
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM vulnerabilities
                        GROUP BY severity
                    ''')
                
                stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for row in cursor.fetchall():
                    severity, count = row
                    stats[severity.lower()] = count
                
                stats['total'] = sum(stats.values())
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting vulnerability stats: {e}")
            return {'total': 0}

    def delete_scan(self, scan_id: int) -> bool:
        """Delete a scan and all associated data"""
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
                    deleted = cursor.rowcount > 0
                    conn.commit()
                    if deleted:
                        self.logger.info(f"Deleted scan ID: {scan_id}")
                    return deleted
        except Exception as e:
            self.logger.error(f"Error deleting scan: {e}")
            return False

    def update_vulnerability_status(self, vuln_id: int, verified: bool = None, 
                                  false_positive: bool = None) -> bool:
        """Update vulnerability verification status"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                updates = []
                params = []
                
                if verified is not None:
                    updates.append('verified = ?')
                    params.append(verified)
                if false_positive is not None:
                    updates.append('false_positive = ?')
                    params.append(false_positive)
                
                if not updates:
                    return False
                
                params.append(vuln_id)
                query = f'UPDATE vulnerabilities SET {", ".join(updates)} WHERE id = ?'
                cursor.execute(query, params)
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error updating vulnerability status: {e}")
            return False

    # Dashboard statistics methods
    def get_total_scans(self) -> int:
        """Get total number of scans"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM scans')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting total scans: {e}")
            return 0

    def get_completed_scans(self) -> int:
        """Get number of completed scans"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM scans WHERE status = "completed"')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting completed scans: {e}")
            return 0

    def get_failed_scans(self) -> int:
        """Get number of failed scans"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM scans WHERE status = "failed"')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting failed scans: {e}")
            return 0

    def get_total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting total vulnerabilities: {e}")
            return 0

    def get_high_risk_vulnerabilities(self) -> int:
        """Get number of high risk vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ("critical", "high")')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting high risk vulnerabilities: {e}")
            return 0

    def get_medium_risk_vulnerabilities(self) -> int:
        """Get number of medium risk vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "medium"')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting medium risk vulnerabilities: {e}")
            return 0

    def get_low_risk_vulnerabilities(self) -> int:
        """Get number of low risk vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "low"')
                return cursor.fetchone()[0]
        except Exception as e:
            self.logger.error(f"Error getting low risk vulnerabilities: {e}")
            return 0

    def get_recent_activity(self, limit: int = 5) -> List[Dict]:
        """Get recent scan activity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, target, scan_name, status, created_at
                    FROM scans
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            self.logger.error(f"Error getting recent activity: {e}")
            return []

    def get_scan_progress(self, scan_id: int) -> Optional[Dict]:
        """Get scan progress information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT id, target, scan_name, status, created_at, updated_at
                    FROM scans
                    WHERE id = ?
                ''', (scan_id,))
                scan = cursor.fetchone()
                
                if not scan:
                    return None
                
                scan_dict = dict(scan)
                
                # Calculate progress based on status
                if scan_dict['status'] == 'completed':
                    progress = 100
                elif scan_dict['status'] == 'failed':
                    progress = 0
                else:
                    progress = 50  # Default for running scans
                
                return {
                    'scan_id': scan_dict['id'],
                    'progress': progress,
                    'status': scan_dict['status'],
                    'target': scan_dict['target'],
                    'scan_name': scan_dict['scan_name']
                }
        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")
            return None

    def get_recent_vulnerabilities(self, limit: int = 10) -> Dict[str, Any]:
        """Get recent vulnerabilities"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT v.*, s.target, s.scan_name
                    FROM vulnerabilities v
                    JOIN scans s ON v.scan_id = s.id
                    ORDER BY v.created_at DESC
                    LIMIT ?
                ''', (limit,))
                
                vulnerabilities = [dict(row) for row in cursor.fetchall()]
                return {"vulnerabilities": vulnerabilities}
                
        except Exception as e:
            self.logger.error(f"Error getting recent vulnerabilities: {e}")
            return {"vulnerabilities": []}

    def get_recent_activity(self, limit: int = 5) -> List[Dict]:
        """Get recent activity for dashboard"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT 
                        'scan' as activity_type,
                        s.scan_name as title,
                        s.target as description,
                        s.created_at,
                        s.status
                    FROM scans s
                    ORDER BY s.created_at DESC
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting recent activity: {e}")
            return []

    def close(self):
        """Close database connection"""
        pass
