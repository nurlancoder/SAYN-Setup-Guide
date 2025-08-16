"""
Test suite for SAYN Security Scanner core functionality
"""

import unittest
import asyncio
import tempfile
import os
import json
from unittest.mock import Mock, patch, AsyncMock

from core.config import Config
from core.database import DatabaseManager
from core.scanner import ScannerEngine
from core.utils import Logger, ReportGenerator


class TestConfig(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'test_config.json')
        
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_config_creation(self):
        """Test config creation with default values"""
        config = Config(self.config_file)
        self.assertIsNotNone(config.get('database'))
        self.assertIsNotNone(config.get('scanning'))
        self.assertIsNotNone(config.get('modules'))
    
    def test_config_save_load(self):
        """Test config save and load functionality"""
        config = Config(self.config_file)
        config.set('test_key', 'test_value')
        config.save()
        
        new_config = Config(self.config_file)
        self.assertEqual(new_config.get('test_key'), 'test_value')
    
    def test_module_enabled(self):
        """Test module enabled check"""
        config = Config(self.config_file)
        config.set('modules', {
            'web_security': {'enabled': True},
            'api_security': {'enabled': False}
        })
        
        self.assertTrue(config.is_module_enabled('web_security'))
        self.assertFalse(config.is_module_enabled('api_security'))


class TestDatabase(unittest.TestCase):
    """Test database management"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.temp_dir, 'test.db')
        self.db = DatabaseManager(self.db_file)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_database_creation(self):
        """Test database creation and table setup"""
        self.db.create_tables()
        
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        self.assertIn('scans', tables)
        self.assertIn('vulnerabilities', tables)
        self.assertIn('scan_logs', tables)
    
    def test_scan_insertion(self):
        """Test scan insertion and retrieval"""
        self.db.create_tables()
        
        scan_data = {
            'target': 'https://example.com',
            'scan_type': 'web',
            'status': 'completed',
            'scan_name': 'Test Scan'
        }
        
        scan_id = self.db.insert_scan(scan_data)
        self.assertIsNotNone(scan_id)
        
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['target'], 'https://example.com')
        self.assertEqual(scan['scan_type'], 'web')
    
    def test_vulnerability_insertion(self):
        """Test vulnerability insertion and retrieval"""
        self.db.create_tables()
        
        vuln_data = {
            'scan_id': 1,
            'type': 'xss',
            'severity': 'high',
            'title': 'XSS Vulnerability',
            'description': 'Cross-site scripting vulnerability found',
            'location': 'https://example.com/page',
            'recommendation': 'Fix the XSS issue'
        }
        
        vuln_id = self.db.insert_vulnerability(vuln_data)
        self.assertIsNotNone(vuln_id)
        
        vuln = self.db.get_vulnerability(vuln_id)
        self.assertEqual(vuln['type'], 'xss')
        self.assertEqual(vuln['severity'], 'high')


class TestScannerEngine(unittest.TestCase):
    """Test scanner engine functionality"""
    
    def setUp(self):
        self.scanner = ScannerEngine()
    
    @patch('aiohttp.ClientSession.get')
    def test_make_request(self, mock_get):
        """Test HTTP request functionality"""
        mock_response = AsyncMock()
        mock_response.text.return_value = "<html>Test content</html>"
        mock_response.status = 200
        mock_response.headers = {'content-type': 'text/html'}
        mock_get.return_value.__aenter__.return_value = mock_response
        
        async def test_request():
            result = await self.scanner.make_request('https://example.com')
            self.assertEqual(result['status_code'], 200)
            self.assertIn('Test content', result['content'])
        
        asyncio.run(test_request())
    
    def test_health_check(self):
        """Test health check functionality"""
        async def test_health():
            result = await self.scanner.health_check('https://example.com')
            self.assertIsInstance(result, dict)
        
        asyncio.run(test_health())


class TestLogger(unittest.TestCase):
    """Test logging functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, 'test.log')
        self.logger = Logger(self.log_file)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_log_creation(self):
        """Test log file creation"""
        self.logger.info("Test log message")
        self.assertTrue(os.path.exists(self.log_file))
    
    def test_log_levels(self):
        """Test different log levels"""
        self.logger.debug("Debug message")
        self.logger.info("Info message")
        self.logger.warning("Warning message")
        self.logger.error("Error message")
        
        with open(self.log_file, 'r') as f:
            content = f.read()
            self.assertIn("Info message", content)
            self.assertIn("Error message", content)


class TestReportGenerator(unittest.TestCase):
    """Test report generation functionality"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.report_dir = os.path.join(self.temp_dir, 'reports')
        os.makedirs(self.report_dir, exist_ok=True)
        self.generator = ReportGenerator(self.report_dir)
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_html_report_generation(self):
        """Test HTML report generation"""
        scan_data = {
            'id': 1,
            'target': 'https://example.com',
            'scan_type': 'web',
            'status': 'completed',
            'created_at': '2024-01-01 12:00:00'
        }
        
        vulnerabilities = [
            {
                'type': 'xss',
                'severity': 'high',
                'title': 'XSS Vulnerability',
                'description': 'Cross-site scripting vulnerability found',
                'location': 'https://example.com/page',
                'recommendation': 'Fix the XSS issue'
            }
        ]
        
        report_path = self.generator.generate_html_report(scan_data, vulnerabilities)
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith('.html'))
    
    def test_json_report_generation(self):
        """Test JSON report generation"""
        scan_data = {
            'id': 1,
            'target': 'https://example.com',
            'scan_type': 'web',
            'status': 'completed'
        }
        
        vulnerabilities = [
            {
                'type': 'xss',
                'severity': 'high',
                'title': 'XSS Vulnerability'
            }
        ]
        
        report_path = self.generator.generate_json_report(scan_data, vulnerabilities)
        self.assertTrue(os.path.exists(report_path))
        self.assertTrue(report_path.endswith('.json'))
        
        with open(report_path, 'r') as f:
            data = json.load(f)
            self.assertEqual(data['scan']['target'], 'https://example.com')
            self.assertEqual(len(data['vulnerabilities']), 1)


class TestIntegration(unittest.TestCase):
    """Integration tests for core components"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, 'config.json')
        self.db_file = os.path.join(self.temp_dir, 'test.db')
        self.log_file = os.path.join(self.temp_dir, 'test.log')
        
        self.config = Config(self.config_file)
        self.db = DatabaseManager(self.db_file)
        self.logger = Logger(self.log_file)
        self.scanner = ScannerEngine()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_full_scan_workflow(self):
        """Test complete scan workflow"""
        self.db.create_tables()
        
        scan_data = {
            'target': 'https://example.com',
            'scan_type': 'web',
            'status': 'running',
            'scan_name': 'Integration Test Scan'
        }
        
        scan_id = self.db.insert_scan(scan_data)
        self.assertIsNotNone(scan_id)
        
        vuln_data = {
            'scan_id': scan_id,
            'type': 'xss',
            'severity': 'high',
            'title': 'XSS Vulnerability',
            'description': 'Test vulnerability',
            'location': 'https://example.com/page',
            'recommendation': 'Fix the issue'
        }
        
        vuln_id = self.db.insert_vulnerability(vuln_data)
        self.assertIsNotNone(vuln_id)
        
        self.db.update_scan_status(scan_id, 'completed')
        
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['status'], 'completed')
        
        vulnerabilities = self.db.get_scan_vulnerabilities(scan_id)
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['type'], 'xss')


if __name__ == '__main__':
    unittest.main()
