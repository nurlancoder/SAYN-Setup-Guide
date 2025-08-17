"""
Web Security Module for SAYN
Enhanced web security scanner with comprehensive vulnerability detection
"""
import asyncio
from typing import Dict, Any, List
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLIScanner
from .headers_scanner import HeadersScanner
from .csrf_scanner import CSRFScanner
from .file_inclusion_scanner import FileInclusionScanner

class WebSecurityScanner:
    """Main web security scanner that coordinates all web security checks"""
    
    def __init__(self, config):
        self.config = config
        self.xss_scanner = XSSScanner(config)
        self.sqli_scanner = SQLIScanner(config)
        self.headers_scanner = HeadersScanner(config)
        self.csrf_scanner = CSRFScanner(config)
        self.file_inclusion_scanner = FileInclusionScanner(config)
        self.logger = config.logger if hasattr(config, 'logger') else None

    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run all web security scans with enhanced coordination"""
        scan_results = {
            'module': 'web_security',
            'target': target,
            'vulnerabilities': [],
            'scan_completed': True,
            'modules_executed': [],
            'scan_duration': 0
        }
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Ensure scanner engine is available for all sub-scanners
            scanner_engine = options.get('scanner_engine')
            if not scanner_engine:
                raise ValueError("Scanner engine not provided in options")
            
            scan_tasks = []
            
            if self.config.is_module_enabled('web_security'):
                if options.get('xss_scan', True):
                    scan_tasks.append(self.xss_scanner.scan(target, options))
                    scan_results['modules_executed'].append('xss_scanner')
                
                if options.get('sqli_scan', True):
                    scan_tasks.append(self.sqli_scanner.scan(target, options))
                    scan_results['modules_executed'].append('sqli_scanner')
                
                if options.get('headers_scan', True):
                    scan_tasks.append(self.headers_scanner.scan(target, options))
                    scan_results['modules_executed'].append('headers_scanner')
                
                if options.get('csrf_scan', True):
                    scan_tasks.append(self.csrf_scanner.scan(target, options))
                    scan_results['modules_executed'].append('csrf_scanner')
                
                if options.get('file_inclusion_scan', True):
                    scan_tasks.append(self.file_inclusion_scanner.scan(target, options))
                    scan_results['modules_executed'].append('file_inclusion_scanner')
            
            if scan_tasks:
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        if self.logger:
                            self.logger.error(f"Scan module error: {result}")
                        continue
                    
                    if isinstance(result, dict) and 'vulnerabilities' in result:
                        scan_results['vulnerabilities'].extend(result.get('vulnerabilities', []))
            
            scan_results['scan_duration'] = asyncio.get_event_loop().time() - start_time
            
            if self.logger:
                self.logger.info(f"Web security scan completed for {target} in {scan_results['scan_duration']:.2f}s")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in web security scan: {e}")
            scan_results['scan_completed'] = False
            scan_results['error'] = str(e)
        
        return scan_results

    def get_scan_summary(self, vulnerabilities: List[Dict]) -> Dict[str, int]:
        """Generate summary statistics for vulnerabilities"""
        summary = {
            'total': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
