"""
Network Security Module for SAYN
Enhanced network security scanner with port scanning and SSL/TLS analysis
"""
import asyncio
from typing import Dict, Any, List
from .port_scanner import PortScanner
from .ssl_scanner import SSLScanner

class NetworkSecurityScanner:
    """Main network security scanner that coordinates all network security checks"""
    
    def __init__(self, config):
        self.config = config
        self.port_scanner = PortScanner(config)
        self.ssl_scanner = SSLScanner(config)
        self.logger = config.logger if hasattr(config, 'logger') else None

    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run all network security scans with enhanced coordination"""
        scan_results = {
            'module': 'network_security',
            'target': target,
            'vulnerabilities': [],
            'scan_completed': True,
            'modules_executed': [],
            'scan_duration': 0
        }
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            scan_tasks = []
            
            if self.config.is_module_enabled('network_security'):
                if options.get('port_scan', True):
                    scan_tasks.append(self.port_scanner.scan(target, options))
                    scan_results['modules_executed'].append('port_scanner')
                
                if options.get('ssl_scan', True):
                    scan_tasks.append(self.ssl_scanner.scan(target, options))
                    scan_results['modules_executed'].append('ssl_scanner')
            
            if scan_tasks:
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        if self.logger:
                            self.logger.error(f"Network scan module error: {result}")
                        continue
                    
                    if isinstance(result, dict) and 'vulnerabilities' in result:
                        scan_results['vulnerabilities'].extend(result.get('vulnerabilities', []))
            
            scan_results['scan_duration'] = asyncio.get_event_loop().time() - start_time
            
            if self.logger:
                self.logger.info(f"Network security scan completed for {target} in {scan_results['scan_duration']:.2f}s")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in network security scan: {e}")
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
