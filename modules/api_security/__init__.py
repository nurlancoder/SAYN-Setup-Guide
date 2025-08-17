"""
API Security Module for SAYN
Enhanced API security scanner with REST and GraphQL vulnerability detection
"""
import asyncio
from typing import Dict, Any, List
from .rest_scanner import RESTScanner
from .graphql_scanner import GraphQLScanner

class APISecurityScanner:
    """Main API security scanner that coordinates all API security checks"""
    
    def __init__(self, config):
        self.config = config
        self.rest_scanner = RESTScanner(config)
        self.graphql_scanner = GraphQLScanner(config)
        self.logger = config.logger if hasattr(config, 'logger') else None

    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Run all API security scans with enhanced coordination"""
        scan_results = {
            'module': 'api_security',
            'target': target,
            'vulnerabilities': [],
            'scan_completed': True,
            'modules_executed': [],
            'scan_duration': 0
        }
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            scan_tasks = []
            
            if self.config.is_module_enabled('api_security'):
                if options.get('rest_scan', True):
                    scan_tasks.append(self.rest_scanner.scan(target, options))
                    scan_results['modules_executed'].append('rest_scanner')
                
                if options.get('graphql_scan', True):
                    scan_tasks.append(self.graphql_scanner.scan(target, options))
                    scan_results['modules_executed'].append('graphql_scanner')
            
            if scan_tasks:
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        if self.logger:
                            self.logger.error(f"API scan module error: {result}")
                        continue
                    
                    if isinstance(result, dict) and 'vulnerabilities' in result:
                        scan_results['vulnerabilities'].extend(result.get('vulnerabilities', []))
            
            scan_results['scan_duration'] = asyncio.get_event_loop().time() - start_time
            
            if self.logger:
                self.logger.info(f"API security scan completed for {target} in {scan_results['scan_duration']:.2f}s")
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error in API security scan: {e}")
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
