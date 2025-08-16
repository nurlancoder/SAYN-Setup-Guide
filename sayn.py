"""
SAYN Security Scanner v2.1.0
Main entry point for the SAYN security scanner
"""
import asyncio
import argparse
import sys
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import ScannerEngine
from core.database import DatabaseManager
from core.config import Config
from core.utils import Logger, ReportGenerator

class SAYN:
    """Main SAYN Security Scanner class"""
    
    def __init__(self, config_file: str = None):
        """Initialize SAYN scanner"""
        self.config = Config(config_file)
        self.db = DatabaseManager()
        self.logger = Logger()
        self.report_gen = ReportGenerator()
        self.scanner_engine = ScannerEngine()
        
        self._init_modules()
        
        self.logger.info("SAYN Security Scanner v2.1.0 initialized")

    def _init_modules(self):
        """Initialize security modules"""
        try:
            from modules.web_security import WebSecurityScanner
            from modules.network_security import NetworkSecurityScanner
            from modules.api_security import APISecurityScanner
            
            self.web_scanner = WebSecurityScanner(self.config)
            self.network_scanner = NetworkSecurityScanner(self.config)
            self.api_scanner = APISecurityScanner(self.config)
            
        except ImportError as e:
            self.logger.warning(f"Some modules could not be loaded: {e}")

    async def scan_target(self, target: str, modules: List[str] = None, 
                         options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Scan a target with specified modules"""
        if modules is None:
            modules = ['web']
        
        if options is None:
            options = {}
        
        start_time = datetime.now()
        self.logger.info(f"Starting scan of {target} with modules: {modules}")
        
        scan_id = self.db.create_scan_record(
            target=target,
            scan_name=options.get('scan_name', f'Scan {start_time.strftime("%Y-%m-%d %H:%M")}'),
            scan_type=','.join(modules),
            scan_depth=options.get('scan_depth', 'normal'),
            threads=options.get('threads', 10),
            timeout=options.get('timeout', 30)
        )
        
        scan_results = {
            'scan_id': scan_id,
            'target': target,
            'modules': modules,
            'options': options,
            'timestamp': start_time.isoformat(),
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'modules_executed': []
            },
            'logs': []
        }
        
        try:
            scan_tasks = []
            
            if 'web' in modules and hasattr(self, 'web_scanner'):
                scan_tasks.append(self.web_scanner.scan(target, options))
                scan_results['summary']['modules_executed'].append('web_security')
            
            if 'network' in modules and hasattr(self, 'network_scanner'):
                scan_tasks.append(self.network_scanner.scan(target, options))
                scan_results['summary']['modules_executed'].append('network_security')
            
            if 'api' in modules and hasattr(self, 'api_scanner'):
                scan_tasks.append(self.api_scanner.scan(target, options))
                scan_results['summary']['modules_executed'].append('api_security')
            
            if scan_tasks:
                results = await asyncio.gather(*scan_tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Module scan error: {result}")
                        continue
                    
                    if isinstance(result, dict) and 'vulnerabilities' in result:
                        scan_results['vulnerabilities'].extend(result.get('vulnerabilities', []))
            
            scan_results['summary']['total_vulnerabilities'] = len(scan_results['vulnerabilities'])
            
            for vuln in scan_results['vulnerabilities']:
                severity = vuln.get('severity', 'low').lower()
                if severity in scan_results['summary']:
                    scan_results['summary'][severity] += 1
            
            scan_results['risk_score'] = self._calculate_risk_score(scan_results['vulnerabilities'])
            
            end_time = datetime.now()
            scan_results['duration'] = str(end_time - start_time)
            
            self.db.save_scan_results(scan_results)
            
            self.logger.info(f"Scan completed in {scan_results['duration']}")
            self.logger.info(f"Found {scan_results['summary']['total_vulnerabilities']} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            scan_results['error'] = str(e)
            scan_results['scan_completed'] = False
        
        return scan_results

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate overall risk score based on vulnerabilities"""
        if not vulnerabilities:
            return 0
        
        weights = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1,
            'info': 0
        }
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            total_score += weights.get(severity, 1)
        
        max_possible_score = len(vulnerabilities) * 10
        risk_score = min(100, int((total_score / max_possible_score) * 100))
        
        return risk_score

    def generate_report(self, scan_results: Dict[str, Any], 
                       format_type: str = 'html') -> str:
        """Generate report in specified format"""
        try:
            report_path = self.report_gen.generate(scan_results, format_type)
            self.logger.info(f"Report generated: {report_path}")
            return report_path
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            raise

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all components"""
        health_status = {
            'status': 'healthy',
            'components': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            scanner_health = await self.scanner_engine.health_check()
            health_status['components']['scanner_engine'] = scanner_health
            
            try:
                self.db.get_scan_history(limit=1)
                health_status['components']['database'] = {'status': 'healthy'}
            except Exception as e:
                health_status['components']['database'] = {'status': 'unhealthy', 'error': str(e)}
            
            health_status['components']['configuration'] = {'status': 'healthy'}
            
            if any(comp.get('status') == 'unhealthy' for comp in health_status['components'].values()):
                health_status['status'] = 'unhealthy'
                
        except Exception as e:
            health_status['status'] = 'error'
            health_status['error'] = str(e)
        
        return health_status

def main():
    """Main entry point for command line usage"""
    parser = argparse.ArgumentParser(
        description='SAYN Security Scanner v2.1.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sayn.py -u https://example.com
  python sayn.py -u https://example.com -m web,api --depth deep
  python sayn.py -u 192.168.1.1 -m network --threads 20
  python sayn.py --web-interface
        """
    )
    
    parser.add_argument('-u', '--url', required=False,
                       help='Target URL or IP address to scan')
    parser.add_argument('-m', '--modules', default='web',
                       help='Comma-separated list of modules (web,network,api,all)')
    parser.add_argument('--depth', choices=['quick', 'normal', 'deep'], default='normal',
                       help='Scan depth (default: normal)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--format', choices=['html', 'pdf', 'json', 'xml', 'csv'], default='html',
                       help='Report format (default: html)')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--web-interface', action='store_true',
                       help='Start web interface')
    parser.add_argument('--host', default='0.0.0.0',
                       help='Host for web interface (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port for web interface (default: 5000)')
    parser.add_argument('--health-check', action='store_true',
                       help='Perform health check')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    sayn = SAYN(args.config)
    
    if args.verbose:
        sayn.logger.logger.setLevel('DEBUG')
    
    async def run_scan():
        if args.health_check:
            health = await sayn.health_check()
            print(f"Health Check: {health['status']}")
            for component, status in health['components'].items():
                print(f"  {component}: {status['status']}")
            return
        
        if args.web_interface:
            from web_interface.app import create_app
            
            app = create_app()
            
            print("Starting SAYN Web Interface...")
            print(f"Access at: http://{args.host}:{args.port}")
            
            app.socketio.run(app, host=args.host, port=args.port, debug=False)
            return
        
        if not args.url:
            parser.error("URL is required unless using --web-interface or --health-check")
        
        if args.modules == 'all':
            modules = ['web', 'network', 'api']
        else:
            modules = [m.strip() for m in args.modules.split(',')]
        
        options = {
            'scan_depth': args.depth,
            'threads': args.threads,
            'timeout': args.timeout,
            'verbose': args.verbose
        }
        
        results = await sayn.scan_target(args.url, modules, options)
        
        report_path = sayn.generate_report(results, args.format)
        
        print(f"\nScan completed!")
        print(f"Target: {results['target']}")
        print(f"Duration: {results['duration']}")
        print(f"Vulnerabilities found: {results['summary']['total_vulnerabilities']}")
        print(f"Risk Score: {results['risk_score']}/100")
        print(f"Report saved: {report_path}")
        
        if results['vulnerabilities']:
            print("\nVulnerability Summary:")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = results['summary'][severity]
                if count > 0:
                    print(f"  {severity.title()}: {count}")
    
    asyncio.run(run_scan())

if __name__ == '__main__':
    main()
