"""
SAYN Utilities
Enhanced utilities with better logging and report generation
"""
import logging
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import hashlib
import shutil
import zipfile
from io import BytesIO
import base64

class Logger:
    """Enhanced logging utility with rotation and multiple handlers"""
    
    def __init__(self, name: str = "SAYN", level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        if self.logger.handlers:
            return
        
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_dir / f"sayn_{datetime.now().strftime('%Y%m%d')}.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        error_handler = RotatingFileHandler(
            log_dir / f"sayn_errors_{datetime.now().strftime('%Y%m%d')}.log",
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        error_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        self.logger.addHandler(error_handler)

    def info(self, message: str):
        self.logger.info(message)

    def error(self, message: str):
        self.logger.error(message)

    def warning(self, message: str):
        self.logger.warning(message)

    def debug(self, message: str):
        self.logger.debug(message)

    def critical(self, message: str):
        self.logger.critical(message)

class ReportGenerator:
    """Enhanced report generation utility with multiple formats"""
    
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger('SAYN.reports')

    def generate(self, scan_results: Dict[str, Any], format_type: str = 'html') -> str:
        """Generate report in specified format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_hash = hashlib.md5(scan_results['target'].encode()).hexdigest()[:8]
        filename = f"sayn_report_{target_hash}_{timestamp}"
        
        try:
            if format_type == 'json':
                return self._generate_json(scan_results, filename)
            elif format_type == 'html':
                return self._generate_html(scan_results, filename)
            elif format_type == 'pdf':
                return self._generate_pdf(scan_results, filename)
            elif format_type == 'xml':
                return self._generate_xml(scan_results, filename)
            elif format_type == 'csv':
                return self._generate_csv(scan_results, filename)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
        except Exception as e:
            self.logger.error(f"Error generating {format_type} report: {e}")
            raise

    def _generate_json(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Generate JSON report"""
        filepath = self.reports_dir / f"{filename}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=4, default=str, ensure_ascii=False)
        return str(filepath)

    def _generate_html(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Generate enhanced HTML report with modern design"""
        filepath = self.reports_dir / f"{filename}.html"
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SAYN Security Report - {scan_results['target']}</title>
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
            <style>
                .gradient-bg {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }}
                .vuln-card {{
                    transition: all 0.3s ease;
                }}
                .vuln-card:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 8px 25px rgba(0,0,0,0.15);
                }}
                .severity-critical {{ background: linear-gradient(135deg, #ff6b6b, #ee5a52); }}
                .severity-high {{ background: linear-gradient(135deg, #ffa726, #ff9800); }}
                .severity-medium {{ background: linear-gradient(135deg, #ffd54f, #ffc107); }}
                .severity-low {{ background: linear-gradient(135deg, #81c784, #4caf50); }}
                .severity-info {{ background: linear-gradient(135deg, #64b5f6, #2196f3); }}
                
                @media print {{
                    .no-print {{ display: none !important; }}
                    .print-break {{ page-break-before: always; }}
                }}
            </style>
        </head>
        <body class="bg-gray-50 min-h-screen">
            <!-- Header -->
            <div class="gradient-bg text-white py-8">
                <div class="container mx-auto px-6">
                    <div class="flex items-center justify-between">
                        <div>
                            <h1 class="text-4xl font-bold mb-2">SAYN Security Scanner</h1>
                            <p class="text-xl opacity-90">Comprehensive Security Assessment Report</p>
                        </div>
                        <div class="text-right">
                            <div class="text-6xl font-bold mb-2">{scan_results['risk_score']}/100</div>
                            <div class="text-lg opacity-90">Risk Score</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Report Info -->
            <div class="container mx-auto px-6 py-8">
                <div class="bg-white rounded-lg shadow-lg p-6 mb-8">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-700 mb-2">Target Information</h3>
                            <p class="text-gray-600"><strong>URL:</strong> {scan_results['target']}</p>
                            <p class="text-gray-600"><strong>Scan Date:</strong> {scan_results.get('timestamp', 'N/A')}</p>
                            <p class="text-gray-600"><strong>Scan Duration:</strong> {scan_results.get('duration', 'N/A')}</p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-700 mb-2">Scan Summary</h3>
                            <p class="text-gray-600"><strong>Total Vulnerabilities:</strong> {scan_results['summary']['total_vulnerabilities']}</p>
                            <p class="text-gray-600"><strong>Modules Executed:</strong> {scan_results['summary']['modules_executed']}</p>
                            <p class="text-gray-600"><strong>Scan Type:</strong> {scan_results.get('scan_type', 'Comprehensive')}</p>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-700 mb-2">Risk Assessment</h3>
                            <div class="space-y-2">
                                <div class="flex justify-between">
                                    <span class="text-red-600">Critical:</span>
                                    <span class="font-semibold">{scan_results['summary']['critical']}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-orange-600">High:</span>
                                    <span class="font-semibold">{scan_results['summary']['high']}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-yellow-600">Medium:</span>
                                    <span class="font-semibold">{scan_results['summary']['medium']}</span>
                                </div>
                                <div class="flex justify-between">
                                    <span class="text-green-600">Low:</span>
                                    <span class="font-semibold">{scan_results['summary']['low']}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Vulnerability Details -->
                <div class="bg-white rounded-lg shadow-lg p-6">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6">Detailed Findings</h2>
                    {self._generate_vulnerability_html(scan_results['vulnerabilities'])}
                </div>

                <!-- Recommendations -->
                <div class="bg-white rounded-lg shadow-lg p-6 mt-8">
                    <h2 class="text-2xl font-bold text-gray-800 mb-6">Security Recommendations</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <h3 class="text-lg font-semibold text-gray-700 mb-3">Immediate Actions</h3>
                            <ul class="space-y-2 text-gray-600">
                                <li class="flex items-start">
                                    <i class="fas fa-exclamation-triangle text-red-500 mt-1 mr-2"></i>
                                    Address all critical vulnerabilities first
                                </li>
                                <li class="flex items-start">
                                    <i class="fas fa-shield-alt text-orange-500 mt-1 mr-2"></i>
                                    Implement proper input validation
                                </li>
                                <li class="flex items-start">
                                    <i class="fas fa-lock text-blue-500 mt-1 mr-2"></i>
                                    Enable security headers
                                </li>
                            </ul>
                        </div>
                        <div>
                            <h3 class="text-lg font-semibold text-gray-700 mb-3">Long-term Improvements</h3>
                            <ul class="space-y-2 text-gray-600">
                                <li class="flex items-start">
                                    <i class="fas fa-code text-purple-500 mt-1 mr-2"></i>
                                    Regular security code reviews
                                </li>
                                <li class="flex items-start">
                                    <i class="fas fa-sync text-green-500 mt-1 mr-2"></i>
                                    Automated security testing
                                </li>
                                <li class="flex items-start">
                                    <i class="fas fa-users text-indigo-500 mt-1 mr-2"></i>
                                    Security awareness training
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div class="text-center py-8 text-gray-500">
                    <p>Generated by SAYN Security Scanner v2.1</p>
                    <p class="mt-2">
                        <strong>Author:</strong> Məmmədli Nurlan | 
                        <strong>Email:</strong> nurlanmammadli2@gmail.com | 
                        <strong>GitHub:</strong> <a href="https://github.com/nurlancoder" class="text-blue-600 hover:underline">nurlancoder</a>
                    </p>
                    <p class="mt-2 text-sm">
                        ⚠️ This report is for authorized security testing only. 
                        Use only on systems you own or have permission to test.
                    </p>
                </div>
            </div>

            <!-- Print Button -->
            <div class="no-print fixed bottom-6 right-6">
                <button onclick="window.print()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-full shadow-lg transition duration-300">
                    <i class="fas fa-print mr-2"></i>Print Report
                </button>
            </div>
        </body>
        </html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        return str(filepath)

    def _generate_pdf(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Generate PDF report"""
        html_path = self._generate_html(scan_results, filename)
        pdf_path = self.reports_dir / f"{filename}.pdf"
        
        try:
            import weasyprint
            weasyprint.HTML(html_path).write_pdf(pdf_path)
            return str(pdf_path)
        except ImportError:
            self.logger.warning("weasyprint not installed. PDF generation skipped.")
            return html_path
        except Exception as e:
            self.logger.error(f"Error generating PDF: {e}")
            return html_path

    def _generate_xml(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Generate XML report"""
        filepath = self.reports_dir / f"{filename}.xml"
        
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<sayn_report version="2.1">
    <meta>
        <target>{scan_results['target']}</target>
        <timestamp>{scan_results.get('timestamp', '')}</timestamp>
        <risk_score>{scan_results['risk_score']}</risk_score>
        <scan_type>{scan_results.get('scan_type', 'comprehensive')}</scan_type>
    </meta>
    <summary>
        <total_vulnerabilities>{scan_results['summary']['total_vulnerabilities']}</total_vulnerabilities>
        <critical>{scan_results['summary']['critical']}</critical>
        <high>{scan_results['summary']['high']}</high>
        <medium>{scan_results['summary']['medium']}</medium>
        <low>{scan_results['summary']['low']}</low>
        <modules_executed>{scan_results['summary']['modules_executed']}</modules_executed>
    </summary>
    <vulnerabilities>
"""
        
        for vuln in scan_results['vulnerabilities']:
            xml_content += f"""
        <vulnerability>
            <type>{vuln.get('type', '')}</type>
            <severity>{vuln.get('severity', '')}</severity>
            <title><![CDATA[{vuln.get('title', '')}]]></title>
            <description><![CDATA[{vuln.get('description', '')}]]></description>
            <location><![CDATA[{vuln.get('location', '')}]]></location>
            <recommendation><![CDATA[{vuln.get('recommendation', '')}]]></recommendation>
            <cve_id>{vuln.get('cve_id', '')}</cve_id>
            <cvss_score>{vuln.get('cvss_score', 0.0)}</cvss_score>
        </vulnerability>
"""
        
        xml_content += """
    </vulnerabilities>
    <footer>
        <generated_by>SAYN Security Scanner v2.1</generated_by>
        <author>Məmmədli Nurlan</author>
        <email>nurlanmammadli2@gmail.com</email>
        <github>https://github.com/nurlancoder</github>
    </footer>
</sayn_report>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        
        return str(filepath)

    def _generate_csv(self, scan_results: Dict[str, Any], filename: str) -> str:
        """Generate CSV report"""
        filepath = self.reports_dir / f"{filename}.csv"
        
        import csv
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            writer.writerow([
                'Type', 'Severity', 'Title', 'Description', 'Location', 
                'Recommendation', 'CVE ID', 'CVSS Score'
            ])
            
            for vuln in scan_results['vulnerabilities']:
                writer.writerow([
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('title', ''),
                    vuln.get('description', ''),
                    vuln.get('location', ''),
                    vuln.get('recommendation', ''),
                    vuln.get('cve_id', ''),
                    vuln.get('cvss_score', 0.0)
                ])
        
        return str(filepath)

    def _get_risk_class(self, score: int) -> str:
        """Get CSS class for risk score"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'

    def _generate_vulnerability_html(self, vulnerabilities: List[Dict]) -> str:
        """Generate HTML for vulnerability list with enhanced styling"""
        if not vulnerabilities:
            return """
            <div class="text-center py-8">
                <i class="fas fa-check-circle text-green-500 text-4xl mb-4"></i>
                <h3 class="text-xl font-semibold text-gray-700 mb-2">No Vulnerabilities Detected</h3>
                <p class="text-gray-500">Great! No security issues were found during this scan.</p>
            </div>
            """
        
        html = ""
        for i, vuln in enumerate(vulnerabilities):
            severity_class = vuln.get('severity', 'low').lower()
            severity_colors = {
                'critical': 'text-red-600 bg-red-50 border-red-200',
                'high': 'text-orange-600 bg-orange-50 border-orange-200',
                'medium': 'text-yellow-600 bg-yellow-50 border-yellow-200',
                'low': 'text-green-600 bg-green-50 border-green-200',
                'info': 'text-blue-600 bg-blue-50 border-blue-200'
            }
            
            html += f"""
            <div class="vuln-card border rounded-lg p-6 mb-6 {severity_colors.get(severity_class, 'border-gray-200')}">
                <div class="flex items-start justify-between mb-4">
                    <div class="flex items-center">
                        <span class="severity-{severity_class} text-white px-3 py-1 rounded-full text-sm font-semibold mr-3">
                            {vuln.get('severity', 'LOW').upper()}
                        </span>
                        <h3 class="text-lg font-semibold text-gray-800">{vuln.get('title', 'Unknown Vulnerability')}</h3>
                    </div>
                    <div class="text-sm text-gray-500">
                        #{i+1}
                    </div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <p class="text-sm font-medium text-gray-600 mb-1">Type</p>
                        <p class="text-gray-800">{vuln.get('type', 'N/A')}</p>
                    </div>
                    <div>
                        <p class="text-sm font-medium text-gray-600 mb-1">Location</p>
                        <p class="text-gray-800 break-all">{vuln.get('location', 'N/A')}</p>
                    </div>
                </div>
                
                <div class="mb-4">
                    <p class="text-sm font-medium text-gray-600 mb-1">Description</p>
                    <p class="text-gray-800">{vuln.get('description', 'No description available')}</p>
                </div>
                
                <div class="mb-4">
                    <p class="text-sm font-medium text-gray-600 mb-1">Recommendation</p>
                    <p class="text-gray-800">{vuln.get('recommendation', 'No recommendation available')}</p>
                </div>
                
                {f"<div class='mb-4'><p class='text-sm font-medium text-gray-600 mb-1'>CVE ID</p><p class='text-gray-800'>{vuln['cve_id']}</p></div>" if vuln.get('cve_id') else ""}
                
                {f"<div><p class='text-sm font-medium text-gray-600 mb-1'>CVSS Score</p><p class='text-gray-800'>{vuln['cvss_score']}</p></div>" if vuln.get('cvss_score') else ""}
            </div>
            """
        
        return html

    def create_report_archive(self, scan_results: Dict[str, Any], formats: List[str] = None) -> str:
        """Create a ZIP archive containing reports in multiple formats"""
        if formats is None:
            formats = ['html', 'json', 'pdf', 'xml']
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_hash = hashlib.md5(scan_results['target'].encode()).hexdigest()[:8]
        archive_name = f"sayn_report_{target_hash}_{timestamp}.zip"
        archive_path = self.reports_dir / archive_name
        
        with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for format_type in formats:
                try:
                    report_path = self.generate(scan_results, format_type)
                    zipf.write(report_path, os.path.basename(report_path))
                except Exception as e:
                    self.logger.error(f"Error adding {format_type} report to archive: {e}")
        
        return str(archive_path)
