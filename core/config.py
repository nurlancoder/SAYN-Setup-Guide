"""
SAYN Configuration Management
Enhanced configuration manager with better validation and features
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging
from datetime import datetime

class Config:
    """Enhanced configuration manager for SAYN"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or os.path.join(os.path.dirname(__file__), '..', 'config.json')
        self.logger = logging.getLogger('SAYN.config')
        self.config = self._load_config()
        self._validate_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file with enhanced defaults"""
        default_config = {
            'database': {
                'type': 'sqlite',
                'path': 'sayn_data.db',
                'host': 'localhost',
                'port': 5432,
                'username': '',
                'password': '',
                'pool_size': 10,
                'max_overflow': 20
            },
            'scanning': {
                'max_threads': 20,
                'timeout': 30,
                'retry_attempts': 3,
                'user_agent': 'SAYN Security Scanner v2.1',
                'max_redirects': 5,
                'rate_limit': 10,
                'delay_between_requests': 0.1,
                'max_concurrent_requests': 50
            },
            'modules': {
                'web_security': {
                    'enabled': True,
                    'aggressive_mode': False,
                    'xss_payloads': [
                        '<script>alert("SAYN-XSS")</script>',
                        '"><script>alert("SAYN-XSS")</script>',
                        "';alert('SAYN-XSS');//",
                        '<img src=x onerror=alert("SAYN-XSS")>',
                        'javascript:alert("SAYN-XSS")'
                    ],
                    'sqli_payloads': [
                        "' OR '1'='1",
                        "' UNION SELECT NULL--",
                        "'; DROP TABLE users--",
                        "' OR 1=1--"
                    ]
                },
                'network_security': {
                    'enabled': True,
                    'port_range': '1-10000',
                    'common_ports': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080],
                    'ssl_scan': True,
                    'tls_versions': ['TLSv1.2', 'TLSv1.3']
                },
                'api_security': {
                    'enabled': True,
                    'test_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                    'auth_endpoints': ['/login', '/auth', '/token', '/oauth'],
                    'rate_limit_testing': True
                }
            },
            'reporting': {
                'output_dir': 'reports',
                'include_screenshots': True,
                'include_raw_data': False,
                'formats': ['html', 'json', 'pdf', 'xml'],
                'template_path': 'templates/reports',
                'auto_generate': True
            },
            'web_interface': {
                'host': '0.0.0.0',
                'port': 5000,
                'secret_key': 'sayn-secret-key-change-in-production',
                'debug': False,
                'ssl_enabled': False,
                'ssl_cert': '',
                'ssl_key': '',
                'session_timeout': 3600,
                'max_file_size': 10485760  # 10MB
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/sayn.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'security': {
                'allowed_hosts': ['*'],
                'csrf_protection': True,
                'rate_limiting': True,
                'max_requests_per_minute': 100,
                'blocked_ips': [],
                'whitelist_ips': []
            },
            'notifications': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_address': '',
                    'to_addresses': []
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': '',
                    'channel': '#security'
                }
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                self._deep_update(default_config, user_config)
                self.logger.info(f"Loaded configuration from {self.config_file}")
            else:
                self.save_config(default_config)
                self.logger.info(f"Created default configuration at {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error loading config: {e}. Using defaults.")
        
        return default_config

    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Deep update dictionary recursively"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _validate_config(self):
        """Validate configuration values"""
        try:
            scanning = self.config.get('scanning', {})
            if scanning.get('max_threads', 0) <= 0:
                self.logger.warning("max_threads must be positive, setting to 20")
                scanning['max_threads'] = 20
            
            if scanning.get('timeout', 0) <= 0:
                self.logger.warning("timeout must be positive, setting to 30")
                scanning['timeout'] = 30
            
            web_interface = self.config.get('web_interface', {})
            if not web_interface.get('secret_key') or web_interface['secret_key'] == 'sayn-secret-key-change-in-production':
                self.logger.warning("Please change the default secret key in production")
            
            if web_interface.get('port', 0) <= 0 or web_interface.get('port', 0) > 65535:
                self.logger.warning("Invalid port number, setting to 5000")
                web_interface['port'] = 5000
            
            self.logger.info("Configuration validation completed")
            
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value

    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config_ref = self.config
        
        for k in keys[:-1]:
            if k not in config_ref:
                config_ref[k] = {}
            config_ref = config_ref[k]
        
        config_ref[keys[-1]] = value
        self.logger.info(f"Updated configuration: {key} = {value}")

    def save_config(self, config_data: Dict = None):
        """Save configuration to file"""
        data = config_data or self.config
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")

    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()
        self._validate_config()
        self.logger.info("Configuration reloaded")

    def get_module_config(self, module_name: str) -> Dict[str, Any]:
        """Get configuration for a specific module"""
        return self.config.get('modules', {}).get(module_name, {})

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled"""
        module_config = self.get_module_config(module_name)
        return module_config.get('enabled', False)

    def get_scanning_config(self) -> Dict[str, Any]:
        """Get scanning configuration"""
        return self.config.get('scanning', {})

    def get_web_interface_config(self) -> Dict[str, Any]:
        """Get web interface configuration"""
        return self.config.get('web_interface', {})

    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.config.get('logging', {})

    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration"""
        return self.config.get('database', {})

    def export_config(self, format_type: str = 'json') -> str:
        """Export configuration in specified format"""
        if format_type == 'json':
            return json.dumps(self.config, indent=4, ensure_ascii=False)
        elif format_type == 'yaml':
            try:
                import yaml
                return yaml.dump(self.config, default_flow_style=False, allow_unicode=True)
            except ImportError:
                self.logger.error("PyYAML not installed, cannot export as YAML")
                return ""
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def import_config(self, config_data: Dict[str, Any]):
        """Import configuration from dictionary"""
        try:
            self._deep_update(self.config, config_data)
            self._validate_config()
            self.save_config()
            self.logger.info("Configuration imported successfully")
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            raise
