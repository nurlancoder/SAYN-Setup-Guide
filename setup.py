"""
SAYN Security Scanner Setup Script
Automated installation and configuration script
"""

import os
import sys
import subprocess
import json
import shutil
from pathlib import Path

def print_banner():
    """Print SAYN banner"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SAYN Security Scanner                     ║
    ║                        v2.1.0                               ║
    ║                                                              ║
    ║  Advanced Web Application Security Scanner                   ║
    ║  Comprehensive vulnerability detection and reporting         ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")

def check_dependencies():
    """Check if required system dependencies are available"""
    dependencies = ['git', 'curl']
    missing = []
    
    for dep in dependencies:
        if shutil.which(dep) is None:
            missing.append(dep)
    
    if missing:
        print(f"⚠️  Warning: Missing system dependencies: {', '.join(missing)}")
        print("   These are optional but recommended for full functionality")
    else:
        print("✅ System dependencies: Available")

def create_directories():
    """Create necessary directories"""
    directories = [
        'data',
        'logs', 
        'reports',
        'config',
        'temp'
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            '--upgrade', 'pip'
        ], check=True, capture_output=True)
        
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            '-r', 'requirements.txt'
        ], check=True)
        
        print("✅ Python dependencies installed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print("   Please check your internet connection and try again")
        sys.exit(1)

def create_default_config():
    """Create default configuration file"""
    config_file = Path('config/config.json')
    
    if config_file.exists():
        print("✅ Configuration file already exists")
        return
    
    default_config = {
        "database": {
            "path": "data/sayn.db",
            "backup_enabled": True,
            "backup_interval": 24
        },
        "scanning": {
            "default_threads": 10,
            "default_timeout": 30,
            "max_concurrent_scans": 5,
            "retry_attempts": 3,
            "retry_delay": 1
        },
        "modules": {
            "web_security": {
                "enabled": True,
                "xss_scanner": {"enabled": True},
                "sqli_scanner": {"enabled": True},
                "csrf_scanner": {"enabled": True},
                "headers_scanner": {"enabled": True},
                "file_inclusion_scanner": {"enabled": True}
            },
            "api_security": {
                "enabled": True,
                "rest_scanner": {"enabled": True},
                "graphql_scanner": {"enabled": True}
            },
            "network_security": {
                "enabled": True,
                "port_scanner": {"enabled": True},
                "ssl_scanner": {"enabled": True}
            }
        },
        "web_interface": {
            "host": "0.0.0.0",
            "port": 5000,
            "debug": False,
            "secret_key": "change-this-in-production"
        },
        "logging": {
            "level": "INFO",
            "file": "logs/sayn.log",
            "max_size": "10MB",
            "backup_count": 5
        },
        "reporting": {
            "formats": ["html", "json", "pdf"],
            "output_dir": "reports",
            "include_evidence": True,
            "include_recommendations": True
        },
        "security": {
            "user_agent": "SAYN-Scanner/2.1.0",
            "rate_limiting": True,
            "max_requests_per_minute": 100
        }
    }
    
    config_file.parent.mkdir(exist_ok=True)
    
    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    print("✅ Default configuration created")

def run_tests():
    """Run basic tests to verify installation"""
    print("\n🧪 Running basic tests...")
    
    try:
        import core.config
        import core.database
        import core.scanner
        import core.utils
        print("✅ Core modules: Import successful")
        
        import web_interface.app
        print("✅ Web interface: Import successful")
        
        import modules.web_security
        import modules.api_security
        import modules.network_security
        print("✅ Security modules: Import successful")
        
        print("✅ All tests passed")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Please check your installation and try again")
        sys.exit(1)

def create_startup_scripts():
    """Create startup scripts for different platforms"""
    scripts = {
        'start_web.sh': '''#!/bin/bash
# SAYN Security Scanner - Web Interface Startup Script
echo "Starting SAYN Security Scanner Web Interface..."
python3 sayn.py --web --host 0.0.0.0 --port 5000
''',
        'start_cli.sh': '''#!/bin/bash
# SAYN Security Scanner - CLI Startup Script
echo "SAYN Security Scanner CLI"
python3 sayn.py --help
''',
        'start_web.bat': '''@echo off
REM SAYN Security Scanner - Web Interface Startup Script (Windows)
echo Starting SAYN Security Scanner Web Interface...
python sayn.py --web --host 0.0.0.0 --port 5000
pause
''',
        'start_cli.bat': '''@echo off
REM SAYN Security Scanner - CLI Startup Script (Windows)
echo SAYN Security Scanner CLI
python sayn.py --help
pause
'''
    }
    
    for filename, content in scripts.items():
        with open(filename, 'w') as f:
            f.write(content)
        
        if filename.endswith('.sh'):
            os.chmod(filename, 0o755)
        
        print(f"✅ Created startup script: {filename}")

def print_next_steps():
    """Print next steps for the user"""
    print("""
    🎉 Installation completed successfully!
    
    Next steps:
    
    1. Start the web interface:
       ./start_web.sh (Linux/Mac)
       start_web.bat (Windows)
       
    2. Or use the CLI:
       ./start_cli.sh (Linux/Mac)
       start_cli.bat (Windows)
       
    3. Access the web interface:
       http://localhost:5000
       
    4. View documentation:
       docs/API_REFERENCE.md
       README.md
       
    5. Run tests:
       python -m pytest tests/
       
    Configuration:
    - Edit config/config.json to customize settings
    - Logs are stored in logs/
    - Reports are generated in reports/
    
    For support:
    - GitHub: https://github.com/sayn-scanner
    - Documentation: docs/
    """)

def main():
    """Main setup function"""
    print_banner()
    
    print("🔍 Checking system requirements...")
    check_python_version()
    check_dependencies()
    
    print("\n📁 Creating directories...")
    create_directories()
    
    print("\n📦 Installing dependencies...")
    install_python_dependencies()
    
    print("\n⚙️  Creating configuration...")
    create_default_config()
    
    print("\n🧪 Running tests...")
    run_tests()
    
    print("\n📝 Creating startup scripts...")
    create_startup_scripts()
    
    print_next_steps()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
