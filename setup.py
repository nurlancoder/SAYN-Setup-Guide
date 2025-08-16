#!/usr/bin/env python3
"""
SAYN Security Scanner Setup Script
Automated installation and configuration script
"""

import os
import sys
import subprocess
import json
import shutil
import platform
from pathlib import Path

def print_banner():
    """Print SAYN banner"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                    SAYN Security Scanner                     ║
    ║                        v2.1.0                                ║
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
        print("   Please upgrade Python and try again")
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
        print("   You can install them manually or continue without them")
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
        try:
            Path(directory).mkdir(exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except PermissionError:
            print(f"❌ Permission denied creating directory: {directory}")
            print("   Please run with appropriate permissions")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error creating directory {directory}: {e}")
            sys.exit(1)

def install_python_dependencies():
    """Install Python dependencies"""
    print("\n📦 Installing Python dependencies...")
    
    try:
        # Upgrade pip first
        print("   Upgrading pip...")
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            '--upgrade', 'pip'
        ], check=True, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("⚠️  Warning: Failed to upgrade pip, continuing...")
        
        # Install requirements
        print("   Installing requirements...")
        if not Path('requirements.txt').exists():
            print("❌ Error: requirements.txt not found")
            print("   Please ensure you're running setup.py from the project root")
            sys.exit(1)
            
        result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', 
            '-r', 'requirements.txt'
        ], check=True, capture_output=True, text=True)
        
        print("✅ Python dependencies installed successfully")
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing dependencies: {e}")
        print(f"   stdout: {e.stdout}")
        print(f"   stderr: {e.stderr}")
        print("   Please check your internet connection and try again")
        sys.exit(1)
    except FileNotFoundError:
        print("❌ Error: pip not found")
        print("   Please ensure Python and pip are properly installed")
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
    
    try:
        config_file.parent.mkdir(exist_ok=True)
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        
        print("✅ Default configuration created")
    except Exception as e:
        print(f"❌ Error creating configuration: {e}")
        sys.exit(1)

def run_tests():
    """Run basic tests to verify installation"""
    print("\n🧪 Running basic tests...")
    
    try:
        # Test core imports
        import core.config
        import core.database
        import core.scanner
        import core.utils
        print("✅ Core modules: Import successful")
        
        # Test web interface
        import web_interface.app
        print("✅ Web interface: Import successful")
        
        # Test security modules
        import modules.web_security
        import modules.api_security
        import modules.network_security
        print("✅ Security modules: Import successful")
        
        print("✅ All tests passed")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Please check your installation and try again")
        print("   Make sure all dependencies are installed correctly")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test error: {e}")
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
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Make shell scripts executable on Unix-like systems only
            if filename.endswith('.sh') and platform.system() != 'Windows':
                try:
                    os.chmod(filename, 0o755)
                except OSError:
                    print(f"⚠️  Warning: Could not make {filename} executable")
            
            print(f"✅ Created startup script: {filename}")
        except Exception as e:
            print(f"❌ Error creating {filename}: {e}")

def print_next_steps():
    """Print next steps for the user"""
    system = platform.system()
    
    print("""
    🎉 Installation completed successfully!
    
    Next steps:
    """)
    
    if system == 'Windows':
        print("""
    1. Start the web interface:
       start_web.bat
       
    2. Or use the CLI:
       start_cli.bat
        """)
    else:
        print("""
    1. Start the web interface:
       ./start_web.sh
       
    2. Or use the CLI:
       ./start_cli.sh
        """)
    
    print("""
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
        print("   Please check the error details above and try again")
        sys.exit(1)
