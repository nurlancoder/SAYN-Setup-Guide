# 🔐 SAYN Security Scanner v2.1.0

SAYN is an advanced security scanner designed for developers and security professionals to identify vulnerabilities in web applications, APIs, and network infrastructure.

## ✨ Features

### 🔍 Comprehensive Web Security Scanning
- **XSS Detection**: Cross-Site Scripting vulnerability detection
- **SQL Injection**: SQL injection vulnerability testing
- **CSRF Protection**: Cross-Site Request Forgery detection
- **Security Headers**: Analysis of security headers
- **File Inclusion**: Local and remote file inclusion testing
- **Authentication Testing**: Login form and session testing

### 🌐 Network Security Scanning
- **Port Scanning**: Comprehensive port discovery
- **SSL/TLS Analysis**: Certificate and configuration analysis
- **Service Detection**: Identification of running services
- **Vulnerability Assessment**: Known vulnerability checking

### 🔌 API Security Testing
- **REST API Security**: Endpoint security analysis
- **GraphQL Security**: GraphQL-specific vulnerability testing
- **Authentication Testing**: API authentication mechanisms
- **Rate Limiting**: Rate limiting vulnerability detection

### 🖥️ Modern Web Interface
- **Real-time Dashboard**: Live scanning progress and results
- **Interactive Reports**: Detailed vulnerability reports
- **Responsive Design**: Mobile-friendly interface
- **WebSocket Support**: Real-time updates

### 📊 Advanced Reporting
- **Multiple Formats**: HTML, PDF, JSON, XML, CSV
- **Detailed Analysis**: Comprehensive vulnerability details
- **Risk Scoring**: Automated risk assessment
- **Recommendations**: Actionable security advice

## 🛠️ Installation

### Prerequisites
- Python 3.9 or higher
- pip package manager

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/nurlancoder/sayn.git
cd sayn

# Install dependencies
pip install -r requirements.txt

# Run the web interface
python -m web_interface.app
```

### Docker Installation

```bash
# Build and run with Docker
docker build -t sayn-security .
docker run -p 5000:5000 sayn-security
```

## 🚀 Quick Start

### Web Interface
```bash
# Start the web interface
python -m web_interface.app

# Access at http://localhost:5000
```

### Command Line Usage
```bash
# Basic scan
python -m sayn -u https://example.com

# Comprehensive scan
python -m sayn -u https://example.com -m all --depth deep

# API scan only
python -m sayn -u https://api.example.com -m api

# Network scan
python -m sayn -u 192.168.1.1 -m network
```

## 📋 Usage Examples

### Web Security Scan
```python
from sayn import SAYN

# Initialize scanner
scanner = SAYN()

# Run web security scan
results = await scanner.scan_target(
    target="https://example.com",
    modules=["web"],
    options={
        "threads": 10,
        "timeout": 30,
        "scan_depth": "normal"
    }
)

# Generate report
report_path = scanner.generate_report(results, format="html")
```

### API Security Scan
```python
# API security scan
api_results = await scanner.scan_target(
    target="https://api.example.com",
    modules=["api"],
    options={
        "test_methods": ["GET", "POST", "PUT", "DELETE"],
        "auth_endpoints": ["/login", "/auth"]
    }
)
```

## 🏗️ Architecture

```
SAYN/
├── core/                 # Core scanning engine
│   ├── scanner.py       # Main scanner engine
│   ├── database.py      # Database management
│   ├── config.py        # Configuration management
│   └── utils.py         # Utilities and logging
├── modules/             # Security modules
│   ├── web_security/    # Web security scanners
│   ├── network_security/ # Network scanners
│   └── api_security/    # API security scanners
├── web_interface/       # Web UI
│   ├── app.py          # Flask application
│   ├── templates/      # HTML templates
│   └── static/         # CSS/JS assets
└── tests/              # Test suite
```

## 🔧 Configuration

### Configuration File
Create `config.json` in the project root:

```json
{
  "scanning": {
    "max_threads": 20,
    "timeout": 30,
    "retry_attempts": 3
  },
  "web_interface": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false
  },
  "modules": {
    "web_security": {
      "enabled": true,
      "aggressive_mode": false
    }
  }
}
```

### Environment Variables
```bash
export SAYN_CONFIG_PATH=/path/to/config.json
export SAYN_LOG_LEVEL=INFO
export SAYN_DATABASE_PATH=/path/to/database.db
```

## 📊 Report Formats

### HTML Report
- Modern, responsive design
- Interactive vulnerability details
- Risk scoring visualization
- Print-friendly layout

### PDF Report
- Professional formatting
- Executive summary
- Detailed technical findings
- Actionable recommendations

### JSON/XML Reports
- Machine-readable format
- API integration ready
- Structured data export

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=sayn

# Run specific module tests
pytest tests/test_web_security.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
flake8 sayn/

# Format code
black sayn/

# Run tests
pytest
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for security testing purposes only. Use only on systems you own or have permission to test. The author is not responsible for any misuse or damage caused by this tool.

## 👨‍💻 Author

**Məmmədli Nurlan**
- 📧 Email: nurlanmammadli2@gmail.com
- 🔗 GitHub: [nurlancoder](https://github.com/nurlancoder)
- 🔗 LinkedIn: [nurlan-mammadli](https://linkedin.com/in/nurlan-mammadli)

## 🙏 Acknowledgments

- Security research community
- Open source security tools
- Contributors and testers

## 📈 Roadmap

- [ ] Machine learning-based vulnerability detection
- [ ] Cloud security scanning
- [ ] Mobile application security
- [ ] Integration with CI/CD pipelines
- [ ] Advanced reporting dashboard
- [ ] Multi-language support

---

**Made with ❤️ for the security community**
