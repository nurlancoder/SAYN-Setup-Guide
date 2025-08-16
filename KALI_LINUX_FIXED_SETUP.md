# 🔧 Kali Linux - Fixed Setup Guide for SAYN Security Scanner

## 🚨 Problem Həlli

Kali Linux-da Python 3.13 ilə yaşanan dependency problemlərini həll etmək üçün bu təlimatları izləyin.

## 📋 Adım-adım Həll

### 1. Mövcud Environment-i Təmizləyin

```bash
# Virtual environment-i deaktivləşdirin
deactivate

# Köhnə environment-i silin
rm -rf sayn_env

# Requirements faylını yeniləyin
rm requirements.txt
```

### 2. Yeni Requirements Faylını Yaradın

```bash
# Fixed requirements faylını yaradın
cat > requirements.txt << 'EOF'
# SAYN Security Scanner - Fixed Requirements for Python 3.13
# Core dependencies
aiohttp>=3.9.0
flask>=2.3.3
flask-socketio>=5.3.6
python-socketio>=5.8.0
python-engineio>=4.7.1

# HTTP and networking
requests>=2.31.0
urllib3>=2.0.4
certifi>=2023.7.22

# Security and SSL
cryptography>=41.0.4
pyopenssl>=23.2.0

# HTML parsing
beautifulsoup4>=4.12.2
lxml>=4.9.3
html5lib>=1.1

# Additional utilities
jinja2>=3.1.2
werkzeug>=2.3.7
click>=8.1.7
itsdangerous>=2.1.2
markupsafe>=2.1.3

# Testing and development
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0

# Code quality
black>=23.0.0
flake8>=6.0.0

# CLI tools
rich>=13.0.0
typer>=0.9.0

# Report generation
weasyprint>=60.0

# Async utilities
asyncio-throttle>=1.0.2
EOF
```

### 3. Sistem Dependencies Quraşdırın

```bash
# Bütün lazımi sistem paketlərini quraşdırın
sudo apt update
sudo apt install -y \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    libpng-dev \
    libffi-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    libharfbuzz-dev \
    libfribidi-dev \
    libxcb1-dev \
    build-essential \
    python3-dev \
    python3-pip \
    python3-venv
```

### 4. Yeni Virtual Environment Yaradın

```bash
# Python 3.11 istifadə edin (daha stabil)
python3.11 -m venv sayn_env

# Environment aktivləşdirin
source sayn_env/bin/activate

# Python versiyasını yoxlayın
python --version
# Nəticə: Python 3.11.x olmalıdır
```

### 5. Python Dependencies Quraşdırın

```bash
# Pip-i yeniləyin
pip install --upgrade pip wheel setuptools

# Core dependencies-i ayrı-ayrı quraşdırın
pip install aiohttp>=3.9.0
pip install flask>=2.3.3
pip install flask-socketio>=5.3.6
pip install requests>=2.31.0
pip install cryptography>=41.0.4
pip install beautifulsoup4>=4.12.2
pip install lxml>=4.9.3

# Qalan dependencies-i quraşdırın
pip install -r requirements.txt
```

### 6. Alternativ Həll (Python 3.11)

Əgər Python 3.13 ilə problem yaşayırsınızsa, Python 3.11 istifadə edin:

```bash
# Python 3.11 quraşdırın
sudo apt install python3.11 python3.11-venv python3.11-dev

# Python 3.11 ilə virtual environment yaradın
python3.11 -m venv sayn_env_py311
source sayn_env_py311/bin/activate

# Dependencies quraşdırın
pip install --upgrade pip wheel
pip install -r requirements.txt
```

### 7. Test Edin

```bash
# Environment aktiv olduğunu yoxlayın
which python
# Nəticə: /home/kali/Desktop/SAYN-Setup-Guide/sayn_env/bin/python

# Python versiyasını yoxlayın
python --version

# Dependencies-i yoxlayın
pip list | grep -E "(aiohttp|flask|requests)"

# Test edin
python -c "import aiohttp; print('aiohttp OK')"
python -c "import flask; print('flask OK')"
python -c "import requests; print('requests OK')"
```

### 8. Konfiqurasiya

```bash
# Lazımi qovluqları yaradın
mkdir -p config data logs reports

# Config faylını yaradın
python -c "
from core.config import Config
config = Config('config/config.json')
config.save()
print('Config file created successfully!')
"
```

### 9. Sistem Testləri

```bash
# Health check
python sayn.py --health-check

# Database test
python -c "
from core.database import DatabaseManager
db = DatabaseManager('data/sayn.db')
db.create_tables()
print('Database initialized successfully!')
"

# Scanner test
python -c "
import asyncio
from core.scanner import ScannerEngine

async def test_scanner():
    scanner = ScannerEngine()
    result = await scanner.health_check('https://httpbin.org/get')
    print('Scanner test result:', result)

asyncio.run(test_scanner())
"
```

## 🔄 Alternativ Həll Yolları

### Həll 1: Docker İstifadə Edin

```bash
# Docker quraşdırın
sudo apt install docker.io docker-compose

# Docker image build edin
docker build -f docker/Dockerfile -t sayn-scanner .

# Docker ilə işlədin
docker run -p 5000:5000 sayn-scanner
```

### Həll 2: Conda İstifadə Edin

```bash
# Miniconda quraşdırın
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh

# Conda environment yaradın
conda create -n sayn python=3.11
conda activate sayn

# Dependencies quraşdırın
pip install -r requirements.txt
```

### Həll 3: System Python İstifadə Edin

```bash
# System Python 3.11 istifadə edin
sudo apt install python3.11 python3.11-pip

# Global quraşdırın
pip3.11 install -r requirements.txt

# İşlədin
python3.11 sayn.py --web
```

## 🧪 Test Script

```bash
# Test script yaradın
cat > test_setup.sh << 'EOF'
#!/bin/bash

echo "=== SAYN Security Scanner Setup Test ==="

# Environment check
echo "1. Environment check..."
if [ -n "$VIRTUAL_ENV" ]; then
    echo "✅ Virtual environment is active: $VIRTUAL_ENV"
else
    echo "❌ Virtual environment is not active"
    exit 1
fi

# Python version check
echo "2. Python version check..."
python --version
if [[ $(python --version 2>&1) == *"3.11"* ]]; then
    echo "✅ Python 3.11 detected"
else
    echo "⚠️  Python version may cause issues"
fi

# Dependencies check
echo "3. Dependencies check..."
python -c "import aiohttp; print('✅ aiohttp OK')" || echo "❌ aiohttp FAILED"
python -c "import flask; print('✅ flask OK')" || echo "❌ flask FAILED"
python -c "import requests; print('✅ requests OK')" || echo "❌ requests FAILED"
python -c "import sqlite3; print('✅ sqlite3 OK')" || echo "❌ sqlite3 FAILED"

# Database test
echo "4. Database test..."
python -c "
from core.database import DatabaseManager
db = DatabaseManager('test.db')
db.create_tables()
print('✅ Database OK')
" || echo "❌ Database FAILED"

# Scanner test
echo "5. Scanner test..."
python -c "
import asyncio
from core.scanner import ScannerEngine

async def test():
    scanner = ScannerEngine()
    result = await scanner.health_check('https://httpbin.org/get')
    print('✅ Scanner OK')

asyncio.run(test())
" || echo "❌ Scanner FAILED"

echo "=== Test completed ==="
EOF

chmod +x test_setup.sh
./test_setup.sh
```

## ✅ Uğurlu Quraşdırma Nəticələri

Uğurlu quraşdırmadan sonra bu nəticələri görməlisiniz:

```
=== SAYN Security Scanner Setup Test ===
1. Environment check...
✅ Virtual environment is active: /home/kali/Desktop/SAYN-Setup-Guide/sayn_env
2. Python version check...
Python 3.11.x
✅ Python 3.11 detected
3. Dependencies check...
✅ aiohttp OK
✅ flask OK
✅ requests OK
✅ sqlite3 OK
4. Database test...
✅ Database OK
5. Scanner test...
✅ Scanner OK
=== Test completed ===
```

## 🚀 Web Interface Başlatmaq

```bash
# Web interface başladın
python sayn.py --web --host 0.0.0.0 --port 5000

# Background-da işlətmək üçün
nohup python sayn.py --web --host 0.0.0.0 --port 5000 > logs/web.log 2>&1 &

# Browser-da yoxlayın
firefox http://localhost:5000
```

## 📝 Qeydlər

- **Python 3.13** ilə aiohttp 3.8.5 uyğun deyil, 3.9.0+ istifadə edin
- **sqlite3** built-in modul olduğu üçün requirements.txt-də olmamalıdır
- **Python 3.11** daha stabil və uyğunluq problemi yoxdur
- **Docker** ən asan həll yoludur

---

**Status:** ✅ **Problem Həll Edildi**  
**Test:** ✅ **Uğurlu**  
**Ready for:** Production Use
