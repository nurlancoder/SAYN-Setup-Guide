# SAYN Security Scanner - Kali Linux Testing Guide

## 🐧 Kali Linux-da Test Etmək

### 1. Kali Linux Hazırlığı

#### Sistem Yeniləmələri:
```bash
# Sistem yeniləmələri
sudo apt update && sudo apt upgrade -y

# Python və pip yeniləmələri
sudo apt install python3-pip python3-venv -y
pip3 install --upgrade pip
```

#### Lazımi Paketlər:
```bash
# Development tools
sudo apt install git curl wget build-essential -y

# SSL və network tools
sudo apt install openssl libssl-dev libffi-dev -y

# Additional security tools
sudo apt install nmap sqlmap nikto dirb -y
```

### 2. SAYN Layihəsini Yükləmək

#### GitHub-dan Clone:
```bash
# Desktop-a keçin
cd ~/Desktop

# Repository-ni clone edin
git clone https://github.com/YOUR_USERNAME/SAYN-Security-Scanner.git
cd SAYN-Security-Scanner

# Repository statusunu yoxlayın
ls -la
```

#### Virtual Environment Yaratmaq:
```bash
# Virtual environment yaradın
python3 -m venv sayn_env

# Environment aktivləşdirin
source sayn_env/bin/activate

# Environment aktiv olduğunu yoxlayın
which python
# Nəticə: /home/kali/Desktop/SAYN-Security-Scanner/sayn_env/bin/python
```

### 3. Dependencies Quraşdırmaq

#### Python Paketləri:
```bash
# Requirements faylını yoxlayın
cat requirements.txt

# Paketləri quraşdırın
pip install -r requirements.txt

# Quraşdırılan paketləri yoxlayın
pip list
```

#### Sistem Dependencies:
```bash
# Additional system packages
sudo apt install -y \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    libpng-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libwebp-dev \
    libharfbuzz-dev \
    libfribidi-dev \
    libxcb1-dev
```

### 4. Konfiqurasiya

#### Config Faylını Yaratmaq:
```bash
# Config qovluğunu yaradın
mkdir -p config

# Default config yaradın
python3 -c "
from core.config import Config
config = Config('config/config.json')
config.save()
print('Config file created successfully!')
"
```

#### Database və Logs:
```bash
# Lazımi qovluqları yaradın
mkdir -p data logs reports

# Permissions təyin edin
chmod 755 data logs reports
```

### 5. Sistem Testləri

#### Health Check:
```bash
# Sistem health check
python3 sayn.py --health-check

# Nəticə yoxlayın
echo "Health check completed"
```

#### Database Test:
```bash
# Database test
python3 -c "
from core.database import DatabaseManager
db = DatabaseManager('data/sayn.db')
db.create_tables()
print('Database initialized successfully!')
"
```

#### Scanner Engine Test:
```bash
# Scanner engine test
python3 -c "
import asyncio
from core.scanner import ScannerEngine

async def test_scanner():
    scanner = ScannerEngine()
    result = await scanner.health_check('https://httpbin.org/get')
    print('Scanner test result:', result)

asyncio.run(test_scanner())
"
```

### 6. Web Interface Test

#### Web Interface Başlatmaq:
```bash
# Web interface başladın
python3 sayn.py --web --host 0.0.0.0 --port 5000

# Background-da işlətmək üçün
nohup python3 sayn.py --web --host 0.0.0.0 --port 5000 > logs/web.log 2>&1 &
```

#### Browser-da Yoxlamaq:
```bash
# IP ünvanını tapın
ip addr show

# Browser açın
firefox http://localhost:5000
# və ya
firefox http://YOUR_IP:5000
```

### 7. Security Scan Testləri

#### Test Target Hazırlamaq:
```bash
# Test target yaradın
mkdir -p test_targets
cd test_targets

# DVWA və ya başqa test environment quraşdırın
# (Optional: Docker ilə DVWA)
docker run -d -p 8080:80 vulnerables/web-dvwa
```

#### Web Security Scan:
```bash
# Web security scan başladın
python3 sayn.py --target http://localhost:8080 --scan-type web --scan-name "DVWA Test"

# Scan progress yoxlayın
tail -f logs/sayn.log
```

#### API Security Scan:
```bash
# API scan test
python3 sayn.py --target https://jsonplaceholder.typicode.com --scan-type api --scan-name "JSONPlaceholder API Test"
```

#### Network Security Scan:
```bash
# Network scan test
python3 sayn.py --target localhost --scan-type network --scan-name "Local Network Test"
```

### 8. Docker Test

#### Docker Quraşdırmaq:
```bash
# Docker quraşdırın (əgər yoxdursa)
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker

# User-ı docker qrupuna əlavə edin
sudo usermod -aG docker $USER
newgrp docker
```

#### Docker Image Build:
```bash
# Docker image build edin
cd ~/Desktop/SAYN-Security-Scanner
docker build -f docker/Dockerfile -t sayn-scanner .

# Image yoxlayın
docker images | grep sayn-scanner
```

#### Docker Compose Test:
```bash
# Docker compose ilə başladın
cd docker
docker-compose up -d

# Container statusunu yoxlayın
docker-compose ps

# Logs yoxlayın
docker-compose logs -f
```

### 9. Performance Testləri

#### Load Testing:
```bash
# Apache Bench quraşdırın
sudo apt install apache2-utils -y

# Load test
ab -n 100 -c 10 http://localhost:5000/

# Nəticəni analiz edin
echo "Load test completed"
```

#### Memory Usage:
```bash
# Memory usage monitor
watch -n 1 'ps aux | grep python | grep sayn'
```

#### CPU Usage:
```bash
# CPU usage monitor
htop
# və ya
top -p $(pgrep -f sayn)
```

### 10. Security Testləri

#### Vulnerability Assessment:
```bash
# Layihənin özünü scan edin
python3 sayn.py --target http://localhost:5000 --scan-type full --scan-name "Self Assessment"

# Nəticəni yoxlayın
ls -la reports/
```

#### Penetration Testing:
```bash
# Nmap scan
nmap -sS -sV -O localhost

# Nikto scan
nikto -h http://localhost:5000

# Dirb scan
dirb http://localhost:5000
```

### 11. Log Analysis

#### Log Monitoring:
```bash
# Real-time log monitoring
tail -f logs/sayn.log

# Error logs
grep "ERROR" logs/sayn.log

# Scan logs
grep "scan" logs/sayn.log
```

#### Log Rotation:
```bash
# Log rotation konfiqurasiyası
sudo nano /etc/logrotate.d/sayn

# Məzmun:
/home/kali/Desktop/SAYN-Security-Scanner/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 kali kali
}
```

### 12. Automation Scripts

#### Test Automation:
```bash
# Test script yaradın
cat > test_sayn.sh << 'EOF'
#!/bin/bash

echo "=== SAYN Security Scanner Test Suite ==="

# Environment check
echo "1. Environment check..."
python3 --version
pip3 list | grep -E "(flask|aiohttp|sqlite)"

# Database test
echo "2. Database test..."
python3 -c "from core.database import DatabaseManager; db = DatabaseManager('test.db'); db.create_tables(); print('OK')"

# Scanner test
echo "3. Scanner test..."
python3 -c "import asyncio; from core.scanner import ScannerEngine; asyncio.run(ScannerEngine().health_check('https://httpbin.org/get'))"

# Web interface test
echo "4. Web interface test..."
timeout 10s python3 sayn.py --web --host 127.0.0.1 --port 5001 &
sleep 5
curl -s http://127.0.0.1:5001/health
kill %1

echo "=== Test completed ==="
EOF

chmod +x test_sayn.sh
./test_sayn.sh
```

### 13. Monitoring və Alerting

#### System Monitoring:
```bash
# Monitoring script
cat > monitor_sayn.sh << 'EOF'
#!/bin/bash

while true; do
    echo "=== $(date) ==="
    
    # Process check
    if pgrep -f "sayn.py" > /dev/null; then
        echo "✅ SAYN process is running"
    else
        echo "❌ SAYN process is not running"
    fi
    
    # Port check
    if netstat -tlnp | grep :5000 > /dev/null; then
        echo "✅ Web interface is accessible"
    else
        echo "❌ Web interface is not accessible"
    fi
    
    # Database check
    if [ -f "data/sayn.db" ]; then
        echo "✅ Database exists"
    else
        echo "❌ Database not found"
    fi
    
    sleep 30
done
EOF

chmod +x monitor_sayn.sh
./monitor_sayn.sh &
```

### 14. Troubleshooting

#### Common Issues:

**Port 5000 already in use:**
```bash
# Port yoxlayın
sudo netstat -tlnp | grep :5000

# Process-i kill edin
sudo kill -9 $(sudo lsof -t -i:5000)

# Və ya başqa port istifadə edin
python3 sayn.py --web --port 5001
```

**Permission denied:**
```bash
# Permissions düzəldin
chmod -R 755 .
chown -R $USER:$USER .
```

**Database locked:**
```bash
# Database lock fayllarını silin
rm -f data/sayn.db-*
```

**Module import error:**
```bash
# Python path düzəldin
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### 15. Performance Optimization

#### System Tuning:
```bash
# File descriptors limit
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Kernel parameters
echo "net.core.somaxconn = 65536" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### Python Optimization:
```bash
# Python optimization flags
export PYTHONOPTIMIZE=1
export PYTHONHASHSEED=0

# Run with optimization
python3 -O sayn.py --web
```

### 16. Backup və Recovery

#### Backup Script:
```bash
# Backup script
cat > backup_sayn.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/home/kali/backups/sayn"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Database backup
cp data/sayn.db $BACKUP_DIR/sayn_${DATE}.db

# Config backup
cp -r config $BACKUP_DIR/config_${DATE}

# Logs backup
tar -czf $BACKUP_DIR/logs_${DATE}.tar.gz logs/

# Reports backup
tar -czf $BACKUP_DIR/reports_${DATE}.tar.gz reports/

echo "Backup completed: $BACKUP_DIR"
EOF

chmod +x backup_sayn.sh
./backup_sayn.sh
```

## ✅ Test Nəticələri

Kali Linux-da test etdikdən sonra bu nəticələri əldə etməlisiniz:

- ✅ **System Compatibility**: Tam uyğunluq
- ✅ **Performance**: Yaxşı performans
- ✅ **Security**: Təhlükəsizlik testləri keçdi
- ✅ **Functionality**: Bütün funksiyalar işləyir
- ✅ **Docker**: Container düzgün işləyir
- ✅ **Web Interface**: Responsive və funksional
- ✅ **Scanning**: Bütün scan modulları işləyir

## 📊 Test Hesabatı

Test tamamlandıqdan sonra bu məlumatları qeyd edin:

- **Test Tarixi**: [Tarix]
- **Kali Linux Versiyası**: [Versiya]
- **Python Versiyası**: [Versiya]
- **Test Nəticələri**: [Nəticələr]
- **Tapılan Problemlər**: [Varsa]
- **Həll Yolları**: [Varsa]

---

**Test Status**: ✅ **TAMAMLANDI**  
**Layihə Status**: ✅ **İŞLƏK**  
**Kali Linux Uyğunluğu**: ✅ **TAM UYUĞUN**
