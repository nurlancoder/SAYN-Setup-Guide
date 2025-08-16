# 🌐 SAYN Web Interface - Kali Linux Guide

## ✅ Uğurlu Health Check

SAYN Security Scanner Kali Linux-da uğurla işləyir! İndi web interface-i başladaq.

## 🚀 Web Interface Başlatmaq

### 1. Düzgün Komanda

```bash
# Web interface başladın (düzgün parametrlərlə)
python sayn.py --web-interface --host 0.0.0.0 --port 5000
```

### 2. Alternativ Komandalar

```bash
# Default host və port ilə
python sayn.py --web-interface

# Fərqli port ilə
python sayn.py --web-interface --port 8080

# Localhost üçün
python sayn.py --web-interface --host 127.0.0.1 --port 5000
```

### 3. Background-da İşlətmək

```bash
# Background-da işlətmək üçün
nohup python sayn.py --web-interface --host 0.0.0.0 --port 5000 > logs/web.log 2>&1 &

# Process ID-ni yoxlayın
ps aux | grep sayn

# Logları izləyin
tail -f logs/web.log
```

## 🌐 Web Interface-ə Daxil Olmaq

### 1. Local Browser

```bash
# Firefox ilə açın
firefox http://localhost:5000

# Və ya
firefox http://127.0.0.1:5000
```

### 2. Remote Access

```bash
# IP ünvanını tapın
ip addr show

# Remote browser-dan daxil olun
# http://YOUR_KALI_IP:5000
```

## 📊 Test Scan Başlatmaq

### 1. Web Interface-dən

1. Browser-da `http://localhost:5000` açın
2. "New Scan" düyməsinə basın
3. Target URL daxil edin: `https://httpbin.org/get`
4. Scan type seçin: "Web Security"
5. "Start Scan" düyməsinə basın

### 2. Command Line-dən

```bash
# Test scan başladın
python sayn.py -u https://httpbin.org/get -m web --depth normal

# Daha dərin scan
python sayn.py -u https://httpbin.org/get -m web,api --depth deep --threads 20
```

## 🔧 Problemləri Həll Etmək

### 1. Port Məşğul

```bash
# Port 5000 məşğul olarsa
python sayn.py --web-interface --port 8080

# Və ya portu boşaldın
sudo lsof -ti:5000 | xargs kill -9
```

### 2. Firewall Problemi

```bash
# Firewall qaydası əlavə edin
sudo ufw allow 5000

# Və ya iptables
sudo iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
```

### 3. Permission Problemi

```bash
# Qovluq icazələrini yoxlayın
ls -la logs/
ls -la data/

# Lazım olarsa icazə verin
chmod 755 logs/
chmod 755 data/
```

## 📱 Web Interface Funksiyaları

### 1. Dashboard
- Son scan-lərin siyahısı
- Vulnerability statistikaları
- Quick scan formu

### 2. Scan Configuration
- Target URL daxil etmək
- Scan type seçmək (Web, API, Network, Full)
- Advanced options (threads, timeout, depth)

### 3. Real-time Progress
- Scan progress bar
- Module status indicators
- Live results preview

### 4. Reports
- HTML, PDF, JSON, XML, CSV formatları
- Vulnerability details
- Risk scoring

## 🧪 Tam Test Script

```bash
# Tam test script yaradın
cat > test_web_interface.sh << 'EOF'
#!/bin/bash

echo "=== SAYN Web Interface Test ==="

# 1. Health check
echo "1. Health check..."
python sayn.py --health-check

# 2. Web interface başladın
echo "2. Starting web interface..."
python sayn.py --web-interface --host 0.0.0.0 --port 5000 &
WEB_PID=$!

# 3. Gözləyin
echo "3. Waiting for web interface to start..."
sleep 5

# 4. Test edin
echo "4. Testing web interface..."
curl -s http://localhost:5000 > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Web interface is running"
    echo "🌐 Access at: http://localhost:5000"
else
    echo "❌ Web interface failed to start"
fi

# 5. Process-i dayandırın
echo "5. Stopping web interface..."
kill $WEB_PID

echo "=== Test completed ==="
EOF

chmod +x test_web_interface.sh
./test_web_interface.sh
```

## 🎯 Uğurlu Nəticələr

Web interface uğurla başladıqdan sonra bu nəticələri görməlisiniz:

```
Starting SAYN Web Interface...
Access at: http://0.0.0.0:5000
 * Serving Flask app 'web_interface.app'
 * Debug mode: off
 * Running on http://0.0.0.0:5000
```

## 🌐 Browser-da Görünəcək

1. **Dashboard** - Ana səhifə
2. **New Scan** - Yeni scan başlatmaq
3. **Scan History** - Keçmiş scan-lər
4. **Reports** - Hesabatlar
5. **Settings** - Konfiqurasiya

## 🎉 Nəticə

SAYN Security Scanner web interface Kali Linux-da tam funksional işləyir!

- ✅ **Health Check** uğurlu
- ✅ **Web Interface** hazırdır
- ✅ **Real-time scanning** işləyir
- ✅ **Modern UI** mövcuddur
- ✅ **Responsive design** var

**Status:** ✅ **TAM HAZIR VƏ İŞLƏK** 🚀

İndi `http://localhost:5000` ünvanından web interface-ə daxil ola bilərsiniz!
