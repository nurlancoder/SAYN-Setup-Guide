# 🔍 SAYN Fayllarını Tapmaq - Kali Linux Guide

## 🚨 Problem

`sayn.py` faylı tapılmır. Gəlin düzgün qovluğu tapaq.

## 📁 Faylları Tapmaq

### 1. Mövcud Qovluqları Yoxlayın

```bash
# Desktop-da nə var yoxlayın
ls -la /home/kali/Desktop/

# SAYN qovluğunu tapın
find /home/kali -name "sayn.py" 2>/dev/null

# Və ya
find /home/kali -name "*.py" | grep -i sayn
```

### 2. SAYN-Setup-Guide Qovluğunu Tapın

```bash
# SAYN-Setup-Guide qovluğunu tapın
find /home/kali -name "*SAYN*" -type d 2>/dev/null

# Və ya
ls -la /home/kali/Desktop/ | grep -i sayn
```

### 3. Düzgün Qovluğa Keçin

```bash
# Əgər SAYN-Setup-Guide qovluğu varsa
cd /home/kali/Desktop/SAYN-Setup-Guide

# Və ya SAYN2 qovluğu varsa
cd /home/kali/Desktop/SAYN2

# Faylları yoxlayın
ls -la
```

## 🚀 Web Interface Başlatmaq

### 1. Düzgün Qovluqda

```bash
# Düzgün qovluğa keçin
cd /home/kali/Desktop/SAYN-Setup-Guide

# Virtual environment aktivləşdirin
source sayn_env/bin/activate

# Web interface başladın
python sayn.py --web-interface
```

### 2. Əgər Fayl Yoxdursa

```bash
# SAYN fayllarını yenidən yaradın
mkdir -p /home/kali/Desktop/SAYN-Project
cd /home/kali/Desktop/SAYN-Project

# Virtual environment yaradın
python3 -m venv sayn_env
source sayn_env/bin/activate

# Dependencies quraşdırın
pip install flask flask-socketio aiohttp requests beautifulsoup4
```

## 📋 Fayl Strukturu

SAYN layihəsinin düzgün strukturu belə olmalıdır:

```
SAYN-Project/
├── sayn.py
├── requirements.txt
├── config/
│   └── config.json
├── core/
│   ├── __init__.py
│   ├── config.py
│   ├── database.py
│   ├── scanner.py
│   └── utils.py
├── modules/
│   ├── __init__.py
│   ├── web_security/
│   ├── network_security/
│   └── api_security/
├── web_interface/
│   ├── app.py
│   ├── templates/
│   └── static/
├── data/
├── logs/
└── reports/
```

## 🔧 Alternativ Həll

### 1. GitHub-dan Yenidən Endirin

```bash
# GitHub-dan endirin
cd /home/kali/Desktop
git clone https://github.com/your-username/SAYN-Security-Scanner.git
cd SAYN-Security-Scanner

# Virtual environment yaradın
python3 -m venv sayn_env
source sayn_env/bin/activate

# Dependencies quraşdırın
pip install -r requirements.txt

# Web interface başladın
python sayn.py --web-interface
```

### 2. Docker İstifadə Edin

```bash
# Docker quraşdırın
sudo apt install docker.io

# Docker image build edin
docker build -t sayn-scanner .

# Docker ilə işlədin
docker run -p 5000:5000 sayn-scanner
```

## 🎯 Test Komandaları

```bash
# Qovluqda nə var yoxlayın
pwd
ls -la

# Python fayllarını tapın
find . -name "*.py" | head -10

# SAYN faylını tapın
find . -name "sayn.py"

# Virtual environment yoxlayın
which python
echo $VIRTUAL_ENV
```

## 🎉 Nəticə

Düzgün qovluğu tapdıqdan sonra:

```bash
# Virtual environment aktivləşdirin
source sayn_env/bin/activate

# Web interface başladın
python sayn.py --web-interface
```

**Status:** 🔍 **Faylları Tapmaq Lazımdır**

