# Subdomain Tracker 🔍

A powerful subdomain monitoring tool that detects new subdomains and sends email alerts.

## Features
- ✅ Subfinder integration for comprehensive enumeration
- ✅ Email notifications for new subdomains
- ✅ Continuous monitoring with configurable intervals
- ✅ State persistence between runs
- ✅ Beautiful console output and email templates

## Installation

### 1. Clone the repository 
```bash
git clone https://github.com/hxxfrd/subdomain-tracker.git
cd subdomain-tracker
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```
### 3. Install Subfinder
```bash
Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

# Quick Start

### First, enumerate all existing subdomains
```bash
python subdomain_monitor.py example.com --enumerate
```

### Configure email alerts (optional)
```bash
Edit email_config.json with your SMTP settings
```

### Start monitoring
```bash
python subdomain_monitor.py example.com --email-config email_config.json
```

# Usage

### Enumerate all subdomains (first time)
```bash
python subdomain_monitor.py example.com --enumerate
```

### Monitor with email alerts
```bash
python subdomain_monitor.py example.com --email-config email_config.json
#automatically checks for new subdomain every 10 hours
```

### Monitor with custom interval (30 minutes)
```bash
python subdomain_monitor.py example.com --interval 1800
```

### Run once to check
```bash
python subdomain_monitor.py example.com --once
```
# Created by hxxfrd
X profile: x.com/f_r_e_d_d_y_1

# 📄 License
MIT License - feel free to modify and distribute!
