#!/usr/bin/env python3
"""
Subdomain Monitoring Script with Subfinder Integration
"""

import requests
import dns.resolver
import time
import json
import argparse
import sys
import smtplib
import ssl
from datetime import datetime
import os
import logging
import signal
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Print banner at startup - FIXED ESCAPE SEQUENCES
print(r"""
\033[1;34m
  .__                      _____           .___
|  |__ ___  ______  ____/ ____\______  __| _/
|  |  \\  \/  /\  \/  /\   __\\_  __ \/ __ | 
|   Y  \>    <  >    <  |  |   |  | \/ /_/ | 
|___|  /__/\_ \/__/\_ \ |__|   |__|  \____ | 
     \/      \/      \/                   \/ 
         Subdomain Tracker - By: hxxfrd
         ===============================
         Follow: github: https://github.com/hxxfrd
                Twitter: f_r_e_d_d_y_1
         ===============================\033[0m
""")


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('subdomain_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SubdomainMonitor:
    def __init__(self, domain, check_interval=36000, state_file='subdomain_state.json', 
                 email_config=None):
        self.domain = domain
        self.check_interval = check_interval
        self.state_file = state_file
        self.email_config = email_config or {}
        self.known_subdomains = self.load_state()
        self.running = False
        
    def load_state(self):
        """Load previously known subdomains from state file"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return set(json.load(f))
            except (json.JSONDecodeError, FileNotFoundError):
                return set()
        return set()
    
    def save_state(self):
        """Save current known subdomains to state file"""
        with open(self.state_file, 'w') as f:
            json.dump(list(self.known_subdomains), f)
    
    def run_subfinder_enumeration(self):
        """Run subfinder to discover ALL existing subdomains and save them"""
        try:
            logging.info(f"🚀 Running Subfinder comprehensive enumeration for {self.domain}...")
            
            result = subprocess.run(
                ['subfinder', '-d', self.domain, '-silent'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                subdomains = set()
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and self.domain in line:
                        subdomains.add(line)
                
                logging.info(f"✅ Subfinder found {len(subdomains)} subdomains")
                
                # Save all discovered subdomains to state file
                with open(self.state_file, 'w') as f:
                    json.dump(list(subdomains), f)
                
                logging.info(f"💾 Saved {len(subdomains)} subdomains to {self.state_file}")
                return subdomains
            else:
                logging.error(f"❌ Subfinder failed: {result.stderr}")
                return set()
                
        except subprocess.TimeoutExpired:
            logging.error("❌ Subfinder timed out after 5 minutes")
            return set()
        except FileNotFoundError:
            logging.error("❌ Subfinder not found. Please install it: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'")
            return set()
        except Exception as e:
            logging.error(f"❌ Subfinder error: {e}")
            return set()
    
    def discover_subdomains(self):
        """Discover subdomains using multiple methods"""
        subdomains = set()
        
        # Method 1: DNS brute force (common subdomains)
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'web', 'blog', 'dev', 'test', 'staging', 'api', 'cdn', 'static', 'img',
            'admin', 'login', 'secure', 'dashboard', 'portal', 'shop', 'store',
            'email', 'news', 'support', 'forum', 'wiki', 'download', 'cdn', 'status'
        ]
        
        for sub in common_subdomains:
            if not self.running:
                break
                
            full_domain = f"{sub}.{self.domain}"
            try:
                dns.resolver.resolve(full_domain, 'A')
                subdomains.add(full_domain)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
        
        # Method 2: Certificate Transparency logs
        if self.running:
            try:
                crt_sh_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = requests.get(crt_sh_url, timeout=30)
                if response.status_code == 200:
                    certificates = response.json()
                    for cert in certificates:
                        if not self.running:
                            break
                        name_value = cert.get('name_value', '')
                        if name_value and self.domain in name_value:
                            for sub in name_value.split('\n'):
                                sub = sub.strip().lower()
                                if sub.endswith(self.domain) and sub != self.domain:
                                    subdomains.add(sub)
            except requests.RequestException:
                pass
        
        return subdomains
    
    def check_for_new_subdomains(self):
        """Check for new subdomains and return any found"""
        current_subdomains = self.discover_subdomains()
        new_subdomains = current_subdomains - self.known_subdomains
        
        if new_subdomains:
            logging.info(f"🎯 Found {len(new_subdomains)} new subdomains!")
            for subdomain in new_subdomains:
                logging.info(f"   ➕ {subdomain}")
            
            # Update known subdomains
            self.known_subdomains.update(new_subdomains)
            self.save_state()
            
            return new_subdomains
        
        logging.info("✅ No new subdomains found")
        return set()
    
    def send_email_alert(self, new_subdomains):
        """Send email alert about new subdomains"""
        if not self.email_config:
            return False
        
        try:
            subject = f"🚨 Subdomain Alert: {len(new_subdomains)} new subdomains found for {self.domain}"
            
            html = f"""
            <html><body>
                <h2>🔍 Subdomain Monitoring Alert</h2>
                <p><strong>Domain:</strong> {self.domain}</p>
                <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>New subdomains found:</strong> {len(new_subdomains)}</p>
                <ul>
            """
            
            for subdomain in sorted(new_subdomains):
                html += f"<li>{subdomain}</li>"
            
            html += "</ul></body></html>"
            
            text = f"New subdomains found for {self.domain}:\n"
            for subdomain in sorted(new_subdomains):
                text += f"  - {subdomain}\n"
            
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = self.email_config['sender_email']
            message["To"] = self.email_config['receiver_email']
            
            message.attach(MIMEText(text, "plain"))
            message.attach(MIMEText(html, "html"))
            
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(self.email_config['smtp_server'], 
                                 self.email_config['smtp_port'], 
                                 context=context) as server:
                server.login(self.email_config['sender_email'], 
                            self.email_config['sender_password'])
                server.sendmail(
                    self.email_config['sender_email'], 
                    self.email_config['receiver_email'], 
                    message.as_string()
                )
            
            logging.info(f"📧 Email alert sent to {self.email_config['receiver_email']}")
            return True
            
        except Exception as e:
            logging.error(f"❌ Failed to send email alert: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        logging.info("⏹️ Stopping monitoring...")
        self.running = False
    
    def monitor_continuously(self):
        """Continuously monitor for new subdomains"""
        logging.info(f"🚀 Starting monitoring for {self.domain}")
        logging.info(f"⏰ Check interval: {self.check_interval} seconds")
        logging.info(f"📋 Known subdomains: {len(self.known_subdomains)}")
        logging.info("⏹️ Press Ctrl+C to stop")
        
        signal.signal(signal.SIGINT, lambda s, f: self.stop_monitoring())
        signal.signal(signal.SIGTERM, lambda s, f: self.stop_monitoring())
        
        self.running = True
        
        try:
            while self.running:
                new_subs = self.check_for_new_subdomains()
                if new_subs:
                    self.send_alert(new_subs)
                    if self.email_config:
                        self.send_email_alert(new_subs)
                
                for _ in range(self.check_interval):
                    if not self.running:
                        break
                    time.sleep(1)
                
        except KeyboardInterrupt:
            logging.info("⏹️ Monitoring stopped by user")
        except Exception as e:
            logging.error(f"❌ Monitoring error: {e}")
        finally:
            self.running = False
            logging.info("⏹️ Monitoring stopped")
    
    def send_alert(self, new_subdomains):
        """Send console alert about new subdomains"""
        print(f"\n{'='*60}")
        print(f"🚨 ALERT: {len(new_subdomains)} NEW SUBDOMAINS FOUND!")
        print(f"⏰ Time: {datetime.now()}")
        print(f"🌐 Domain: {self.domain}")
        print("📋 New subdomains:")
        for sub in sorted(new_subdomains):
            print(f"   • {sub}")
        print(f"{'='*60}\n")

def load_email_config(config_file='email_config.json'):
    """Load email configuration from JSON file"""
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logging.error(f"❌ Failed to load email config: {e}")
            return None
    return None

def main():
    parser = argparse.ArgumentParser(description='Subdomain monitoring with Subfinder integration')
    parser.add_argument('domain', help='Domain to monitor (e.g., example.com)')
    parser.add_argument('--interval', '-i', type=int, default=36000,
                       help='Check interval in seconds (default: 36000)')
    parser.add_argument('--state-file', '-s', default='subdomain_state.json',
                       help='State file for known subdomains')
    parser.add_argument('--once', '-o', action='store_true',
                       help='Run check once instead of continuous')
    parser.add_argument('--email-config', '-e', default='email_config.json',
                       help='Email configuration file')
    parser.add_argument('--enumerate', '--enum', action='store_true',
                       help='Run Subfinder to enumerate ALL subdomains first')
    
    args = parser.parse_args()
    
    if not args.domain or '.' not in args.domain:
        print("❌ Error: Please provide a valid domain name")
        sys.exit(1)
    
    email_config = load_email_config(args.email_config)
    
    monitor = SubdomainMonitor(
        domain=args.domain,
        check_interval=args.interval,
        state_file=args.state_file,
        email_config=email_config
    )
    
    # Step 1: Run Subfinder enumeration if requested
    if args.enumerate:
        print(f"🔍 Running Subfinder enumeration for {args.domain}...")
        subdomains = monitor.run_subfinder_enumeration()
        if subdomains:
            print(f"✅ Found {len(subdomains)} subdomains")
            print(f"💾 Saved to {args.state_file}")
        else:
            print("❌ Subfinder enumeration failed")
        return
    
    # Step 2: Run monitoring
    if args.once:
        new_subs = monitor.check_for_new_subdomains()
        if new_subs:
            monitor.send_alert(new_subs)
            if email_config:
                monitor.send_email_alert(new_subs)
        else:
            print("✅ No new subdomains found")
    else:
        monitor.monitor_continuously()

if __name__ == "__main__":
    main()