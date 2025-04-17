import psutil
import socket
import platform
import logging
try:
    import wmi  # For Windows USB device monitoring
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False
from pynput import keyboard
from config import (
    KEYSTROKE_THRESHOLD, 
    PROCESS_MONITOR_INTERVAL, 
    KNOWN_KEYLOGGERS,
    USB_MONITORING_ENABLED,
    ALERT_EMAIL,
    ALERT_THRESHOLD,
    MALWARE_SIGNATURE_DB,
    MALWARE_SCAN_INTERVAL,
    KNOWN_MALWARE_PATTERNS,
    WEB_TRAFFIC_MONITORING,
    SUSPICIOUS_HTTP_PATTERNS,
    INJECTION_DETECTION
)
import os
import threading
from storage import DataStorage
from datetime import datetime, timedelta
import time
import smtplib
import logging
from email.message import EmailMessage

class KeyloggerDetector:
    """Enhanced keylogger detection with:
    - Process monitoring
    - Keystroke analysis
    - Resource usage tracking
    - Network activity monitoring
    """

    def __init__(self): 
        self.logger = self._setup_logger()  # Initialize logger
        self.storage = DataStorage()
        self.keystroke_count = 0
        self.last_reset_time = datetime.now()
        self.listener = None
        
        if USB_MONITORING_ENABLED and not WMI_AVAILABLE:
            print("Warning: USB monitoring enabled but WMI module not available")
        
        # Start malware scanning in a separate thread if enabled
        if MALWARE_SIGNATURE_DB:
            malware_thread = threading.Thread(target=self.scan_for_malware)
            malware_thread.daemon = True
            malware_thread.start()
            
        # Start web traffic monitoring in a separate thread if enabled
        if WEB_TRAFFIC_MONITORING:
            web_thread = threading.Thread(target=self.monitor_web_traffic)
            web_thread.daemon = True
            web_thread.start()

    def monitor_processes(self):
        """Monitor running processes for suspicious activity"""
        # Initialize storage for this thread
        storage = DataStorage()
        
        while True:
            for proc in psutil.process_iter(['name', 'pid', 'cpu_percent', 'memory_percent']):
                proc_name = proc.info['name'].lower()
                
                # Check for known keylogger patterns
                for kl_name in KNOWN_KEYLOGGERS:
                    if kl_name in proc_name:
                        storage.log_suspicious_process(
                            proc_name,
                            proc.info['pid'],
                            "Matches known keylogger pattern"
                        )
                
                # Check for suspicious resource usage
                if proc.info['cpu_percent'] > 30 or proc.info['memory_percent'] > 30:
                    storage.log_suspicious_process(
                        proc_name,
                        proc.info['pid'],
                        f"High resource usage (CPU: {proc.info['cpu_percent']}%, MEM: {proc.info['memory_percent']}%)"
                    )
            
            time.sleep(PROCESS_MONITOR_INTERVAL)

    def monitor_network(self):
        """Monitor network activity for suspicious connections"""
        # Initialize storage for this thread
        storage = DataStorage()
        
        while True:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Skip local and private network connections
                        if not any(d in conn.raddr.ip for d in ['192.168', '10.0', '127.0']):
                            # Get process name for the connection
                            try:
                                proc = psutil.Process(conn.pid)
                                proc_name = proc.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                proc_name = "Unknown Process"
                            
                            storage.log_suspicious_process(
                                proc_name,
                                conn.pid,
                                f"Suspicious connection to {conn.raddr.ip}:{conn.raddr.port}"
                            )
            except Exception as e:
                print(f"Network monitoring error: {str(e)}")
            time.sleep(60)  # Check every minute

    def on_press(self, key):
        """Callback for each key press"""
        self.keystroke_count += 1

    def monitor_keystrokes(self):
        """Monitor keystroke rate for suspicious activity"""
        # Initialize storage for this thread
        storage = DataStorage()
        
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()

        while True:
            time.sleep(60)  # Check every minute
            current_time = datetime.now()
            time_diff = (current_time - self.last_reset_time).total_seconds()
            
            if time_diff >= 60:
                keystroke_rate = self.keystroke_count / (time_diff / 60)
                is_suspicious = keystroke_rate > KEYSTROKE_THRESHOLD
                
                storage.log_keystroke_stats(
                    self.keystroke_count,
                    is_suspicious
                )
                
                if is_suspicious:
                    print(f"Warning: High keystroke rate detected ({keystroke_rate:.1f} keystrokes/min)")
                
                self.keystroke_count = 0
                self.last_reset_time = current_time

    def monitor_usb_devices(self):
        """Monitor USB devices for suspicious activity using WMI"""
        if not USB_MONITORING_ENABLED or not WMI_AVAILABLE:
            return

        try:
            c = wmi.WMI()
            watcher = c.Win32_DeviceChangeEvent.watch_for(
                notification_type="Creation",
                delay_secs=1
            )

            while True:
                try:
                    event = watcher()
                    for usb in c.Win32_USBControllerDevice():
                        device = c.Win32_PnPEntity(DeviceID=usb.Dependent)
                        if device:
                            self.storage.log_suspicious_device(
                                device[0].Description or "Unknown",
                                device[0].DeviceID or "Unknown",
                                "New USB device connected"
                            )
                            self.send_alert(f"New USB device connected: {device[0].Description or 'Unknown'}")
                except Exception as e:
                    print(f"USB monitoring error: {str(e)}")
                    time.sleep(5)
        except Exception as e:
            print(f"Failed to initialize WMI: {str(e)}")
            return

    def quarantine_file(self, file_path):
        """Move detected file to quarantine for analysis"""
        quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)
        
        # Skip files in system directories
        system_dirs = ['windows', 'program files', 'gcc', 'system32', 'share']
        if any(dir in file_path.lower() for dir in system_dirs):
            self.logger.warning(f"Skipping system file: {file_path}")
            return False
            
        # Generate unique filename if already exists
        base_name = os.path.basename(file_path)
        dest_path = os.path.join(quarantine_dir, base_name)
        counter = 1
        while os.path.exists(dest_path):
            name, ext = os.path.splitext(base_name)
            dest_path = os.path.join(quarantine_dir, f"{name}_{counter}{ext}")
            counter += 1
            
        # Try moving file with retries for locked files
        max_retries = 3
        for attempt in range(max_retries):
            try:
                os.rename(file_path, dest_path)
                self.storage.log_malware_detection(
                    file_path,
                    "QUARANTINED",
                    f"Moved to {dest_path}"
                )
                self.logger.info(f"Successfully quarantined file: {file_path} -> {dest_path}")
                return True
            except PermissionError as e:
                if attempt < max_retries - 1:
                    time.sleep(1)  # Wait before retrying
                    continue
                self.logger.error(f"Failed to quarantine file (file in use): {file_path}")
                return False
            except Exception as e:
                self.logger.error(f"Failed to quarantine file {file_path}: {str(e)}")
                return False
        return False

    def remove_malware(self, file_path):
        """Remove detected malware file (use quarantine_file instead)"""
        if not os.path.exists(file_path):
            self.logger.warning(f"File not found: {file_path}")
            return False
            
        try:
            os.remove(file_path)
            self.storage.log_malware_detection(
                file_path,
                "REMOVED",
                "Deleted"
            )
            self.logger.info(f"Successfully removed malware: {file_path}")
            self.send_alert(f"Malware removed: {file_path}")
            return True
        except PermissionError:
            self.logger.warning(f"Permission denied for file: {file_path}")
            # Try again with admin privileges
            try:
                if platform.system() == 'Windows':
                    import ctypes
                    if ctypes.windll.shell32.IsUserAnAdmin():
                        os.remove(file_path)
                        self.logger.info(f"Successfully removed malware with admin privileges: {file_path}")
                        return True
            except Exception as admin_e:
                self.logger.error(f"Admin removal failed: {str(admin_e)}")
                return False
        except Exception as e:
            self.logger.error(f"Error removing file {file_path}: {str(e)}")
            self.storage.log_malware_detection(
                file_path,
                "REMOVAL_FAILED",
                f"Error: {str(e)}"
            )
            self.send_alert(f"Failed to remove malware: {file_path} ({str(e)})")
            return False

    def scan_for_malware(self):
        """Scan system for known malware signatures and remove them"""
        if not hasattr(self, 'malware_signatures'):
            # Load malware signatures on first run
            try:
                with open(MALWARE_SIGNATURE_DB, 'r') as f:
                    self.malware_signatures = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"Warning: Malware signature database not found at {MALWARE_SIGNATURE_DB}")
                self.malware_signatures = KNOWN_MALWARE_PATTERNS
            except Exception as e:
                print(f"Error loading malware signatures: {str(e)}")
                self.malware_signatures = KNOWN_MALWARE_PATTERNS

        while True:
            try:
                for root, _, files in os.walk('C:\\'):  # Scan all drives
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'rb') as f:
                                content = f.read()
                                for signature in self.malware_signatures:
                                    # Only flag as malware if signature appears in first 1MB of file
                                    # and file is not in common system/program directories
                                    if (signature.encode() in content[:1048576] and 
                                        not any(dir in file_path.lower() for dir in ['windows', 'program files', 'gcc'])):
                                        print(f"Potential malware detected: {file_path}")
                                        if self.quarantine_file(file_path):
                                            print(f"Successfully quarantined malware: {file_path}")
                                        else:
                                            print(f"Failed to quarantine malware: {file_path}")
                        except (PermissionError, IOError):
                            continue
            except Exception as e:
                print(f"Error during malware scan: {str(e)}")
                self.logger.error(f"Malware scan error: {str(e)}")
            time.sleep(MALWARE_SCAN_INTERVAL)

    def monitor_web_traffic(self):
        """Monitor HTTP/HTTPS traffic for suspicious patterns"""
        if not WEB_TRAFFIC_MONITORING:
            return

        while True:
            try:
                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        # Check for web traffic (ports 80, 443)
                        if conn.raddr.port in [80, 443]:
                            try:
                                proc = psutil.Process(conn.pid)
                                proc_name = proc.name()
                                # Check for suspicious patterns in process memory
                                for pattern in SUSPICIOUS_HTTP_PATTERNS:
                                    if pattern in str(proc.memory_maps()):
                                        self.storage.log_web_traffic(
                                            conn.laddr.ip,
                                            conn.raddr.ip,
                                            f"http{'s' if conn.raddr.port == 443 else ''}://{conn.raddr.ip}",
                                            pattern,
                                            "Blocked"
                                        )
                                        self.send_alert(f"Suspicious web traffic pattern detected: {pattern}")
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
            except Exception as e:
                print(f"Web traffic monitoring error: {str(e)}")
            time.sleep(60)

        
    def _setup_logger(self):
        """Setup logging configuration"""
        logger = logging.getLogger('keylogger_detector')
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler
        fh = logging.FileHandler('detection.log')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
        return logger

    def send_alert(self, message):
        """Send alert notification using system default mail client"""
        # First try to get alert email configuration
        try:
            from config import ALERT_EMAIL
            self.alert_email = ALERT_EMAIL
        except ImportError:
            self.alert_email = None
        except Exception as e:
            self.logger.error(f"Error loading alert email config: {str(e)}")
            self.alert_email = None

        # If no alert email configured, prompt user
        if not self.alert_email:
            try:
                self.alert_email = input("pandeyritikkumar68@gmail.com: ")
                # Update config for future alerts
                with open('config.py', 'a') as f:
                    f.write(f"\nALERT_EMAIL = '{self.alert_email}'")
                self.logger.info(f"Alert email set to: {self.alert_email}")
            except Exception as e:
                self.logger.error(f"Failed to configure alert email: {str(e)}")
                return

        # Try to send the alert
        try:
            import win32com.client as win32
            outlook = win32.Dispatch('outlook.application')
            mail = outlook.CreateItem(0)
            mail.Subject = 'Keylogger Detection Alert'
            mail.Body = message
            mail.To = self.alert_email
            mail.Send()
            self.logger.info(f"Alert sent to {self.alert_email}")
        except ImportError as e:
            self.logger.error(f"Failed to import Outlook client: {str(e)}")
            self.logger.warning(f"Alert would be: {message}")
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {str(e)}")
            self.logger.warning(f"Alert message was: {message}")
