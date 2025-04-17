import os
from dotenv import load_dotenv

load_dotenv()

# Detection thresholds
KEYSTROKE_THRESHOLD = int(os.getenv('KEYSTROKE_THRESHOLD', 1000))  # Max keystrokes/min considered suspicious
PROCESS_MONITOR_INTERVAL = int(os.getenv('PROCESS_MONITOR_INTERVAL', 5))  # Seconds between process checks

# Known keylogger process names
KNOWN_KEYLOGGERS = [
    'keylogger',
    'keysniffer',
    'logkeys',
    'kidlogger',
    'refog',
    'spytector'
]

# Database configuration
DB_NAME = 'keylogger_detection.db'

# New configurations
USB_MONITORING_ENABLED = bool(os.getenv('USB_MONITORING_ENABLED', True))
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')  # Empty default to prompt user
ALERT_THRESHOLD = int(os.getenv('ALERT_THRESHOLD', 5))

# Malware detection settings
MALWARE_SIGNATURE_DB = os.getenv('MALWARE_SIGNATURE_DB', 'malware_signatures.db')
MALWARE_SCAN_INTERVAL = int(os.getenv('MALWARE_SCAN_INTERVAL', 3600))  # 1 hour
KNOWN_MALWARE_PATTERNS = [
    'ransomware',
    'trojan',
    'spyware',
    'rootkit',
    'worm'
]

# Web traffic monitoring
WEB_TRAFFIC_MONITORING = bool(os.getenv('WEB_TRAFFIC_MONITORING', True))
SUSPICIOUS_HTTP_PATTERNS = [
    'SELECT * FROM',
    'DROP TABLE',
    'UNION SELECT',
    'script>alert',
    'eval('
]

# Injection attack detection
INJECTION_DETECTION = bool(os.getenv('INJECTION_DETECTION', True))

ALERT_EMAIL = 'pandeyritikkumar2001@gmail.com'
ALERT_EMAIL = 'pandeyritikkumar68@gmail.com'
ALERT_EMAIL = ''