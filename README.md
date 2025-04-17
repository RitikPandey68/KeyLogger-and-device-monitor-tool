# Keylogger Detection Tool

A Python-based tool to detect suspicious keylogger activity by:
- Monitoring running processes for known keylogger patterns
- Tracking keystroke rates for abnormal activity
- Logging all detections to a SQLite database

## Features
- Real-time process monitoring
- Keystroke rate analysis
- Persistent logging of suspicious activity
- Configurable detection thresholds

## Installation
1. Install requirements:
```bash
pip install -r requirements.txt
```

2. Configure settings in `.env` file (optional):
```
KEYSTROKE_THRESHOLD=1000
PROCESS_MONITOR_INTERVAL=5
```

## Usage
Run the detection system:
```bash
python main.py
```

The system will:
- Continuously monitor processes
- Track keystroke rates
- Log suspicious activity to `keylogger_detection.db`

## Database Schema
The SQLite database contains two tables:
1. `suspicious_processes` - Logs detected suspicious processes
2. `keystroke_stats` - Records keystroke statistics

## Detection Methods
1. **Process Monitoring**:
   - Scans for known keylogger process names
   - Runs every 5 seconds (configurable)

2. **Keystroke Analysis**:
   - Tracks keystrokes per minute
   - Flags rates above threshold (default: 1000/min)
   - Logs all activity to database

## Requirements
- Python 3.6+
- psutil
- pynput
- python-dotenv

## License
MIT
