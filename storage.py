import sqlite3
import threading
from datetime import datetime

class DataStorage:
    _local = threading.local()
    
    def __init__(self, db_name='keylogger_detection.db'):
        self.db_name = db_name
        if not hasattr(DataStorage._local, 'conn'):
            DataStorage._local.conn = sqlite3.connect(self.db_name, check_same_thread=False)
            self._create_tables()
            
    @property
    def conn(self):
        if not hasattr(DataStorage._local, 'conn'):
            DataStorage._local.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        return DataStorage._local.conn

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_processes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                detection_time DATETIME NOT NULL,
                reason TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keystroke_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                count INTEGER NOT NULL,
                is_suspicious BOOLEAN NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malware_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                detection_time DATETIME NOT NULL,
                signature_name TEXT NOT NULL,
                action_taken TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS web_traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                url TEXT,
                suspicious_pattern TEXT,
                action_taken TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS injection_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                process_name TEXT,
                input_data TEXT,
                pattern_detected TEXT
            )
        ''')
        self.conn.commit()

    def log_suspicious_process(self, process_name, process_id, reason):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO suspicious_processes 
                (process_name, process_id, detection_time, reason)
                VALUES (?, ?, ?, ?)
            ''', (process_name, process_id, datetime.now(), reason))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def log_keystroke_stats(self, count, is_suspicious):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO keystroke_stats 
                (timestamp, count, is_suspicious)
                VALUES (?, ?, ?)
            ''', (datetime.now(), count, is_suspicious))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def get_recent_detections(self, limit=10):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM suspicious_processes 
                ORDER BY detection_time DESC 
                LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
        except Exception as e:
            print(f"Database error: {str(e)}")
            return []

    def log_suspicious_device(self, device_name, device_id, reason):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO suspicious_devices 
                (device_name, device_id, detection_time, reason)
                VALUES (?, ?, ?, ?)
            ''', (device_name, device_id, datetime.now(), reason))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def log_malware_detection(self, file_path, signature_name, action_taken):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO malware_detections 
                (file_path, detection_time, signature_name, action_taken)
                VALUES (?, ?, ?, ?)
            ''', (file_path, datetime.now(), signature_name, action_taken))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def log_web_traffic(self, source_ip, destination_ip, url, suspicious_pattern, action_taken):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO web_traffic_logs 
                (timestamp, source_ip, destination_ip, url, suspicious_pattern, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (datetime.now(), source_ip, destination_ip, url, suspicious_pattern, action_taken))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def log_injection_attempt(self, process_name, input_data, pattern_detected):
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO injection_attempts 
                (timestamp, process_name, input_data, pattern_detected)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now(), process_name, input_data, pattern_detected))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {str(e)}")

    def close(self):
        if hasattr(DataStorage._local, 'conn'):
            self.conn.close()
