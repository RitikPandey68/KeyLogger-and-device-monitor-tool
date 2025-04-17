from detection import KeyloggerDetector
from config import (
    MALWARE_SIGNATURE_DB,
    WEB_TRAFFIC_MONITORING
)
import threading
import signal
import sys

def main():
    detector = KeyloggerDetector()
    
    # Start process monitoring in a separate thread
    process_thread = threading.Thread(target=detector.monitor_processes)
    process_thread.daemon = True
    process_thread.start()
    
    # Start network monitoring in a separate thread
    network_thread = threading.Thread(target=detector.monitor_network)
    network_thread.daemon = True
    network_thread.start()
    
    # Start keystroke monitoring
    detector.monitor_keystrokes()
    
    # Start USB device monitoring in a separate thread
    usb_thread = threading.Thread(target=detector.monitor_usb_devices)
    usb_thread.daemon = True
    usb_thread.start()
    
    print("All monitoring systems initialized:")
    print("- Process monitoring")
    print("- Network monitoring") 
    print("- Keystroke monitoring")
    print("- USB device monitoring")
    if MALWARE_SIGNATURE_DB:
        print("- Malware scanning")
    if WEB_TRAFFIC_MONITORING:
        print("- Web traffic monitoring")
    
    # Handle graceful shutdown
    def signal_handler(sig, frame):
        print("\nShutting down keylogger detector gracefully...")
        try:
            if detector.listener:
                detector.listener.stop()
            detector.storage.close()
        except Exception as e:
            print(f"Cleanup error: {str(e)}")
        finally:
            sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    print("Keylogger detection system running. Press Ctrl+C to exit.")
    signal.pause()

if __name__ == "__main__":
    try:
        print("Starting keylogger detection system...")
        print("Initializing detector...")
        main()
    except Exception as e:
        print(f"Error starting keylogger detector: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        print("Program ended")
