#!/usr/bin/env python3
"""
Android Forensic Data Recovery Tool - Desktop Version
Connects to Android devices via ADB and recovers deleted files
"""

import os
import subprocess
import hashlib
import json
from datetime import datetime
from pathlib import Path
import struct

class AndroidForensicTool:
    def __init__(self):
        self.device_id = None
        self.recovery_path = Path("recovered_files")
        self.recovery_path.mkdir(exist_ok=True)
        self.log_file = "forensic_log.txt"
        
        # Common file signatures (magic bytes)
        self.file_signatures = {
            'jpg': [b'\xFF\xD8\xFF'],
            'png': [b'\x89\x50\x4E\x47'],
            'gif': [b'\x47\x49\x46\x38'],
            'pdf': [b'\x25\x50\x44\x46'],
            'zip': [b'\x50\x4B\x03\x04'],
            'mp4': [b'\x00\x00\x00\x18\x66\x74\x79\x70', b'\x00\x00\x00\x1c\x66\x74\x79\x70'],
            'mp3': [b'\x49\x44\x33', b'\xFF\xFB'],
            'doc': [b'\xD0\xCF\x11\xE0'],
            'docx': [b'\x50\x4B\x03\x04'],
            'sqlite': [b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33']
        }
        
        self.log("Forensic Tool Initialized")
    
    def log(self, message):
        """Log forensic activities"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        print(log_entry.strip())
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def check_adb(self):
        """Check if ADB is installed and accessible"""
        try:
            result = subprocess.run(['adb', 'version'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                self.log("ADB found and operational")
                return True
            return False
        except FileNotFoundError:
            self.log("ERROR: ADB not found. Please install Android SDK Platform Tools")
            print("\n📱 Install ADB:")
            print("Windows: choco install adb")
            print("Mac: brew install android-platform-tools")
            print("Linux: sudo apt install adb")
            return False
        except Exception as e:
            self.log(f"ERROR checking ADB: {str(e)}")
            return False
    
    def list_devices(self):
        """List connected Android devices"""
        try:
            result = subprocess.run(['adb', 'devices'], 
                                  capture_output=True, 
                                  text=True)
            devices = []
            for line in result.stdout.split('\n')[1:]:
                if '\tdevice' in line:
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
            
            if devices:
                self.log(f"Found {len(devices)} device(s): {devices}")
            else:
                self.log("No devices connected")
            return devices
        except Exception as e:
            self.log(f"ERROR listing devices: {str(e)}")
            return []
    
    def connect_device(self, device_id=None):
        """Connect to specific device"""
        devices = self.list_devices()
        if not devices:
            return False
        
        if device_id:
            if device_id in devices:
                self.device_id = device_id
            else:
                self.log(f"Device {device_id} not found")
                return False
        else:
            self.device_id = devices[0]
        
        self.log(f"Connected to device: {self.device_id}")
        return True
    
    def get_device_info(self):
        """Get device information"""
        if not self.device_id:
            return None
        
        try:
            info = {}
            
            # Get model
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 
                                   'getprop', 'ro.product.model'],
                                  capture_output=True, text=True)
            info['model'] = result.stdout.strip()
            
            # Get Android version
            result = subprocess.run(['adb', '-s', self.device_id, 'shell', 
                                   'getprop', 'ro.build.version.release'],
                                  capture_output=True, text=True)
            info['android_version'] = result.stdout.strip()
            
            # Get serial
            info['serial'] = self.device_id
            
            self.log(f"Device Info: {json.dumps(info, indent=2)}")
            return info
        except Exception as e:
            self.log(f"ERROR getting device info: {str(e)}")
            return None
    
    def pull_storage_image(self, partition='/sdcard'):
        """Pull storage partition for analysis"""
        if not self.device_id:
            self.log("No device connected")
            return None
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            image_path = self.recovery_path / f"storage_image_{timestamp}.img"
            
            self.log(f"Pulling storage image from {partition}...")
            self.log("This may take several minutes...")
            
            # For demo purposes, we'll pull specific directories
            # In real forensics, you'd use dd to create full disk image
            demo_dirs = [
                f"{partition}/DCIM",
                f"{partition}/Download",
                f"{partition}/Pictures",
                f"{partition}/Documents"
            ]
            
            pulled_files = []
            for dir_path in demo_dirs:
                # List files in directory
                result = subprocess.run(['adb', '-s', self.device_id, 'shell', 
                                       'ls', dir_path],
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    for file in files[:5]:  # Limit for demo
                        if file and not file.startswith('ls:'):
                            pulled_files.append(f"{dir_path}/{file}")
            
            return pulled_files
        except Exception as e:
            self.log(f"ERROR pulling storage: {str(e)}")
            return None
    
    def detect_file_type(self, data):
        """Detect file type from magic bytes"""
        for file_type, signatures in self.file_signatures.items():
            for sig in signatures:
                if data.startswith(sig):
                    return file_type
        return 'unknown'
    
    def carve_files_from_data(self, data):
        """Data carving - extract files from raw data"""
        carved_files = []
        
        for file_type, signatures in self.file_signatures.items():
            for sig in signatures:
                pos = 0
                while True:
                    pos = data.find(sig, pos)
                    if pos == -1:
                        break
                    
                    # Found potential file
                    carved_files.append({
                        'type': file_type,
                        'offset': pos,
                        'signature': sig.hex()
                    })
                    pos += len(sig)
        
        return carved_files
    
    def scan_deleted_files(self, source_path=None):
        """Scan for deleted files using various techniques"""
        if not self.device_id:
            self.log("No device connected")
            return []
        
        self.log("Starting deleted file scan...")
        found_files = []
        
        try:
            # Method 1: Check common cache and temp directories
            cache_dirs = [
                '/sdcard/.cache',
                '/sdcard/.thumbnails',
                '/data/local/tmp',
                '/sdcard/Android/data'
            ]
            
            for cache_dir in cache_dirs:
                result = subprocess.run(['adb', '-s', self.device_id, 'shell',
                                       f'find {cache_dir} -type f 2>/dev/null'],
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    for file_path in files:
                        if file_path and not file_path.startswith('find:'):
                            found_files.append({
                                'path': file_path,
                                'source': 'cache',
                                'type': 'cached_file'
                            })
            
            # Method 2: Check for SQLite databases (WhatsApp, SMS, etc.)
            result = subprocess.run(['adb', '-s', self.device_id, 'shell',
                                   'find /sdcard -name "*.db" 2>/dev/null'],
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                db_files = result.stdout.strip().split('\n')
                for db_path in db_files[:10]:  # Limit for demo
                    if db_path and not db_path.startswith('find:'):
                        found_files.append({
                            'path': db_path,
                            'source': 'database',
                            'type': 'sqlite'
                        })
            
            self.log(f"Found {len(found_files)} potentially recoverable items")
            return found_files
            
        except Exception as e:
            self.log(f"ERROR during scan: {str(e)}")
            return found_files
    
    def recover_file(self, file_info):
        """Recover a specific file"""
        if not self.device_id:
            return False
        
        try:
            file_path = file_info['path']
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create recovery directory
            recovery_dir = self.recovery_path / timestamp
            recovery_dir.mkdir(exist_ok=True)
            
            # Pull file
            local_path = recovery_dir / file_name
            result = subprocess.run(['adb', '-s', self.device_id, 'pull',
                                   file_path, str(local_path)],
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0 and local_path.exists():
                # Calculate hash
                with open(local_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                self.log(f"✓ Recovered: {file_name}")
                self.log(f"  Location: {local_path}")
                self.log(f"  SHA-256: {file_hash}")
                
                return {
                    'success': True,
                    'path': str(local_path),
                    'hash': file_hash
                }
            else:
                self.log(f"✗ Failed to recover: {file_name}")
                return {'success': False}
                
        except Exception as e:
            self.log(f"ERROR recovering file: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def generate_report(self, scan_results, recovered_files):
        """Generate forensic report"""
        report_path = self.recovery_path / f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("FORENSIC DATA RECOVERY REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Device ID: {self.device_id}\n\n")
            
            device_info = self.get_device_info()
            if device_info:
                f.write("DEVICE INFORMATION:\n")
                f.write("-" * 70 + "\n")
                for key, value in device_info.items():
                    f.write(f"{key}: {value}\n")
                f.write("\n")
            
            f.write("SCAN RESULTS:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total items found: {len(scan_results)}\n\n")
            
            for idx, item in enumerate(scan_results[:50], 1):  # Limit to 50 in report
                f.write(f"{idx}. {item['path']}\n")
                f.write(f"   Type: {item['type']}\n")
                f.write(f"   Source: {item['source']}\n\n")
            
            f.write("\nRECOVERED FILES:\n")
            f.write("-" * 70 + "\n")
            f.write(f"Successfully recovered: {len(recovered_files)}\n\n")
            
            for item in recovered_files:
                if item['success']:
                    f.write(f"✓ {item['path']}\n")
                    f.write(f"  Hash: {item.get('hash', 'N/A')}\n\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 70 + "\n")
        
        self.log(f"Report generated: {report_path}")
        return report_path


def main():
    """Main function - Interactive forensic tool"""
    print("=" * 70)
    print("ANDROID FORENSIC DATA RECOVERY TOOL - DESKTOP VERSION")
    print("=" * 70)
    print()
    
    tool = AndroidForensicTool()
    
    # Check ADB
    if not tool.check_adb():
        print("\n❌ ADB not available. Please install it first.")
        return
    
    # Connect to device
    print("\n📱 Looking for connected devices...")
    if not tool.connect_device():
        print("\n❌ No devices found. Please:")
        print("1. Enable USB Debugging on your Android device")
        print("2. Connect via USB cable")
        print("3. Accept USB debugging prompt on phone")
        return
    
    # Get device info
    device_info = tool.get_device_info()
    if device_info:
        print(f"\n✓ Connected to: {device_info['model']}")
        print(f"  Android: {device_info['android_version']}")
    
    # Main menu
    while True:
        print("\n" + "=" * 70)
        print("FORENSIC OPERATIONS:")
        print("=" * 70)
        print("1. Scan for deleted files")
        print("2. Pull storage image")
        print("3. View device info")
        print("4. Generate report")
        print("5. Exit")
        print()
        
        choice = input("Select option (1-5): ").strip()
        
        if choice == '1':
            print("\n🔍 Scanning device for recoverable files...")
            scan_results = tool.scan_deleted_files()
            
            if scan_results:
                print(f"\n✓ Found {len(scan_results)} potentially recoverable items")
                print("\nFirst 10 results:")
                for idx, item in enumerate(scan_results[:10], 1):
                    print(f"{idx}. {item['path']}")
                    print(f"   Type: {item['type']} | Source: {item['source']}")
                
                # Ask to recover
                recover = input("\nRecover files? (y/n): ").strip().lower()
                if recover == 'y':
                    recovered = []
                    for item in scan_results[:5]:  # Recover first 5 for demo
                        result = tool.recover_file(item)
                        if result['success']:
                            recovered.append(result)
                    
                    print(f"\n✓ Recovered {len(recovered)} files")
                    print(f"Location: {tool.recovery_path}")
            else:
                print("\n❌ No recoverable files found")
        
        elif choice == '2':
            print("\n📦 Pulling storage data...")
            files = tool.pull_storage_image()
            if files:
                print(f"✓ Found {len(files)} accessible files")
        
        elif choice == '3':
            info = tool.get_device_info()
            if info:
                print("\nDevice Information:")
                for key, value in info.items():
                    print(f"  {key}: {value}")
        
        elif choice == '4':
            print("\n📄 Generating forensic report...")
            report = tool.generate_report([], [])
            print(f"✓ Report saved: {report}")
        
        elif choice == '5':
            print("\n👋 Exiting forensic tool...")
            break
        
        else:
            print("\n❌ Invalid option")


if __name__ == "__main__":
    main()