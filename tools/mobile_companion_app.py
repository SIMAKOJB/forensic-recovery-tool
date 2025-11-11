#!/data/data/com.termux/files/usr/bin/python3
"""
Android Forensic Data Recovery - Mobile Companion App
Runs directly on Android device using Termux
"""

import os
import hashlib
import json
from datetime import datetime
from pathlib import Path
import struct

class MobileForensicTool:
    def __init__(self):
        # Termux accessible paths
        self.storage_root = Path('/sdcard')
        self.termux_home = Path.home()
        self.recovery_path = self.termux_home / 'forensic_recovery'
        self.recovery_path.mkdir(exist_ok=True)
        self.log_file = self.recovery_path / 'forensic_log.txt'
        
        # File signatures
        self.file_signatures = {
            'jpg': b'\xFF\xD8\xFF',
            'png': b'\x89\x50\x4E\x47',
            'gif': b'\x47\x49\x46\x38',
            'pdf': b'\x25\x50\x44\x46',
            'zip': b'\x50\x4B\x03\x04',
            'mp4': b'\x00\x00\x00\x18\x66\x74\x79\x70',
            'mp3': b'\x49\x44\x33',
            'doc': b'\xD0\xCF\x11\xE0',
            'sqlite': b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33'
        }
        
        self.log("Mobile Forensic Tool Initialized")
        print("🔧 Forensic Recovery Tool - Mobile Version")
        print(f"📁 Recovery Directory: {self.recovery_path}")
    
    def log(self, message):
        """Log forensic activities"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def check_permissions(self):
        """Check storage permissions"""
        try:
            if self.storage_root.exists():
                # Test write access
                test_file = self.storage_root / '.forensic_test'
                test_file.touch()
                test_file.unlink()
                self.log("Storage access confirmed")
                return True
            else:
                print("\n❌ Storage not accessible")
                print("Run: termux-setup-storage")
                return False
        except PermissionError:
            print("\n❌ Permission denied")
            print("Run: termux-setup-storage")
            return False
        except Exception as e:
            self.log(f"Permission check error: {str(e)}")
            return False
    
    def get_device_info(self):
        """Get device information"""
        info = {}
        try:
            # Try to get Android properties
            prop_files = [
                '/system/build.prop',
                '/default.prop'
            ]
            
            for prop_file in prop_files:
                if os.path.exists(prop_file):
                    try:
                        with open(prop_file, 'r') as f:
                            for line in f:
                                if 'ro.product.model' in line:
                                    info['model'] = line.split('=')[1].strip()
                                elif 'ro.build.version.release' in line:
                                    info['android_version'] = line.split('=')[1].strip()
                    except:
                        pass
            
            # Fallback info
            if not info:
                info = {
                    'device': 'Android Device',
                    'app': 'Termux Mobile Forensic Tool'
                }
            
            self.log(f"Device Info: {json.dumps(info)}")
            return info
        except Exception as e:
            self.log(f"Error getting device info: {str(e)}")
            return {'error': str(e)}
    
    def detect_file_type(self, file_path):
        """Detect file type from magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)
                
            for file_type, sig in self.file_signatures.items():
                if header.startswith(sig):
                    return file_type
            return 'unknown'
        except:
            return 'error'
    
    def scan_directory(self, directory, recursive=True):
        """Scan directory for files"""
        found_files = []
        try:
            dir_path = Path(directory)
            if not dir_path.exists():
                return found_files
            
            pattern = '**/*' if recursive else '*'
            for item in dir_path.glob(pattern):
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_info = {
                            'path': str(item),
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                            'type': self.detect_file_type(item)
                        }
                        found_files.append(file_info)
                    except:
                        pass
            
            return found_files
        except Exception as e:
            self.log(f"Scan error: {str(e)}")
            return found_files
    
    def scan_deleted_files(self):
        """Scan for potentially deleted or recoverable files"""
        self.log("Starting deleted file scan...")
        print("\n🔍 Scanning for recoverable files...")
        
        recoverable = []
        
        # Areas to check (accessible without root)
        scan_locations = [
            self.storage_root / 'DCIM' / '.thumbnails',
            self.storage_root / '.cache',
            self.storage_root / 'Android' / 'data',
            self.storage_root / 'Download',
            self.storage_root / 'Pictures',
            self.storage_root / 'Documents'
        ]
        
        for location in scan_locations:
            if location.exists():
                print(f"  Scanning: {location.name}...")
                files = self.scan_directory(location, recursive=False)
                
                for file_info in files:
                    # Check if file looks like it might be deleted/temp
                    name = Path(file_info['path']).name
                    if any(x in name.lower() for x in ['.tmp', '.cache', '.thumbnail', '~']):
                        file_info['source'] = 'cache/temp'
                        recoverable.append(file_info)
                    elif file_info['type'] in ['jpg', 'png', 'mp4', 'pdf']:
                        file_info['source'] = 'media'
                        recoverable.append(file_info)
        
        self.log(f"Found {len(recoverable)} potentially recoverable files")
        return recoverable
    
    def recover_file(self, file_info):
        """Copy file to recovery directory"""
        try:
            source = Path(file_info['path'])
            if not source.exists():
                return {'success': False, 'error': 'File not found'}
            
            # Create timestamped recovery folder
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            recovery_folder = self.recovery_path / timestamp
            recovery_folder.mkdir(exist_ok=True)
            
            # Copy file
            dest = recovery_folder / source.name
            with open(source, 'rb') as src_file:
                data = src_file.read()
                file_hash = hashlib.sha256(data).hexdigest()
                
                with open(dest, 'wb') as dst_file:
                    dst_file.write(data)
            
            self.log(f"Recovered: {source.name} -> {dest}")
            
            return {
                'success': True,
                'path': str(dest),
                'hash': file_hash,
                'size': len(data)
            }
        except Exception as e:
            self.log(f"Recovery error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def analyze_sqlite_db(self, db_path):
        """Analyze SQLite database for deleted records"""
        try:
            import sqlite3
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get table list
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            analysis = {
                'path': db_path,
                'tables': [t[0] for t in tables],
                'table_count': len(tables)
            }
            
            conn.close()
            return analysis
        except Exception as e:
            return {'error': str(e)}
    
    def search_databases(self):
        """Search for SQLite databases"""
        print("\n🗄️  Searching for databases...")
        databases = []
        
        search_paths = [
            self.storage_root,
            self.storage_root / 'Android' / 'data'
        ]
        
        for search_path in search_paths:
            if search_path.exists():
                for db_file in search_path.rglob('*.db'):
                    if db_file.is_file():
                        size = db_file.stat().st_size
                        databases.append({
                            'path': str(db_file),
                            'name': db_file.name,
                            'size': size,
                            'type': 'sqlite'
                        })
        
        self.log(f"Found {len(databases)} database files")
        return databases
    
    def generate_report(self, scan_results):
        """Generate forensic report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.recovery_path / f"report_{timestamp}.txt"
        
        with open(report_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("MOBILE FORENSIC SCAN REPORT\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            device_info = self.get_device_info()
            f.write("\nDevice Information:\n")
            f.write("-" * 60 + "\n")
            for key, value in device_info.items():
                f.write(f"{key}: {value}\n")
            
            f.write("\nScan Results:\n")
            f.write("-" * 60 + "\n")
            f.write(f"Total files found: {len(scan_results)}\n\n")
            
            # Group by type
            by_type = {}
            for item in scan_results:
                ftype = item.get('type', 'unknown')
                if ftype not in by_type:
                    by_type[ftype] = []
                by_type[ftype].append(item)
            
            for ftype, items in by_type.items():
                f.write(f"\n{ftype.upper()} Files: {len(items)}\n")
                for item in items[:10]:  # First 10 of each type
                    f.write(f"  • {Path(item['path']).name}\n")
                    f.write(f"    Size: {item['size']} bytes\n")
            
            f.write("\n" + "=" * 60 + "\n")
        
        self.log(f"Report generated: {report_path}")
        return report_path
    
    def quick_recovery_mode(self):
        """Quick recovery of recent photos/videos"""
        print("\n⚡ Quick Recovery Mode")
        print("Scanning recent media files...")
        
        media_dirs = [
            self.storage_root / 'DCIM' / 'Camera',
            self.storage_root / 'Pictures',
            self.storage_root / 'Download'
        ]
        
        recovered = []
        for media_dir in media_dirs:
            if media_dir.exists():
                files = self.scan_directory(media_dir, recursive=False)
                
                # Get most recent files
                recent_files = sorted(files, key=lambda x: x['modified'], reverse=True)[:5]
                
                for file_info in recent_files:
                    if file_info['type'] in ['jpg', 'png', 'mp4']:
                        result = self.recover_file(file_info)
                        if result['success']:
                            recovered.append(result)
        
        return recovered


def print_menu():
    """Display main menu"""
    print("\n" + "=" * 60)
    print("MOBILE FORENSIC TOOL - MAIN MENU")
    print("=" * 60)
    print("1. Quick Scan (Recent files)")
    print("2. Deep Scan (All accessible storage)")
    print("3. Search Databases")
    print("4. Quick Recovery (Recent media)")
    print("5. Device Information")
    print("6. Generate Report")
    print("7. View Logs")
    print("8. Exit")
    print("=" * 60)


def main():
    """Main function"""
    print("\n" + "=" * 60)
    print("🔬 ANDROID FORENSIC TOOL - MOBILE COMPANION")
    print("=" * 60)
    print("\n⚠️  This tool runs directly on your Android device")
    print("📱 Requires Termux app and storage permissions\n")
    
    tool = MobileForensicTool()
    
    # Check permissions
    if not tool.check_permissions():
        print("\n❌ Cannot access storage. Setup required:")
        print("   1. Run: termux-setup-storage")
        print("   2. Grant storage permission")
        print("   3. Restart this script")
        return
    
    print("\n✓ Storage access confirmed")
    
    scan_results = []
    
    while True:
        print_menu()
        choice = input("\nSelect option (1-8): ").strip()
        
        if choice == '1':
            print("\n🔍 Quick Scan - Checking common locations...")
            scan_results = tool.scan_deleted_files()
            
            if scan_results:
                print(f"\n✓ Found {len(scan_results)} files")
                print("\nFile Type Summary:")
                
                types = {}
                for item in scan_results:
                    ftype = item['type']
                    types[ftype] = types.get(ftype, 0) + 1
                
                for ftype, count in types.items():
                    print(f"  • {ftype}: {count} files")
                
                print("\nFirst 5 files:")
                for idx, item in enumerate(scan_results[:5], 1):
                    name = Path(item['path']).name
                    print(f"  {idx}. {name}")
                    print(f"     Type: {item['type']} | Size: {item['size']} bytes")
            else:
                print("\n❌ No recoverable files found")
        
        elif choice == '2':
            print("\n🔍 Deep Scan - This may take a while...")
            all_files = []
            
            scan_dirs = [
                tool.storage_root / 'DCIM',
                tool.storage_root / 'Download',
                tool.storage_root / 'Pictures',
                tool.storage_root / 'Documents',
                tool.storage_root / 'Music'
            ]
            
            for scan_dir in scan_dirs:
                if scan_dir.exists():
                    print(f"  Scanning: {scan_dir.name}...")
                    files = tool.scan_directory(scan_dir, recursive=True)
                    all_files.extend(files)
            
            scan_results = all_files
            print(f"\n✓ Deep scan complete: {len(scan_results)} files found")
        
        elif choice == '3':
            databases = tool.search_databases()
            
            if databases:
                print(f"\n✓ Found {len(databases)} database files")
                print("\nDatabases:")
                for idx, db in enumerate(databases[:10], 1):
                    print(f"  {idx}. {db['name']}")
                    print(f"     Size: {db['size']} bytes")
                    print(f"     Path: {db['path']}")
                
                # Ask to analyze
                if databases:
                    analyze = input("\nAnalyze first database? (y/n): ").strip().lower()
                    if analyze == 'y':
                        analysis = tool.analyze_sqlite_db(databases[0]['path'])
                        if 'error' not in analysis:
                            print(f"\n📊 Database Analysis:")
                            print(f"   Tables: {analysis['table_count']}")
                            print(f"   Table names: {', '.join(analysis['tables'][:5])}")
                        else:
                            print(f"\n❌ Analysis failed: {analysis['error']}")
            else:
                print("\n❌ No databases found")
        
        elif choice == '4':
            print("\n⚡ Quick Recovery Mode")
            recovered = tool.quick_recovery_mode()
            
            if recovered:
                print(f"\n✓ Recovered {len(recovered)} files")
                print(f"📁 Location: {tool.recovery_path}")
                
                for item in recovered:
                    print(f"\n  • {Path(item['path']).name}")
                    print(f"    Size: {item['size']} bytes")
                    print(f"    Hash: {item['hash'][:16]}...")
            else:
                print("\n❌ No files recovered")
        
        elif choice == '5':
            print("\n📱 Device Information:")
            info = tool.get_device_info()
            for key, value in info.items():
                print(f"   {key}: {value}")
        
        elif choice == '6':
            if scan_results:
                print("\n📄 Generating report...")
                report = tool.generate_report(scan_results)
                print(f"✓ Report saved: {report}")
            else:
                print("\n❌ No scan results. Run a scan first.")
        
        elif choice == '7':
            print("\n📋 Recent Log Entries:")
            try:
                with open(tool.log_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-10:]:  # Last 10 entries
                        print(f"   {line.strip()}")
            except:
                print("   No logs available")
        
        elif choice == '8':
            print("\n👋 Exiting forensic tool...")
            print(f"📁 Recovered files saved in: {tool.recovery_path}")
            break
        
        else:
            print("\n❌ Invalid option. Please select 1-8.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Tool interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        print("Check logs for details")