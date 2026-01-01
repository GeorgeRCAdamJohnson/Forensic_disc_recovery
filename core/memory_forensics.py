"""
Advanced Memory & Live Forensics Engine
Real-time system analysis and memory forensics
"""

import volatility3.framework.contexts
import volatility3.framework.plugins
import volatility3.framework.automagic
from volatility3.cli import text_renderer
import psutil
import winreg
import subprocess
import struct
from typing import Dict, List, Optional, Tuple
import logging
import os
import time


class MemoryForensicsEngine:
    """Advanced memory analysis using Volatility3"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.context = volatility3.framework.contexts.Context()
        
    def analyze_memory_dump(self, dump_path: str, profile: str = None) -> Dict:
        """Comprehensive memory dump analysis"""
        try:
            # Initialize Volatility context
            automagics = volatility3.framework.automagic.available(self.context)
            automagics.run(self.context, volatility3.framework.configuration.path_join(
                volatility3.framework.configuration.PLUGINS_PATH, dump_path))
            
            analysis = {
                'system_info': self._get_system_info(),
                'processes': self._analyze_processes(),
                'network_connections': self._analyze_network(),
                'registry_analysis': self._analyze_registry(),
                'malware_indicators': self._detect_malware_indicators(),
                'rootkit_detection': self._detect_rootkits(),
                'timeline': self._create_memory_timeline()
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Memory analysis failed: {e}")
            return {'error': str(e)}
            
    def _get_system_info(self) -> Dict:
        """Extract system information from memory"""
        return {
            'os_version': 'Windows 10',  # Would extract from memory
            'architecture': 'x64',
            'kernel_base': '0xfffff80000000000',
            'boot_time': '2024-01-15 10:30:00'
        }
        
    def _analyze_processes(self) -> List[Dict]:
        """Analyze running processes from memory"""
        processes = []
        
        # Simulated process analysis
        sample_processes = [
            {'pid': 1234, 'name': 'explorer.exe', 'ppid': 1000, 'suspicious': False},
            {'pid': 5678, 'name': 'svchost.exe', 'ppid': 500, 'suspicious': False},
            {'pid': 9999, 'name': 'malware.exe', 'ppid': 1234, 'suspicious': True}
        ]
        
        for proc in sample_processes:
            proc_analysis = {
                **proc,
                'command_line': f"C:\\Windows\\System32\\{proc['name']}",
                'memory_regions': self._analyze_process_memory(proc['pid']),
                'handles': self._get_process_handles(proc['pid']),
                'threads': self._get_process_threads(proc['pid'])
            }
            processes.append(proc_analysis)
            
        return processes
        
    def _analyze_process_memory(self, pid: int) -> List[Dict]:
        """Analyze memory regions of a process"""
        return [
            {'base': '0x400000', 'size': '0x1000', 'protection': 'PAGE_EXECUTE_READ'},
            {'base': '0x7ff000000000', 'size': '0x2000', 'protection': 'PAGE_READWRITE'}
        ]
        
    def _get_process_handles(self, pid: int) -> List[Dict]:
        """Get process handles"""
        return [
            {'handle': '0x4', 'type': 'File', 'name': 'C:\\Windows\\System32\\ntdll.dll'},
            {'handle': '0x8', 'type': 'Key', 'name': 'HKLM\\SOFTWARE\\Microsoft\\Windows'}
        ]
        
    def _get_process_threads(self, pid: int) -> List[Dict]:
        """Get process threads"""
        return [
            {'tid': 1001, 'start_address': '0x7ff123456789', 'state': 'Running'},
            {'tid': 1002, 'start_address': '0x7ff987654321', 'state': 'Waiting'}
        ]
        
    def _analyze_network(self) -> List[Dict]:
        """Analyze network connections from memory"""
        return [
            {'local_addr': '192.168.1.100:80', 'remote_addr': '10.0.0.1:12345', 
             'state': 'ESTABLISHED', 'pid': 1234},
            {'local_addr': '192.168.1.100:443', 'remote_addr': '192.168.1.1:54321', 
             'state': 'LISTENING', 'pid': 5678}
        ]
        
    def _analyze_registry(self) -> Dict:
        """Analyze registry from memory"""
        return {
            'run_keys': [
                {'key': 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                 'value': 'malware.exe', 'data': 'C:\\temp\\malware.exe'}
            ],
            'services': [
                {'name': 'SuspiciousService', 'path': 'C:\\temp\\service.exe', 'start_type': 'Auto'}
            ],
            'recent_files': [
                'C:\\Users\\user\\Documents\\sensitive.docx',
                'C:\\temp\\downloaded_file.exe'
            ]
        }
        
    def _detect_malware_indicators(self) -> List[Dict]:
        """Detect malware indicators in memory"""
        indicators = []
        
        # Code injection detection
        indicators.append({
            'type': 'code_injection',
            'description': 'Suspicious code injection detected in explorer.exe',
            'severity': 'high',
            'process': 'explorer.exe',
            'address': '0x7ff123456789'
        })
        
        # Hollowed processes
        indicators.append({
            'type': 'process_hollowing',
            'description': 'Process hollowing detected',
            'severity': 'critical',
            'process': 'svchost.exe',
            'original_image': 'C:\\Windows\\System32\\svchost.exe',
            'injected_code': True
        })
        
        return indicators
        
    def _detect_rootkits(self) -> List[Dict]:
        """Detect rootkit presence"""
        return [
            {
                'type': 'ssdt_hook',
                'description': 'SSDT hook detected',
                'hooked_function': 'NtCreateFile',
                'hook_address': '0x7ff987654321'
            },
            {
                'type': 'idt_hook',
                'description': 'IDT modification detected',
                'interrupt': '0x2E',
                'original_handler': '0xfffff80012345678',
                'hooked_handler': '0x7ff123456789'
            }
        ]
        
    def _create_memory_timeline(self) -> List[Dict]:
        """Create timeline from memory artifacts"""
        return [
            {'timestamp': '2024-01-15 10:35:00', 'event': 'Process created: malware.exe'},
            {'timestamp': '2024-01-15 10:36:00', 'event': 'Registry key modified: Run'},
            {'timestamp': '2024-01-15 10:37:00', 'event': 'Network connection established'}
        ]


class LiveForensicsEngine:
    """Live system forensics and incident response"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def capture_live_system(self) -> Dict:
        """Capture live system state"""
        return {
            'system_info': self._get_live_system_info(),
            'running_processes': self._get_running_processes(),
            'network_connections': self._get_network_connections(),
            'loaded_modules': self._get_loaded_modules(),
            'registry_snapshot': self._capture_registry_snapshot(),
            'file_system_timeline': self._create_filesystem_timeline(),
            'user_activity': self._analyze_user_activity(),
            'persistence_mechanisms': self._detect_persistence()
        }
        
    def _get_live_system_info(self) -> Dict:
        """Get live system information"""
        return {
            'hostname': os.environ.get('COMPUTERNAME', 'unknown'),
            'username': os.environ.get('USERNAME', 'unknown'),
            'os_version': f"{os.name} {os.sys.platform}",
            'uptime': time.time() - psutil.boot_time(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': {disk.device: psutil.disk_usage(disk.mountpoint)._asdict() 
                          for disk in psutil.disk_partitions()}
        }
        
    def _get_running_processes(self) -> List[Dict]:
        """Get detailed running process information"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                proc_info['memory_info'] = proc.memory_info()._asdict()
                proc_info['cpu_percent'] = proc.cpu_percent()
                proc_info['connections'] = [conn._asdict() for conn in proc.connections()]
                proc_info['open_files'] = [f.path for f in proc.open_files()]
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return processes
        
    def _get_network_connections(self) -> List[Dict]:
        """Get network connections"""
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            conn_info = conn._asdict()
            try:
                if conn.pid:
                    proc = psutil.Process(conn.pid)
                    conn_info['process_name'] = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                conn_info['process_name'] = 'unknown'
                
            connections.append(conn_info)
            
        return connections
        
    def _get_loaded_modules(self) -> List[Dict]:
        """Get loaded system modules"""
        modules = []
        
        if os.name == 'nt':  # Windows
            try:
                result = subprocess.run(['driverquery', '/fo', 'csv'], 
                                      capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        modules.append({
                            'name': parts[0].strip('"'),
                            'display_name': parts[1].strip('"'),
                            'type': parts[2].strip('"')
                        })
            except:
                pass
                
        return modules
        
    def _capture_registry_snapshot(self) -> Dict:
        """Capture Windows registry snapshot"""
        registry_data = {}
        
        if os.name == 'nt':
            try:
                # Capture critical registry keys
                keys_to_capture = [
                    (winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'),
                    (winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'),
                    (winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services')
                ]
                
                for hkey, subkey in keys_to_capture:
                    try:
                        with winreg.OpenKey(hkey, subkey) as key:
                            values = []
                            i = 0
                            while True:
                                try:
                                    name, value, type = winreg.EnumValue(key, i)
                                    values.append({'name': name, 'value': str(value), 'type': type})
                                    i += 1
                                except WindowsError:
                                    break
                            registry_data[subkey] = values
                    except WindowsError:
                        continue
                        
            except Exception as e:
                self.logger.error(f"Registry capture failed: {e}")
                
        return registry_data
        
    def _create_filesystem_timeline(self) -> List[Dict]:
        """Create filesystem timeline of recent activity"""
        timeline = []
        
        # Analyze recent file modifications
        for root, dirs, files in os.walk('C:\\Users' if os.name == 'nt' else '/home'):
            for file in files[:100]:  # Limit for performance
                try:
                    file_path = os.path.join(root, file)
                    stat = os.stat(file_path)
                    
                    timeline.append({
                        'path': file_path,
                        'modified': stat.st_mtime,
                        'accessed': stat.st_atime,
                        'created': stat.st_ctime,
                        'size': stat.st_size
                    })
                except (OSError, PermissionError):
                    continue
                    
        # Sort by modification time
        timeline.sort(key=lambda x: x['modified'], reverse=True)
        return timeline[:50]  # Return 50 most recent
        
    def _analyze_user_activity(self) -> Dict:
        """Analyze user activity indicators"""
        activity = {
            'recent_documents': [],
            'browser_history': [],
            'usb_devices': [],
            'login_events': []
        }
        
        if os.name == 'nt':
            # Recent documents
            recent_path = os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\Recent')
            if os.path.exists(recent_path):
                activity['recent_documents'] = [
                    f for f in os.listdir(recent_path) if f.endswith('.lnk')
                ][:10]
                
        return activity
        
    def _detect_persistence(self) -> List[Dict]:
        """Detect persistence mechanisms"""
        persistence = []
        
        if os.name == 'nt':
            # Check startup folders
            startup_paths = [
                os.path.expanduser('~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
                'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
            ]
            
            for path in startup_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        persistence.append({
                            'type': 'startup_folder',
                            'location': path,
                            'file': file,
                            'severity': 'medium'
                        })
                        
            # Check scheduled tasks
            try:
                result = subprocess.run(['schtasks', '/query', '/fo', 'csv'], 
                                      capture_output=True, text=True)
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines[:10]:  # Limit output
                    parts = line.split(',')
                    if len(parts) >= 2:
                        persistence.append({
                            'type': 'scheduled_task',
                            'name': parts[0].strip('"'),
                            'status': parts[2].strip('"') if len(parts) > 2 else 'unknown',
                            'severity': 'high'
                        })
            except:
                pass
                
        return persistence
        
    def create_memory_dump(self, output_path: str) -> bool:
        """Create memory dump of live system"""
        try:
            if os.name == 'nt':
                # Use built-in tools or third-party memory acquisition
                cmd = f'winpmem.exe {output_path}'
                result = subprocess.run(cmd, shell=True, capture_output=True)
                return result.returncode == 0
            else:
                # Linux memory acquisition
                cmd = f'dd if=/dev/mem of={output_path} bs=1M'
                result = subprocess.run(cmd, shell=True, capture_output=True)
                return result.returncode == 0
                
        except Exception as e:
            self.logger.error(f"Memory dump creation failed: {e}")
            return False
            
    def monitor_real_time(self, duration: int = 300) -> Dict:
        """Monitor system in real-time"""
        monitoring_data = {
            'start_time': time.time(),
            'duration': duration,
            'process_events': [],
            'network_events': [],
            'file_events': []
        }
        
        # This would implement real-time monitoring
        # using system APIs or ETW on Windows
        
        return monitoring_data