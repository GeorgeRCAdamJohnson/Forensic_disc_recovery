"""
Enhanced Recovery Engine
Advanced file recovery with timeline analysis and metadata extraction
"""

import os
import struct
import logging
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from datetime import datetime
import json
from .recovery_engine import RecoveryEngine


class EnhancedRecoveryEngine(RecoveryEngine):
    """Enhanced recovery engine with advanced features"""
    
    # Extended file signatures with metadata extraction
    EXTENDED_SIGNATURES = {
        **RecoveryEngine.FILE_SIGNATURES,
        'sqlite': {
            'header': b'SQLite format 3\x00',
            'footer': None,
            'extension': '.db',
            'max_size': 100 * 1024 * 1024,
            'extract_metadata': True
        },
        'pst': {
            'header': b'!BDN',
            'footer': None,
            'extension': '.pst',
            'max_size': 2 * 1024 * 1024 * 1024,  # 2GB
            'extract_metadata': True
        },
        'registry': {
            'header': b'regf',
            'footer': None,
            'extension': '.reg',
            'max_size': 100 * 1024 * 1024,
            'extract_metadata': True
        },
        'lnk': {
            'header': b'L\x00\x00\x00\x01\x14\x02\x00',
            'footer': None,
            'extension': '.lnk',
            'max_size': 1024 * 1024,
            'extract_metadata': True
        }
    }
    
    def __init__(self):
        super().__init__()
        self.FILE_SIGNATURES.update(self.EXTENDED_SIGNATURES)
        self.timeline_events = []
        
    def recover_with_timeline(self, image_path: str, output_dir: str, 
                            file_types: Optional[List[str]] = None) -> Dict:
        """Recover files and build timeline"""
        self.logger.info("Starting recovery with timeline analysis")
        
        recovery_stats = {
            'files_recovered': 0,
            'timeline_events': [],
            'metadata_extracted': {},
            'file_types': {}
        }
        
        # Perform standard recovery
        recovered_count = self.recover_deleted(image_path, output_dir, file_types)
        recovery_stats['files_recovered'] = recovered_count
        
        # Analyze recovered files for timeline
        timeline_events = self._build_timeline(output_dir)
        recovery_stats['timeline_events'] = timeline_events
        
        # Extract metadata from recovered files
        metadata = self._extract_metadata_batch(output_dir)
        recovery_stats['metadata_extracted'] = metadata
        
        return recovery_stats
        
    def _build_timeline(self, recovery_dir: str) -> List[Dict]:
        """Build timeline from recovered files"""
        timeline = []
        recovery_path = Path(recovery_dir)
        
        for file_path in recovery_path.rglob('*'):
            if file_path.is_file():
                try:
                    stat = file_path.stat()
                    
                    # Add file system timestamps
                    timeline.append({
                        'timestamp': datetime.fromtimestamp(stat.st_ctime),
                        'event_type': 'File Created',
                        'file_path': str(file_path),
                        'file_size': stat.st_size,
                        'source': 'filesystem'
                    })
                    
                    timeline.append({
                        'timestamp': datetime.fromtimestamp(stat.st_mtime),
                        'event_type': 'File Modified',
                        'file_path': str(file_path),
                        'file_size': stat.st_size,
                        'source': 'filesystem'
                    })
                    
                    # Extract embedded timestamps
                    embedded_timestamps = self._extract_embedded_timestamps(file_path)
                    timeline.extend(embedded_timestamps)
                    
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {e}")
                    
        # Sort timeline by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        return timeline
        
    def _extract_embedded_timestamps(self, file_path: Path) -> List[Dict]:
        """Extract timestamps embedded in file content"""
        timestamps = []
        
        try:
            if file_path.suffix.lower() == '.jpg':
                timestamps.extend(self._extract_exif_timestamps(file_path))
            elif file_path.suffix.lower() == '.pdf':
                timestamps.extend(self._extract_pdf_timestamps(file_path))
            elif file_path.suffix.lower() in ['.docx', '.xlsx']:
                timestamps.extend(self._extract_office_timestamps(file_path))
                
        except Exception as e:
            self.logger.debug(f"Error extracting timestamps from {file_path}: {e}")
            
        return timestamps
        
    def _extract_exif_timestamps(self, file_path: Path) -> List[Dict]:
        """Extract EXIF timestamps from JPEG files"""
        timestamps = []
        
        try:
            with open(file_path, 'rb') as f:
                # Look for EXIF data
                data = f.read()
                exif_start = data.find(b'\xff\xe1')
                
                if exif_start != -1:
                    # Simple EXIF parsing for DateTime
                    datetime_tag = data.find(b'DateTime\x00', exif_start)
                    if datetime_tag != -1:
                        # Extract datetime string (simplified)
                        dt_start = datetime_tag + 9
                        dt_str = data[dt_start:dt_start+19].decode('ascii', errors='ignore')
                        
                        try:
                            dt = datetime.strptime(dt_str, '%Y:%m:%d %H:%M:%S')
                            timestamps.append({
                                'timestamp': dt,
                                'event_type': 'Photo Taken',
                                'file_path': str(file_path),
                                'source': 'exif'
                            })
                        except:
                            pass
                            
        except Exception as e:
            self.logger.debug(f"EXIF extraction error: {e}")
            
        return timestamps
        
    def _extract_pdf_timestamps(self, file_path: Path) -> List[Dict]:
        """Extract timestamps from PDF metadata"""
        timestamps = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(10000, os.path.getsize(file_path)))  # Read first 10KB
                
                # Look for creation date
                creation_match = data.find(b'/CreationDate')
                if creation_match != -1:
                    # Extract date string (simplified)
                    date_start = data.find(b'(D:', creation_match)
                    if date_start != -1:
                        date_end = data.find(b')', date_start)
                        if date_end != -1:
                            date_str = data[date_start+3:date_end].decode('ascii', errors='ignore')
                            # Parse PDF date format: YYYYMMDDHHmmSSOHH'mm'
                            if len(date_str) >= 14:
                                try:
                                    dt = datetime.strptime(date_str[:14], '%Y%m%d%H%M%S')
                                    timestamps.append({
                                        'timestamp': dt,
                                        'event_type': 'PDF Created',
                                        'file_path': str(file_path),
                                        'source': 'pdf_metadata'
                                    })
                                except:
                                    pass
                                    
        except Exception as e:
            self.logger.debug(f"PDF timestamp extraction error: {e}")
            
        return timestamps
        
    def _extract_office_timestamps(self, file_path: Path) -> List[Dict]:
        """Extract timestamps from Office documents"""
        timestamps = []
        
        # Office documents are ZIP files with XML metadata
        try:
            import zipfile
            
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Look for core properties
                if 'docProps/core.xml' in zf.namelist():
                    core_xml = zf.read('docProps/core.xml').decode('utf-8', errors='ignore')
                    
                    # Simple XML parsing for timestamps
                    if '<dcterms:created' in core_xml:
                        start = core_xml.find('<dcterms:created')
                        end = core_xml.find('</dcterms:created>', start)
                        if start != -1 and end != -1:
                            created_section = core_xml[start:end]
                            # Extract ISO timestamp
                            ts_start = created_section.find('>') + 1
                            timestamp_str = created_section[ts_start:].strip()
                            
                            try:
                                # Parse ISO format
                                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                                timestamps.append({
                                    'timestamp': dt,
                                    'event_type': 'Document Created',
                                    'file_path': str(file_path),
                                    'source': 'office_metadata'
                                })
                            except:
                                pass
                                
        except Exception as e:
            self.logger.debug(f"Office timestamp extraction error: {e}")
            
        return timestamps
        
    def _extract_metadata_batch(self, recovery_dir: str) -> Dict:
        """Extract metadata from all recovered files"""
        metadata = {}
        recovery_path = Path(recovery_dir)
        
        for file_path in recovery_path.rglob('*'):
            if file_path.is_file():
                try:
                    file_metadata = self._extract_file_metadata(file_path)
                    if file_metadata:
                        metadata[str(file_path)] = file_metadata
                except Exception as e:
                    self.logger.debug(f"Metadata extraction error for {file_path}: {e}")
                    
        return metadata
        
    def _extract_file_metadata(self, file_path: Path) -> Optional[Dict]:
        """Extract metadata from a single file"""
        metadata = {
            'file_size': file_path.stat().st_size,
            'file_extension': file_path.suffix.lower(),
            'created': datetime.fromtimestamp(file_path.stat().st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        }
        
        # File-specific metadata extraction
        if file_path.suffix.lower() == '.lnk':
            metadata.update(self._extract_lnk_metadata(file_path))
        elif file_path.suffix.lower() == '.db':
            metadata.update(self._extract_sqlite_metadata(file_path))
            
        return metadata
        
    def _extract_lnk_metadata(self, file_path: Path) -> Dict:
        """Extract metadata from Windows LNK files"""
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Read LNK header
                header = f.read(76)
                
                if len(header) >= 76 and header[:4] == b'L\x00\x00\x00':
                    # Extract target file attributes
                    file_attributes = struct.unpack('<I', header[24:28])[0]
                    creation_time = struct.unpack('<Q', header[28:36])[0]
                    access_time = struct.unpack('<Q', header[36:44])[0]
                    write_time = struct.unpack('<Q', header[44:52])[0]
                    
                    # Convert Windows FILETIME to datetime
                    if creation_time > 0:
                        metadata['target_created'] = self._filetime_to_datetime(creation_time)
                    if access_time > 0:
                        metadata['target_accessed'] = self._filetime_to_datetime(access_time)
                    if write_time > 0:
                        metadata['target_modified'] = self._filetime_to_datetime(write_time)
                        
                    metadata['file_attributes'] = hex(file_attributes)
                    
        except Exception as e:
            self.logger.debug(f"LNK metadata extraction error: {e}")
            
        return metadata
        
    def _extract_sqlite_metadata(self, file_path: Path) -> Dict:
        """Extract metadata from SQLite databases"""
        metadata = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Read SQLite header
                header = f.read(100)
                
                if header[:16] == b'SQLite format 3\x00':
                    # Extract database info
                    page_size = struct.unpack('>H', header[16:18])[0]
                    if page_size == 1:
                        page_size = 65536
                        
                    metadata['sqlite_version'] = header[:16].decode('ascii', errors='ignore')
                    metadata['page_size'] = page_size
                    metadata['database_size_pages'] = struct.unpack('>I', header[28:32])[0]
                    
        except Exception as e:
            self.logger.debug(f"SQLite metadata extraction error: {e}")
            
        return metadata
        
    def _filetime_to_datetime(self, filetime: int) -> str:
        """Convert Windows FILETIME to datetime string"""
        try:
            # FILETIME is 100-nanosecond intervals since January 1, 1601
            timestamp = (filetime - 116444736000000000) / 10000000
            return datetime.fromtimestamp(timestamp).isoformat()
        except:
            return "Invalid timestamp"
            
    def generate_timeline_report(self, timeline_events: List[Dict], output_path: str):
        """Generate timeline report"""
        timeline_html = """
<!DOCTYPE html>
<html>
<head>
    <title>Forensic Timeline Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .timeline-event { 
            border-left: 3px solid #3498db; 
            padding: 10px; 
            margin: 10px 0; 
            background: #f8f9fa; 
        }
        .timestamp { font-weight: bold; color: #2c3e50; }
        .event-type { color: #e74c3c; font-weight: bold; }
        .file-path { color: #27ae60; font-family: monospace; }
    </style>
</head>
<body>
    <h1>Forensic Timeline Analysis</h1>
    <p>Generated: {}</p>
    <p>Total Events: {}</p>
""".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), len(timeline_events))
        
        for event in timeline_events:
            timeline_html += f"""
    <div class="timeline-event">
        <div class="timestamp">{event['timestamp']}</div>
        <div class="event-type">{event['event_type']}</div>
        <div class="file-path">{event['file_path']}</div>
        <div>Source: {event['source']}</div>
    </div>
"""
        
        timeline_html += """
</body>
</html>
"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(timeline_html)
            
        self.logger.info(f"Timeline report saved to: {output_path}")