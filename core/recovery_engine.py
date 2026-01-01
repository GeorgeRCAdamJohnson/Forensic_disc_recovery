"""
Recovery Engine Module
Handles file recovery and data carving operations
"""

import os
import struct
import logging
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from datetime import datetime


class RecoveryEngine:
    """Engine for recovering deleted files and carving data"""
    
    # File signatures for data carving
    FILE_SIGNATURES = {
        'jpeg': {
            'header': b'\xFF\xD8\xFF',
            'footer': b'\xFF\xD9',
            'extension': '.jpg',
            'max_size': 10 * 1024 * 1024  # 10MB
        },
        'png': {
            'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
            'extension': '.png',
            'max_size': 10 * 1024 * 1024
        },
        'pdf': {
            'header': b'%PDF-',
            'footer': b'%%EOF',
            'extension': '.pdf',
            'max_size': 50 * 1024 * 1024  # 50MB
        },
        'zip': {
            'header': b'PK\x03\x04',
            'footer': b'PK\x05\x06',
            'extension': '.zip',
            'max_size': 100 * 1024 * 1024  # 100MB
        },
        'docx': {
            'header': b'PK\x03\x04',
            'footer': None,
            'extension': '.docx',
            'max_size': 50 * 1024 * 1024
        },
        'xlsx': {
            'header': b'PK\x03\x04',
            'footer': None,
            'extension': '.xlsx',
            'max_size': 50 * 1024 * 1024
        },
        'mp4': {
            'header': b'\x00\x00\x00\x18\x66\x74\x79\x70',
            'footer': None,
            'extension': '.mp4',
            'max_size': 500 * 1024 * 1024  # 500MB
        },
        'avi': {
            'header': b'RIFF',
            'footer': None,
            'extension': '.avi',
            'max_size': 500 * 1024 * 1024
        },
    }
    
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks for reading
    
    def __init__(self):
        """Initialize recovery engine"""
        self.logger = logging.getLogger(__name__)
        self.recovered_count = 0
        
    def recover_deleted(self, image_path: str, output_dir: str, 
                       file_types: Optional[List[str]] = None) -> int:
        """
        Recover deleted files from a disc image
        
        Args:
            image_path: Path to the disc image
            output_dir: Directory to save recovered files
            file_types: List of file extensions to recover (e.g., ['jpg', 'pdf'])
            
        Returns:
            Number of files recovered
        """
        self.logger.info(f"Starting deleted file recovery from {image_path}")
        
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
            
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Use data carving as the primary recovery method
        signatures = file_types if file_types else list(self.FILE_SIGNATURES.keys())
        recovered = self.carve_data(image_path, output_dir, signatures)
        
        return recovered
        
    def carve_data(self, image_path: str, output_dir: str, 
                   signatures: List[str]) -> int:
        """
        Perform data carving to recover files by signature matching
        
        Args:
            image_path: Path to the disc image
            output_dir: Directory to save carved files
            signatures: List of file types to carve (e.g., ['jpeg', 'pdf'])
            
        Returns:
            Number of files carved
        """
        self.logger.info(f"Starting data carving: {', '.join(signatures)}")
        
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
            
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        carved_count = 0
        image_size = os.path.getsize(image_path)
        
        # Filter valid signatures
        sig_configs = {}
        for sig in signatures:
            if sig.lower() in self.FILE_SIGNATURES:
                sig_configs[sig.lower()] = self.FILE_SIGNATURES[sig.lower()]
            else:
                self.logger.warning(f"Unknown signature: {sig}")
                
        if not sig_configs:
            self.logger.error("No valid signatures to search for")
            return 0
            
        with open(image_path, 'rb') as f:
            position = 0
            buffer = b''
            
            while position < image_size:
                # Read chunk
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                    
                buffer += chunk
                offset = 0
                
                # Search for signatures in buffer
                for sig_name, sig_config in sig_configs.items():
                    header = sig_config['header']
                    
                    while True:
                        idx = buffer.find(header, offset)
                        if idx == -1:
                            break
                            
                        # Found potential file
                        file_position = position + idx
                        self.logger.debug(f"Found {sig_name} signature at offset {file_position}")
                        
                        # Try to carve the file
                        carved_file = self._carve_file(
                            f, file_position, sig_config, 
                            output_path, sig_name, carved_count
                        )
                        
                        if carved_file:
                            carved_count += 1
                            self.logger.info(f"Carved file {carved_count}: {carved_file}")
                            
                        offset = idx + len(header)
                        
                # Keep last part of buffer for signatures spanning chunks
                buffer = buffer[-max(len(sig['header']) for sig in sig_configs.values()):]
                position += len(chunk)
                
                # Progress logging
                if position % (100 * 1024 * 1024) == 0:
                    progress = (position / image_size) * 100
                    self.logger.info(f"Carving progress: {progress:.1f}% ({carved_count} files)")
                    
        self.logger.info(f"Data carving complete: {carved_count} files recovered")
        return carved_count
        
    def _carve_file(self, file_handle, start_pos: int, sig_config: Dict,
                   output_dir: Path, file_type: str, file_num: int) -> Optional[str]:
        """
        Carve a single file from the disc image
        
        Args:
            file_handle: Open file handle to the disc image
            start_pos: Starting position of the file
            sig_config: Signature configuration dictionary
            output_dir: Output directory for carved files
            file_type: Type of file being carved
            file_num: Sequential file number
            
        Returns:
            Path to carved file if successful, None otherwise
        """
        current_pos = file_handle.tell()
        file_handle.seek(start_pos)
        
        header = sig_config['header']
        footer = sig_config.get('footer')
        extension = sig_config['extension']
        max_size = sig_config['max_size']
        
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = output_dir / f"recovered_{file_type}_{timestamp}_{file_num}{extension}"
        
        try:
            with open(output_file, 'wb') as out:
                bytes_written = 0
                
                if footer:
                    # Search for footer
                    buffer = b''
                    while bytes_written < max_size:
                        chunk = file_handle.read(4096)
                        if not chunk:
                            break
                            
                        buffer += chunk
                        out.write(chunk)
                        bytes_written += len(chunk)
                        
                        # Check for footer
                        footer_idx = buffer.find(footer)
                        if footer_idx != -1:
                            # Found footer, truncate file
                            final_size = bytes_written - len(buffer) + footer_idx + len(footer)
                            out.truncate(final_size)
                            file_handle.seek(current_pos)
                            return str(output_file)
                            
                        # Keep last part for footer spanning chunks
                        if len(buffer) > len(footer) * 2:
                            buffer = buffer[-len(footer) * 2:]
                            
                    # No footer found within max_size
                    self.logger.debug(f"No footer found for {file_type} at {start_pos}")
                    os.remove(output_file)
                    file_handle.seek(current_pos)
                    return None
                else:
                    # No footer defined, use heuristics or max_size
                    # For formats like DOCX/XLSX (ZIP-based), try to read entire archive
                    if header == b'PK\x03\x04':
                        # ZIP format - read until end of central directory
                        carved = self._carve_zip_file(file_handle, out, max_size)
                        if carved:
                            file_handle.seek(current_pos)
                            return str(output_file)
                    else:
                        # Read max_size
                        data = file_handle.read(max_size)
                        out.write(data)
                        
                    file_handle.seek(current_pos)
                    return str(output_file)
                    
        except Exception as e:
            self.logger.error(f"Error carving file at {start_pos}: {e}")
            if output_file.exists():
                os.remove(output_file)
            file_handle.seek(current_pos)
            return None
            
    def _carve_zip_file(self, file_handle, output_handle, max_size: int) -> bool:
        """
        Carve a ZIP-based file (ZIP, DOCX, XLSX, etc.)
        
        Args:
            file_handle: Input file handle
            output_handle: Output file handle
            max_size: Maximum file size to read
            
        Returns:
            True if successful, False otherwise
        """
        try:
            bytes_read = 0
            
            while bytes_read < max_size:
                chunk = file_handle.read(4096)
                if not chunk:
                    break
                    
                output_handle.write(chunk)
                bytes_read += len(chunk)
                
                # Look for end of central directory signature
                if b'PK\x05\x06' in chunk:
                    # Found end marker, file is complete
                    return True
                    
            return bytes_read > 0
        except Exception as e:
            self.logger.error(f"Error carving ZIP file: {e}")
            return False
            
    def analyze_recovered_files(self, recovery_dir: str) -> Dict:
        """
        Analyze recovered files and generate statistics
        
        Args:
            recovery_dir: Directory containing recovered files
            
        Returns:
            Dictionary with recovery statistics
        """
        recovery_path = Path(recovery_dir)
        
        if not recovery_path.exists():
            return {'error': 'Recovery directory not found'}
            
        stats = {
            'total_files': 0,
            'total_size': 0,
            'file_types': {},
            'largest_file': None,
            'largest_size': 0,
        }
        
        for file_path in recovery_path.rglob('*'):
            if file_path.is_file():
                stats['total_files'] += 1
                size = file_path.stat().st_size
                stats['total_size'] += size
                
                # Track by extension
                ext = file_path.suffix.lower()
                if ext not in stats['file_types']:
                    stats['file_types'][ext] = {'count': 0, 'size': 0}
                stats['file_types'][ext]['count'] += 1
                stats['file_types'][ext]['size'] += size
                
                # Track largest file
                if size > stats['largest_size']:
                    stats['largest_size'] = size
                    stats['largest_file'] = str(file_path)
                    
        stats['total_size_mb'] = stats['total_size'] / (1024 * 1024)
        
        return stats
