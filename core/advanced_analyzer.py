"""
Advanced File System Analyzer
Enhanced support for multiple file systems and deleted file detection
"""

import struct
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .filesystem_analyzer import FileSystemAnalyzer


class AdvancedFileSystemAnalyzer(FileSystemAnalyzer):
    """Enhanced file system analyzer with advanced features"""
    
    # Extended file system signatures
    EXTENDED_FS_SIGNATURES = {
        **FileSystemAnalyzer.FS_SIGNATURES,
        'APFS': (b'NXSB', 0x20),
        'HFS+': (b'H+', 0x400),
        'XFS': (b'XFSB', 0x00),
        'BTRFS': (b'_BHRfS_M', 0x10040),
        'ZFS': (b'\x0c\xb1\xba\x00', 0x00),
        'ReFS': (b'\x00\x00\x00ReFS\x00\x00', 0x00),
    }
    
    def __init__(self):
        super().__init__()
        self.FS_SIGNATURES = self.EXTENDED_FS_SIGNATURES
        
    def analyze_deleted_entries(self, image_path: str) -> List[Dict]:
        """Analyze and find deleted file entries"""
        self.logger.info("Analyzing deleted file entries")
        
        fs_type = self._detect_filesystem(image_path)
        deleted_entries = []
        
        if fs_type == 'NTFS':
            deleted_entries = self._find_deleted_ntfs_entries(image_path)
        elif fs_type.startswith('FAT'):
            deleted_entries = self._find_deleted_fat_entries(image_path)
        elif fs_type.startswith('EXT'):
            deleted_entries = self._find_deleted_ext_entries(image_path)
            
        return deleted_entries
        
    def _find_deleted_ntfs_entries(self, image_path: str) -> List[Dict]:
        """Find deleted NTFS file entries"""
        deleted_files = []
        
        with open(image_path, 'rb') as f:
            # Get MFT location from boot sector
            boot_sector = f.read(512)
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            sectors_per_cluster = struct.unpack('<B', boot_sector[0x0D:0x0E])[0]
            mft_cluster = struct.unpack('<Q', boot_sector[0x30:0x38])[0]
            
            mft_offset = mft_cluster * sectors_per_cluster * bytes_per_sector
            f.seek(mft_offset)
            
            # Read MFT entries (each is 1024 bytes typically)
            mft_entry_size = 1024
            entry_num = 0
            
            while entry_num < 1000:  # Limit for demo
                entry_data = f.read(mft_entry_size)
                if len(entry_data) < mft_entry_size:
                    break
                    
                # Check if entry is deleted (signature + flags)
                if entry_data[:4] == b'FILE':
                    flags = struct.unpack('<H', entry_data[0x16:0x18])[0]
                    if flags & 0x01 == 0:  # Not in use (deleted)
                        # Parse filename attribute
                        filename = self._extract_ntfs_filename(entry_data)
                        if filename:
                            deleted_files.append({
                                'entry_number': entry_num,
                                'filename': filename,
                                'type': 'NTFS Deleted Entry',
                                'offset': mft_offset + (entry_num * mft_entry_size)
                            })
                            
                entry_num += 1
                
        return deleted_files
        
    def _extract_ntfs_filename(self, mft_entry: bytes) -> Optional[str]:
        """Extract filename from NTFS MFT entry"""
        try:
            # Look for filename attribute (0x30)
            offset = 0x38  # Start of attributes
            while offset < len(mft_entry) - 4:
                attr_type = struct.unpack('<I', mft_entry[offset:offset+4])[0]
                if attr_type == 0x30:  # Filename attribute
                    attr_length = struct.unpack('<I', mft_entry[offset+4:offset+8])[0]
                    if attr_length > 0 and offset + attr_length <= len(mft_entry):
                        # Extract filename (Unicode)
                        name_offset = offset + 0x5A
                        name_length = mft_entry[offset + 0x58] * 2
                        if name_offset + name_length <= len(mft_entry):
                            filename_bytes = mft_entry[name_offset:name_offset + name_length]
                            return filename_bytes.decode('utf-16le', errors='ignore')
                elif attr_type == 0xFFFFFFFF:
                    break
                    
                # Move to next attribute
                attr_length = struct.unpack('<I', mft_entry[offset+4:offset+8])[0]
                if attr_length == 0:
                    break
                offset += attr_length
                
        except:
            pass
            
        return None
        
    def _find_deleted_fat_entries(self, image_path: str) -> List[Dict]:
        """Find deleted FAT file entries"""
        deleted_files = []
        
        with open(image_path, 'rb') as f:
            # Parse FAT boot sector to find root directory
            boot_sector = f.read(512)
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            sectors_per_cluster = struct.unpack('<B', boot_sector[0x0D:0x0E])[0]
            reserved_sectors = struct.unpack('<H', boot_sector[0x0E:0x10])[0]
            num_fats = struct.unpack('<B', boot_sector[0x10:0x11])[0]
            root_entries = struct.unpack('<H', boot_sector[0x11:0x13])[0]
            
            # Calculate root directory offset
            if root_entries > 0:  # FAT12/16
                sectors_per_fat = struct.unpack('<H', boot_sector[0x16:0x18])[0]
                root_dir_offset = (reserved_sectors + (num_fats * sectors_per_fat)) * bytes_per_sector
                
                f.seek(root_dir_offset)
                
                # Read directory entries (32 bytes each)
                for i in range(root_entries):
                    entry = f.read(32)
                    if len(entry) < 32:
                        break
                        
                    # Check for deleted entry (first byte = 0xE5)
                    if entry[0] == 0xE5:
                        # Extract filename
                        filename = entry[1:11].decode('ascii', errors='ignore').strip()
                        if filename:
                            deleted_files.append({
                                'entry_number': i,
                                'filename': filename,
                                'type': 'FAT Deleted Entry',
                                'offset': root_dir_offset + (i * 32)
                            })
                            
        return deleted_files
        
    def _find_deleted_ext_entries(self, image_path: str) -> List[Dict]:
        """Find deleted EXT file entries (simplified)"""
        deleted_files = []
        
        # EXT deleted file recovery is complex and typically requires
        # parsing inode tables and directory blocks
        # This is a simplified implementation
        
        with open(image_path, 'rb') as f:
            # Skip to superblock
            f.seek(1024)
            superblock = f.read(1024)
            
            # Get basic info
            total_inodes = struct.unpack('<I', superblock[0x00:0x04])[0]
            block_size = 1024 << struct.unpack('<I', superblock[0x18:0x1C])[0]
            
            # This would require extensive EXT parsing
            # For now, return placeholder
            deleted_files.append({
                'entry_number': 0,
                'filename': 'EXT_deleted_analysis_requires_advanced_parsing',
                'type': 'EXT Analysis Placeholder',
                'offset': 1024
            })
            
        return deleted_files
        
    def analyze_file_slack(self, image_path: str) -> Dict:
        """Analyze file slack space for hidden data"""
        self.logger.info("Analyzing file slack space")
        
        fs_type = self._detect_filesystem(image_path)
        slack_analysis = {
            'fs_type': fs_type,
            'total_slack_bytes': 0,
            'slack_locations': [],
            'potential_data_found': False
        }
        
        # Implementation would depend on file system type
        # This is a framework for slack space analysis
        
        return slack_analysis
        
    def detect_encryption(self, image_path: str) -> Dict:
        """Detect encrypted volumes and containers"""
        encryption_info = {
            'encrypted_volumes': [],
            'encryption_types': [],
            'bitlocker_detected': False,
            'truecrypt_detected': False,
            'luks_detected': False
        }
        
        with open(image_path, 'rb') as f:
            # Check for BitLocker signature
            f.seek(0x03)
            if f.read(8) == b'-FVE-FS-':
                encryption_info['bitlocker_detected'] = True
                encryption_info['encryption_types'].append('BitLocker')
                
            # Check for TrueCrypt/VeraCrypt signature
            f.seek(0x00)
            header = f.read(512)
            if b'TRUE' in header or b'VERA' in header:
                encryption_info['truecrypt_detected'] = True
                encryption_info['encryption_types'].append('TrueCrypt/VeraCrypt')
                
            # Check for LUKS signature
            f.seek(0x00)
            if f.read(6) == b'LUKS\xba\xbe':
                encryption_info['luks_detected'] = True
                encryption_info['encryption_types'].append('LUKS')
                
        return encryption_info