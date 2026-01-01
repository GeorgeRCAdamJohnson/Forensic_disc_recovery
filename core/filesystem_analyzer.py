"""
File System Analyzer Module
Analyzes various file systems for forensic purposes
"""

import os
import struct
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path


class FileSystemAnalyzer:
    """Analyze file system structures for forensic investigation"""
    
    # File system signatures
    FS_SIGNATURES = {
        'NTFS': (b'NTFS    ', 0x03),
        'FAT32': (b'FAT32   ', 0x52),
        'FAT16': (b'FAT16   ', 0x36),
        'EXT4': (b'\x53\xEF', 0x438),
        'EXT3': (b'\x53\xEF', 0x438),
        'EXT2': (b'\x53\xEF', 0x438),
    }
    
    def __init__(self):
        """Initialize file system analyzer"""
        self.logger = logging.getLogger(__name__)
        
    def analyze(self, image_path: str) -> Dict:
        """
        Analyze the file system in a disc image
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            Dictionary containing file system analysis results
        """
        self.logger.info(f"Analyzing file system: {image_path}")
        
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
            
        fs_type = self._detect_filesystem(image_path)
        
        analysis = {
            'image_path': image_path,
            'fs_type': fs_type,
            'timestamp': datetime.now().isoformat(),
        }
        
        # Perform file system specific analysis
        if fs_type == 'NTFS':
            analysis.update(self._analyze_ntfs(image_path))
        elif fs_type.startswith('FAT'):
            analysis.update(self._analyze_fat(image_path))
        elif fs_type.startswith('EXT'):
            analysis.update(self._analyze_ext(image_path))
        else:
            self.logger.warning(f"Unsupported file system: {fs_type}")
            
        return analysis
        
    def _detect_filesystem(self, image_path: str) -> str:
        """
        Detect the file system type by checking signatures
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            File system type string
        """
        with open(image_path, 'rb') as f:
            # Read first 4KB to check signatures
            boot_sector = f.read(4096)
            
            for fs_name, (signature, offset) in self.FS_SIGNATURES.items():
                if len(boot_sector) > offset + len(signature):
                    if boot_sector[offset:offset + len(signature)] == signature:
                        self.logger.info(f"Detected file system: {fs_name}")
                        return fs_name
                        
        self.logger.warning("Unknown file system type")
        return "Unknown"
        
    def _analyze_ntfs(self, image_path: str) -> Dict:
        """
        Analyze NTFS file system
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            Dictionary with NTFS-specific information
        """
        self.logger.info("Performing NTFS analysis")
        
        info = {}
        
        with open(image_path, 'rb') as f:
            # Read NTFS boot sector
            boot_sector = f.read(512)
            
            # Parse NTFS BPB (BIOS Parameter Block)
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            sectors_per_cluster = struct.unpack('<B', boot_sector[0x0D:0x0E])[0]
            total_sectors = struct.unpack('<Q', boot_sector[0x28:0x30])[0]
            mft_cluster = struct.unpack('<Q', boot_sector[0x30:0x38])[0]
            
            info['bytes_per_sector'] = bytes_per_sector
            info['sectors_per_cluster'] = sectors_per_cluster
            info['cluster_size'] = bytes_per_sector * sectors_per_cluster
            info['total_sectors'] = total_sectors
            info['total_size'] = total_sectors * bytes_per_sector
            info['mft_cluster'] = mft_cluster
            info['mft_offset'] = mft_cluster * sectors_per_cluster * bytes_per_sector
            
            # Extract volume serial number
            volume_serial = boot_sector[0x48:0x50]
            info['volume_serial'] = volume_serial.hex().upper()
            
        return info
        
    def _analyze_fat(self, image_path: str) -> Dict:
        """
        Analyze FAT file system
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            Dictionary with FAT-specific information
        """
        self.logger.info("Performing FAT analysis")
        
        info = {}
        
        with open(image_path, 'rb') as f:
            # Read FAT boot sector
            boot_sector = f.read(512)
            
            # Parse FAT BPB
            bytes_per_sector = struct.unpack('<H', boot_sector[0x0B:0x0D])[0]
            sectors_per_cluster = struct.unpack('<B', boot_sector[0x0D:0x0E])[0]
            reserved_sectors = struct.unpack('<H', boot_sector[0x0E:0x10])[0]
            num_fats = struct.unpack('<B', boot_sector[0x10:0x11])[0]
            
            info['bytes_per_sector'] = bytes_per_sector
            info['sectors_per_cluster'] = sectors_per_cluster
            info['cluster_size'] = bytes_per_sector * sectors_per_cluster
            info['reserved_sectors'] = reserved_sectors
            info['number_of_fats'] = num_fats
            
            # FAT32 specific
            if boot_sector[0x52:0x5A] == b'FAT32   ':
                sectors_per_fat = struct.unpack('<I', boot_sector[0x24:0x28])[0]
                root_cluster = struct.unpack('<I', boot_sector[0x2C:0x30])[0]
                info['sectors_per_fat'] = sectors_per_fat
                info['root_cluster'] = root_cluster
                
                # Volume serial
                volume_serial = boot_sector[0x43:0x47]
                info['volume_serial'] = struct.unpack('<I', volume_serial)[0]
                
        return info
        
    def _analyze_ext(self, image_path: str) -> Dict:
        """
        Analyze EXT file system
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            Dictionary with EXT-specific information
        """
        self.logger.info("Performing EXT analysis")
        
        info = {}
        
        with open(image_path, 'rb') as f:
            # Skip to superblock at offset 1024
            f.seek(1024)
            superblock = f.read(1024)
            
            # Parse EXT superblock
            total_inodes = struct.unpack('<I', superblock[0x00:0x04])[0]
            total_blocks = struct.unpack('<I', superblock[0x04:0x08])[0]
            block_size = 1024 << struct.unpack('<I', superblock[0x18:0x1C])[0]
            blocks_per_group = struct.unpack('<I', superblock[0x20:0x24])[0]
            inodes_per_group = struct.unpack('<I', superblock[0x28:0x2C])[0]
            
            info['total_inodes'] = total_inodes
            info['total_blocks'] = total_blocks
            info['block_size'] = block_size
            info['total_size'] = total_blocks * block_size
            info['blocks_per_group'] = blocks_per_group
            info['inodes_per_group'] = inodes_per_group
            
            # Magic number verification
            magic = struct.unpack('<H', superblock[0x38:0x3A])[0]
            info['magic'] = hex(magic)
            
        return info
        
    def list_partitions(self, image_path: str) -> List[Dict]:
        """
        List partitions in a disc image
        
        Args:
            image_path: Path to the disc image
            
        Returns:
            List of partition information dictionaries
        """
        self.logger.info("Listing partitions")
        
        partitions = []
        
        with open(image_path, 'rb') as f:
            # Read MBR
            mbr = f.read(512)
            
            # Check for MBR signature
            if mbr[510:512] != b'\x55\xAA':
                self.logger.warning("Invalid MBR signature")
                return partitions
                
            # Parse partition table (4 entries starting at offset 0x1BE)
            for i in range(4):
                offset = 0x1BE + (i * 16)
                entry = mbr[offset:offset + 16]
                
                status = entry[0]
                partition_type = entry[4]
                lba_start = struct.unpack('<I', entry[8:12])[0]
                num_sectors = struct.unpack('<I', entry[12:16])[0]
                
                if partition_type != 0:  # Active partition
                    partitions.append({
                        'partition': i + 1,
                        'status': 'Bootable' if status == 0x80 else 'Non-bootable',
                        'type': hex(partition_type),
                        'lba_start': lba_start,
                        'num_sectors': num_sectors,
                        'size_mb': (num_sectors * 512) / (1024 * 1024)
                    })
                    
        return partitions
