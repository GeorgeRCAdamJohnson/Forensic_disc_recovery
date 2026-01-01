"""
Disc Imaging Module
Handles forensic disc imaging with hash verification
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple
from datetime import datetime


class DiscImager:
    """Create and verify forensic disc images"""
    
    BUFFER_SIZE = 65536  # 64KB buffer for reading
    
    def __init__(self):
        """Initialize the disc imager"""
        self.logger = logging.getLogger(__name__)
        
    def create_image(self, source: str, output: str, 
                    hash_verify: bool = True, 
                    compression: bool = False) -> str:
        """
        Create a forensic disc image with optional hash verification
        
        Args:
            source: Source device or file path
            output: Output image file path
            hash_verify: Calculate and save hash values
            compression: Compress the image (not implemented)
            
        Returns:
            Path to the created image file
        """
        self.logger.info(f"Starting image creation: {source} -> {output}")
        
        # Validate source exists
        if not os.path.exists(source):
            raise FileNotFoundError(f"Source not found: {source}")
            
        # Create output directory if needed
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Calculate hashes during imaging
        md5_hash = hashlib.md5() if hash_verify else None
        sha256_hash = hashlib.sha256() if hash_verify else None
        
        total_bytes = 0
        start_time = datetime.now()
        
        try:
            with open(source, 'rb') as src, open(output, 'wb') as dst:
                while True:
                    chunk = src.read(self.BUFFER_SIZE)
                    if not chunk:
                        break
                        
                    dst.write(chunk)
                    total_bytes += len(chunk)
                    
                    if hash_verify:
                        md5_hash.update(chunk)
                        sha256_hash.update(chunk)
                    
                    # Log progress every 100MB
                    if total_bytes % (100 * 1024 * 1024) == 0:
                        mb = total_bytes / (1024 * 1024)
                        self.logger.info(f"Copied {mb:.2f} MB")
                        
        except Exception as e:
            self.logger.error(f"Error during imaging: {e}")
            # Clean up partial image
            if os.path.exists(output):
                os.remove(output)
            raise
            
        elapsed = (datetime.now() - start_time).total_seconds()
        mb_per_sec = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0
        
        self.logger.info(f"Image created: {total_bytes:,} bytes in {elapsed:.2f}s ({mb_per_sec:.2f} MB/s)")
        
        # Save hash values
        if hash_verify:
            hash_file = f"{output}.hashes"
            with open(hash_file, 'w') as hf:
                hf.write(f"Image: {output}\n")
                hf.write(f"Created: {datetime.now().isoformat()}\n")
                hf.write(f"Size: {total_bytes:,} bytes\n")
                hf.write(f"MD5: {md5_hash.hexdigest()}\n")
                hf.write(f"SHA256: {sha256_hash.hexdigest()}\n")
            self.logger.info(f"Hash file saved: {hash_file}")
            
        return output
        
    def verify_image(self, image_path: str, hash_file: str = None) -> bool:
        """
        Verify the integrity of a disc image using saved hashes
        
        Args:
            image_path: Path to the image file
            hash_file: Path to hash file (defaults to image_path.hashes)
            
        Returns:
            True if hashes match, False otherwise
        """
        if hash_file is None:
            hash_file = f"{image_path}.hashes"
            
        if not os.path.exists(hash_file):
            self.logger.warning(f"Hash file not found: {hash_file}")
            return False
            
        # Read saved hashes
        saved_hashes = {}
        with open(hash_file, 'r') as hf:
            for line in hf:
                if ':' in line:
                    key, value = line.strip().split(':', 1)
                    saved_hashes[key.strip()] = value.strip()
                    
        # Calculate current hashes
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(image_path, 'rb') as f:
            while True:
                chunk = f.read(self.BUFFER_SIZE)
                if not chunk:
                    break
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
                
        # Compare
        md5_match = md5_hash.hexdigest() == saved_hashes.get('MD5', '')
        sha256_match = sha256_hash.hexdigest() == saved_hashes.get('SHA256', '')
        
        if md5_match and sha256_match:
            self.logger.info("Image verification successful - hashes match")
            return True
        else:
            self.logger.error("Image verification FAILED - hashes do not match!")
            if not md5_match:
                self.logger.error(f"MD5 mismatch: {md5_hash.hexdigest()} != {saved_hashes.get('MD5')}")
            if not sha256_match:
                self.logger.error(f"SHA256 mismatch: {sha256_hash.hexdigest()} != {saved_hashes.get('SHA256')}")
            return False
            
    def get_image_info(self, image_path: str) -> dict:
        """
        Get metadata information about a disc image
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing image metadata
        """
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
            
        stat = os.stat(image_path)
        
        info = {
            'path': image_path,
            'size': stat.st_size,
            'size_mb': stat.st_size / (1024 * 1024),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
        
        # Add hash info if available
        hash_file = f"{image_path}.hashes"
        if os.path.exists(hash_file):
            with open(hash_file, 'r') as hf:
                for line in hf:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        info[key.strip().lower()] = value.strip()
                        
        return info
