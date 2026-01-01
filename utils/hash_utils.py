"""
Hash Utilities Module
Calculate and verify cryptographic hashes for forensic evidence
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, Tuple


class HashCalculator:
    """Calculate cryptographic hashes for files and data"""
    
    BUFFER_SIZE = 65536  # 64KB buffer
    
    def __init__(self):
        """Initialize hash calculator"""
        self.logger = logging.getLogger(__name__)
        
    def calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate MD5, SHA1, and SHA256 hashes for a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with hash algorithm names and hex digest values
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(self.BUFFER_SIZE)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
                
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
        
    def calculate_string_hash(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Calculate hash for a byte string
        
        Args:
            data: Byte data to hash
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
            
        Returns:
            Hex digest string
        """
        if algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
    def verify_file_hash(self, file_path: str, expected_hash: str, 
                        algorithm: str = 'sha256') -> bool:
        """
        Verify a file's hash against an expected value
        
        Args:
            file_path: Path to the file
            expected_hash: Expected hash value (hex string)
            algorithm: Hash algorithm to use
            
        Returns:
            True if hashes match, False otherwise
        """
        hashes = self.calculate_file_hashes(file_path)
        actual_hash = hashes.get(algorithm.lower())
        
        if actual_hash is None:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        match = actual_hash.lower() == expected_hash.lower()
        
        if match:
            self.logger.info(f"Hash verification PASSED for {file_path}")
        else:
            self.logger.error(f"Hash verification FAILED for {file_path}")
            self.logger.error(f"Expected: {expected_hash}")
            self.logger.error(f"Actual: {actual_hash}")
            
        return match
        
    def hash_directory(self, directory: str) -> Dict[str, Dict[str, str]]:
        """
        Calculate hashes for all files in a directory
        
        Args:
            directory: Path to directory
            
        Returns:
            Dictionary mapping file paths to their hash dictionaries
        """
        dir_path = Path(directory)
        results = {}
        
        for file_path in dir_path.rglob('*'):
            if file_path.is_file():
                try:
                    hashes = self.calculate_file_hashes(str(file_path))
                    results[str(file_path)] = hashes
                except Exception as e:
                    self.logger.error(f"Error hashing {file_path}: {e}")
                    
        return results
        
    def save_hashes_to_file(self, hashes: Dict[str, Dict[str, str]], 
                           output_file: str):
        """
        Save hash calculations to a file
        
        Args:
            hashes: Dictionary of file paths to hash dictionaries
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            for file_path, hash_dict in hashes.items():
                f.write(f"\nFile: {file_path}\n")
                for algo, hash_value in hash_dict.items():
                    f.write(f"  {algo.upper()}: {hash_value}\n")
                    
        self.logger.info(f"Hashes saved to: {output_file}")
