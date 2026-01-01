"""
Security Module
Enhanced security features for forensic operations
"""

import os
import sys
import ctypes
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


class SecurityManager:
    """Manage security aspects of forensic operations"""
    
    def __init__(self):
        self.is_admin = self._check_admin_privileges()
        
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            if os.name == 'nt':  # Windows
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:  # Unix/Linux
                return os.geteuid() == 0
        except:
            return False
            
    def require_admin(self):
        """Require administrator privileges"""
        if not self.is_admin:
            raise PermissionError("Administrator privileges required for forensic operations")
            
    def generate_case_key(self, case_id: str, password: str) -> bytes:
        """Generate encryption key for case data"""
        salt = hashlib.sha256(case_id.encode()).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
    def encrypt_evidence(self, data: bytes, key: bytes) -> bytes:
        """Encrypt evidence data"""
        f = Fernet(key)
        return f.encrypt(data)
        
    def decrypt_evidence(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt evidence data"""
        f = Fernet(key)
        return f.decrypt(encrypted_data)
        
    def secure_delete(self, file_path: str, passes: int = 3):
        """Securely delete a file with multiple overwrites"""
        if not os.path.exists(file_path):
            return
            
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
                
        os.remove(file_path)
        
    def create_integrity_manifest(self, directory: str) -> Dict:
        """Create integrity manifest for evidence directory"""
        manifest = {
            'created': os.path.getctime(directory),
            'files': {}
        }
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, directory)
                
                with open(file_path, 'rb') as f:
                    content = f.read()
                    manifest['files'][rel_path] = {
                        'size': len(content),
                        'sha256': hashlib.sha256(content).hexdigest(),
                        'modified': os.path.getmtime(file_path)
                    }
                    
        return manifest