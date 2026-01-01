#!/usr/bin/env python3
"""
Professional Setup and Deployment Script
Forensic Disc Recovery Tool - Professional Edition
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path
import configparser


class ProfessionalSetup:
    """Professional setup and deployment manager"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.is_admin = self._check_admin()
        self.project_root = Path(__file__).parent
        
    def _check_admin(self) -> bool:
        """Check if running with admin privileges"""
        try:
            if self.system == 'windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
            
    def setup_professional_environment(self):
        """Set up professional forensic environment"""
        print("🔧 Setting up Forensic Disc Recovery Tool - Professional Edition")
        print("=" * 60)
        
        if not self.is_admin:
            print("⚠️  WARNING: Administrator privileges recommended for full functionality")
            
        # Create professional directory structure
        self._create_directory_structure()
        
        # Install dependencies
        self._install_dependencies()
        
        # Configure professional settings
        self._configure_professional_settings()
        
        # Set up security features
        self._setup_security()
        
        # Create desktop shortcuts (Windows)
        if self.system == 'windows':
            self._create_shortcuts()
            
        # Verify installation
        self._verify_installation()
        
        print("\n✅ Professional setup completed successfully!")
        print("📖 See PROFESSIONAL_GUIDE.md for usage instructions")
        
    def _create_directory_structure(self):
        """Create professional directory structure"""
        print("📁 Creating professional directory structure...")
        
        directories = [
            'cases',
            'templates',
            'logs',
            'evidence_logs',
            'reports',
            'backups',
            'config',
            'plugins',
            'signatures'
        ]
        
        for directory in directories:
            dir_path = self.project_root / directory
            dir_path.mkdir(exist_ok=True)
            print(f"   Created: {directory}/")
            
        # Create case template structure
        case_template = self.project_root / 'templates' / 'case_template'
        case_template.mkdir(exist_ok=True)
        
        for subdir in ['images', 'recovered', 'reports', 'logs', 'analysis']:
            (case_template / subdir).mkdir(exist_ok=True)
            
    def _install_dependencies(self):
        """Install professional dependencies"""
        print("📦 Installing professional dependencies...")
        
        try:
            # Upgrade pip first
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'], 
                         check=True, capture_output=True)
            
            # Install requirements
            requirements_file = self.project_root / 'requirements.txt'
            if requirements_file.exists():
                subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)], 
                             check=True, capture_output=True)
                print("   ✅ Professional dependencies installed")
            else:
                print("   ⚠️  requirements.txt not found")
                
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Error installing dependencies: {e}")
            
    def _configure_professional_settings(self):
        """Configure professional settings"""
        print("⚙️  Configuring professional settings...")
        
        config_file = self.project_root / 'config.ini'
        if not config_file.exists():
            self._create_professional_config(config_file)
            
        # Create custom signatures file
        signatures_file = self.project_root / 'signatures' / 'custom_signatures.json'
        if not signatures_file.exists():
            self._create_custom_signatures(signatures_file)
            
        print("   ✅ Professional configuration completed")
        
    def _create_professional_config(self, config_file: Path):
        """Create professional configuration file"""
        config = configparser.ConfigParser()
        
        # Professional configuration sections
        config['General'] = {
            'version': '2.0.0',
            'tool_name': 'Forensic Disc Recovery Tool - Professional',
            'organization': 'Digital Forensics Lab',
            'license_type': 'Professional'
        }
        
        config['Security'] = {
            'require_admin': 'true',
            'evidence_encryption': 'true',
            'secure_deletion_passes': '7',
            'access_control': 'true',
            'audit_trail': 'true'
        }
        
        config['Performance'] = {
            'multi_threading': 'true',
            'max_threads': '8',
            'memory_limit': '4096',
            'disk_caching': 'true'
        }
        
        config['Compliance'] = {
            'nist_compliance': 'true',
            'iso_27037_compliance': 'true',
            'acpo_compliance': 'true',
            'chain_of_custody': 'true'
        }
        
        with open(config_file, 'w') as f:
            config.write(f)
            
    def _create_custom_signatures(self, signatures_file: Path):
        """Create custom file signatures configuration"""
        import json
        
        custom_signatures = {
            "custom_signatures": {
                "bitcoin_wallet": {
                    "header": "\\x01\\x00\\x00\\x00",
                    "footer": null,
                    "extension": ".wallet",
                    "max_size": 10485760,
                    "description": "Bitcoin wallet file"
                },
                "encrypted_zip": {
                    "header": "PK\\x03\\x04\\x14\\x00\\x01\\x00",
                    "footer": null,
                    "extension": ".zip",
                    "max_size": 1073741824,
                    "description": "Encrypted ZIP archive"
                }
            }
        }
        
        with open(signatures_file, 'w') as f:
            json.dump(custom_signatures, f, indent=4)
            
    def _setup_security(self):
        """Set up security features"""
        print("🔒 Setting up security features...")
        
        # Create encryption key directory
        key_dir = self.project_root / '.keys'
        key_dir.mkdir(exist_ok=True, mode=0o700)
        
        # Create forensic key file
        forensic_key = key_dir / '.forensic_key'
        if not forensic_key.exists():
            import secrets
            key = secrets.token_bytes(32)
            forensic_key.write_bytes(key)
            forensic_key.chmod(0o600)
            
        print("   ✅ Security features configured")
        
    def _create_shortcuts(self):
        """Create Windows desktop shortcuts"""
        print("🖥️  Creating desktop shortcuts...")
        
        try:
            import winshell
            from win32com.client import Dispatch
            
            desktop = winshell.desktop()
            
            # Main application shortcut
            shortcut = Dispatch('WScript.Shell').CreateShortCut(
                os.path.join(desktop, 'Forensic Recovery Pro.lnk')
            )
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = str(self.project_root / 'main.py')
            shortcut.WorkingDirectory = str(self.project_root)
            shortcut.IconLocation = str(self.project_root / 'assets' / 'icon.ico')
            shortcut.save()
            
            print("   ✅ Desktop shortcuts created")
            
        except ImportError:
            print("   ⚠️  Windows shell extensions not available")
        except Exception as e:
            print(f"   ⚠️  Could not create shortcuts: {e}")
            
    def _verify_installation(self):
        """Verify professional installation"""
        print("🔍 Verifying installation...")
        
        checks = [
            ('Python version', sys.version_info >= (3, 8)),
            ('Config file', (self.project_root / 'config.ini').exists()),
            ('Core modules', self._check_core_modules()),
            ('Professional features', self._check_professional_features()),
        ]
        
        all_passed = True
        for check_name, result in checks:
            status = "✅" if result else "❌"
            print(f"   {status} {check_name}")
            if not result:
                all_passed = False
                
        return all_passed
        
    def _check_core_modules(self) -> bool:
        """Check if core modules are available"""
        try:
            from core.disc_imager import DiscImager
            from core.advanced_analyzer import AdvancedFileSystemAnalyzer
            from core.enhanced_recovery import EnhancedRecoveryEngine
            from core.security import SecurityManager
            return True
        except ImportError:
            return False
            
    def _check_professional_features(self) -> bool:
        """Check if professional features are available"""
        try:
            from cryptography.fernet import Fernet
            import pytsk3
            return True
        except ImportError:
            return False
            
    def create_case_template(self, case_name: str):
        """Create a new case from template"""
        print(f"📋 Creating case: {case_name}")
        
        case_dir = self.project_root / 'cases' / case_name
        template_dir = self.project_root / 'templates' / 'case_template'
        
        if case_dir.exists():
            print(f"   ⚠️  Case {case_name} already exists")
            return False
            
        # Copy template structure
        shutil.copytree(template_dir, case_dir)
        
        # Create case metadata
        metadata = {
            'case_name': case_name,
            'created': str(Path().cwd()),
            'investigator': os.getenv('USERNAME', 'Unknown'),
            'status': 'Active'
        }
        
        import json
        with open(case_dir / 'case_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=4)
            
        print(f"   ✅ Case {case_name} created successfully")
        return True
        
    def run_diagnostics(self):
        """Run system diagnostics"""
        print("🔧 Running system diagnostics...")
        print("=" * 40)
        
        # System information
        print(f"Operating System: {platform.system()} {platform.release()}")
        print(f"Python Version: {sys.version}")
        print(f"Architecture: {platform.architecture()[0]}")
        print(f"Admin Privileges: {'Yes' if self.is_admin else 'No'}")
        
        # Disk space
        total, used, free = shutil.disk_usage(self.project_root)
        print(f"Disk Space: {free // (2**30)} GB free of {total // (2**30)} GB")
        
        # Memory
        try:
            import psutil
            memory = psutil.virtual_memory()
            print(f"Memory: {memory.available // (2**30)} GB available of {memory.total // (2**30)} GB")
        except ImportError:
            print("Memory: psutil not available")
            
        # Dependencies
        print("\nDependency Status:")
        dependencies = [
            'cryptography', 'pytsk3', 'pillow', 'matplotlib', 
            'pytest', 'numpy', 'requests'
        ]
        
        for dep in dependencies:
            try:
                __import__(dep)
                print(f"   ✅ {dep}")
            except ImportError:
                print(f"   ❌ {dep}")


def main():
    """Main setup function"""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        setup = ProfessionalSetup()
        
        if command == 'install':
            setup.setup_professional_environment()
        elif command == 'diagnostics':
            setup.run_diagnostics()
        elif command == 'create-case' and len(sys.argv) > 2:
            setup.create_case_template(sys.argv[2])
        else:
            print("Usage:")
            print("  python setup_professional.py install")
            print("  python setup_professional.py diagnostics")
            print("  python setup_professional.py create-case CASE_NAME")
    else:
        setup = ProfessionalSetup()
        setup.setup_professional_environment()


if __name__ == '__main__':
    main()