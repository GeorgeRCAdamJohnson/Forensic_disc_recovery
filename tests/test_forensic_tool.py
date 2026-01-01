"""
Comprehensive Unit Tests for Forensic Disc Recovery Tool - Professional Edition
Run with: python -m pytest tests/ -v --cov=core --cov=utils
"""

import os
import tempfile
import pytest
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch

# Import modules to test
from core.disc_imager import DiscImager
from core.advanced_analyzer import AdvancedFileSystemAnalyzer
from core.enhanced_recovery import EnhancedRecoveryEngine
from core.security import SecurityManager
from utils.hash_utils import HashCalculator
from utils.report_generator import ReportGenerator
from utils.logger import ForensicLogger


class TestSecurityManager:
    """Test security management functionality"""
    
    def test_admin_privilege_check(self):
        """Test administrator privilege checking"""
        security = SecurityManager()
        # Note: This will depend on actual system privileges
        assert isinstance(security.is_admin, bool)
        
    def test_case_key_generation(self):
        """Test encryption key generation for cases"""
        security = SecurityManager()
        key1 = security.generate_case_key("case1", "password123")
        key2 = security.generate_case_key("case1", "password123")
        key3 = security.generate_case_key("case2", "password123")
        
        assert key1 == key2  # Same case and password should generate same key
        assert key1 != key3  # Different case should generate different key
        assert len(key1) == 44  # Base64 encoded 32-byte key
        
    def test_evidence_encryption(self):
        """Test evidence encryption and decryption"""
        security = SecurityManager()
        key = security.generate_case_key("test_case", "test_password")
        
        original_data = b"This is sensitive evidence data"
        encrypted_data = security.encrypt_evidence(original_data, key)
        decrypted_data = security.decrypt_evidence(encrypted_data, key)
        
        assert encrypted_data != original_data
        assert decrypted_data == original_data
        
    def test_secure_delete(self, tmp_path):
        """Test secure file deletion"""
        security = SecurityManager()
        test_file = tmp_path / "sensitive.txt"
        test_file.write_text("Sensitive data to be securely deleted")
        
        assert test_file.exists()
        security.secure_delete(str(test_file), passes=1)
        assert not test_file.exists()


class TestAdvancedFileSystemAnalyzer:
    """Test advanced file system analysis"""
    
    def test_extended_fs_detection(self, tmp_path):
        """Test detection of extended file systems"""
        analyzer = AdvancedFileSystemAnalyzer()
        
        # Create mock file system images
        ntfs_image = tmp_path / "ntfs.img"
        with open(ntfs_image, 'wb') as f:
            f.write(b'\x00' * 0x03)  # Padding
            f.write(b'NTFS    ')     # NTFS signature
            f.write(b'\x00' * 1000)  # More data
            
        fs_type = analyzer._detect_filesystem(str(ntfs_image))
        assert fs_type == 'NTFS'
        
    def test_deleted_entry_analysis(self, tmp_path):
        """Test deleted file entry analysis"""
        analyzer = AdvancedFileSystemAnalyzer()
        
        # Create mock image with NTFS signature
        test_image = tmp_path / "test.img"
        with open(test_image, 'wb') as f:
            # Create minimal NTFS boot sector
            boot_sector = bytearray(512)
            boot_sector[0x03:0x0B] = b'NTFS    '
            boot_sector[0x0B:0x0D] = (512).to_bytes(2, 'little')  # bytes per sector
            boot_sector[0x0D] = 8  # sectors per cluster
            boot_sector[0x30:0x38] = (1024).to_bytes(8, 'little')  # MFT cluster
            f.write(boot_sector)
            
            # Pad to MFT location and add mock MFT entry
            f.write(b'\x00' * (1024 * 8 * 512 - 512))  # Pad to MFT
            
            # Mock deleted MFT entry
            mft_entry = bytearray(1024)
            mft_entry[0:4] = b'FILE'
            mft_entry[0x16:0x18] = (0).to_bytes(2, 'little')  # Flags: not in use
            f.write(mft_entry)
            
        deleted_entries = analyzer.analyze_deleted_entries(str(test_image))
        assert isinstance(deleted_entries, list)
        
    def test_encryption_detection(self, tmp_path):
        """Test encryption detection"""
        analyzer = AdvancedFileSystemAnalyzer()
        
        # Create mock BitLocker image
        bitlocker_image = tmp_path / "bitlocker.img"
        with open(bitlocker_image, 'wb') as f:
            f.write(b'\x00' * 3)     # Padding
            f.write(b'-FVE-FS-')     # BitLocker signature
            f.write(b'\x00' * 1000)  # More data
            
        encryption_info = analyzer.detect_encryption(str(bitlocker_image))
        assert encryption_info['bitlocker_detected'] == True
        assert 'BitLocker' in encryption_info['encryption_types']


class TestEnhancedRecoveryEngine:
    """Test enhanced recovery functionality"""
    
    def test_timeline_building(self, tmp_path):
        """Test timeline building from recovered files"""
        engine = EnhancedRecoveryEngine()
        
        # Create mock recovered files
        recovery_dir = tmp_path / "recovered"
        recovery_dir.mkdir()
        
        # Create test files with different timestamps
        (recovery_dir / "document.pdf").write_bytes(b"Mock PDF content")
        (recovery_dir / "image.jpg").write_bytes(b"Mock JPEG content")
        
        timeline = engine._build_timeline(str(recovery_dir))
        assert isinstance(timeline, list)
        assert len(timeline) >= 4  # At least created and modified for each file
        
        # Check timeline structure
        for event in timeline:
            assert 'timestamp' in event
            assert 'event_type' in event
            assert 'file_path' in event
            assert 'source' in event
            
    def test_metadata_extraction(self, tmp_path):
        """Test metadata extraction from files"""
        engine = EnhancedRecoveryEngine()
        
        # Create mock LNK file
        lnk_file = tmp_path / "test.lnk"
        lnk_data = bytearray(76)
        lnk_data[0:4] = b'L\x00\x00\x00'  # LNK signature
        lnk_data[24:28] = (0x20).to_bytes(4, 'little')  # File attributes
        lnk_file.write_bytes(lnk_data)
        
        metadata = engine._extract_file_metadata(lnk_file)
        assert metadata is not None
        assert 'file_size' in metadata
        assert 'file_extension' in metadata
        assert metadata['file_extension'] == '.lnk'
        
    def test_extended_signatures(self):
        """Test extended file signatures"""
        engine = EnhancedRecoveryEngine()
        
        # Check that extended signatures are loaded
        assert 'sqlite' in engine.FILE_SIGNATURES
        assert 'pst' in engine.FILE_SIGNATURES
        assert 'registry' in engine.FILE_SIGNATURES
        assert 'lnk' in engine.FILE_SIGNATURES
        
        # Verify signature properties
        sqlite_sig = engine.FILE_SIGNATURES['sqlite']
        assert sqlite_sig['header'] == b'SQLite format 3\x00'
        assert sqlite_sig['extension'] == '.db'
        assert 'extract_metadata' in sqlite_sig


class TestForensicLogger:
    """Test forensic logging functionality"""
    
    def test_forensic_logger_initialization(self, tmp_path):
        """Test forensic logger initialization"""
        # Change to temp directory to avoid creating logs in project
        os.chdir(tmp_path)
        
        logger = ForensicLogger("TEST_CASE_001", "Test Investigator")
        
        assert logger.case_name == "TEST_CASE_001"
        assert logger.investigator == "Test Investigator"
        assert logger.log_file.exists()
        
        # Check log file content
        log_content = logger.log_file.read_text()
        assert "FORENSIC INVESTIGATION LOG" in log_content
        assert "TEST_CASE_001" in log_content
        assert "Test Investigator" in log_content
        
    def test_evidence_acquisition_logging(self, tmp_path):
        """Test evidence acquisition logging"""
        os.chdir(tmp_path)
        
        logger = ForensicLogger("TEST_CASE_002", "Test Investigator")
        logger.log_evidence_acquisition(
            "/dev/sda", "evidence.dd", 
            "d41d8cd98f00b204e9800998ecf8427e",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        
        log_content = logger.log_file.read_text()
        assert "EVIDENCE ACQUISITION" in log_content
        assert "/dev/sda" in log_content
        assert "evidence.dd" in log_content
        assert "d41d8cd98f00b204e9800998ecf8427e" in log_content


class TestHashCalculator:
    """Test enhanced hash calculation utilities"""
    
    def test_multiple_hash_algorithms(self, tmp_path):
        """Test calculation of multiple hash algorithms"""
        test_file = tmp_path / "test.txt"
        test_content = "Hello, Forensic World!"
        test_file.write_text(test_content)
        
        calculator = HashCalculator()
        hashes = calculator.calculate_file_hashes(str(test_file))
        
        # Check all hash types are present
        assert 'md5' in hashes
        assert 'sha1' in hashes
        assert 'sha256' in hashes
        
        # Verify hash lengths
        assert len(hashes['md5']) == 32
        assert len(hashes['sha1']) == 40
        assert len(hashes['sha256']) == 64
        
        # Verify actual hash values
        expected_md5 = hashlib.md5(test_content.encode()).hexdigest()
        assert hashes['md5'] == expected_md5
        
    def test_directory_hashing(self, tmp_path):
        """Test hashing entire directories"""
        # Create test directory structure
        test_dir = tmp_path / "test_evidence"
        test_dir.mkdir()
        
        (test_dir / "file1.txt").write_text("Content 1")
        (test_dir / "file2.txt").write_text("Content 2")
        
        subdir = test_dir / "subdir"
        subdir.mkdir()
        (subdir / "file3.txt").write_text("Content 3")
        
        calculator = HashCalculator()
        results = calculator.hash_directory(str(test_dir))
        
        # Should have hashes for all files
        assert len(results) == 3
        
        # Check that all files are included
        file_names = [Path(path).name for path in results.keys()]
        assert "file1.txt" in file_names
        assert "file2.txt" in file_names
        assert "file3.txt" in file_names
        
    def test_hash_file_saving(self, tmp_path):
        """Test saving hash results to file"""
        calculator = HashCalculator()
        
        # Create mock hash results
        hash_results = {
            "file1.txt": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
        
        output_file = tmp_path / "hashes.txt"
        calculator.save_hashes_to_file(hash_results, str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "file1.txt" in content
        assert "MD5: d41d8cd98f00b204e9800998ecf8427e" in content
        assert "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in content


class TestReportGenerator:
    """Test enhanced report generation"""
    
    def test_professional_html_report(self, tmp_path):
        """Test professional HTML report generation"""
        report = ReportGenerator()
        
        # Add professional sections
        report.add_section('Case Information', {
            'Case ID': 'CASE_2024_001',
            'Investigator': 'John Doe',
            'Date': '2024-01-15',
            'Evidence Type': 'Hard Drive'
        })
        
        report.add_section('Technical Details', {
            'Tool Version': '2.0.0',
            'Hash Algorithms': 'MD5, SHA1, SHA256, SHA512',
            'Compliance': 'NIST SP 800-86, ISO 27037'
        })
        
        output = tmp_path / "professional_report.html"
        result = report.generate('Professional Test Case', str(output), 'html')
        
        assert Path(result).exists()
        content = Path(result).read_text()
        
        # Check professional elements
        assert 'Professional Test Case' in content
        assert 'Case Information' in content
        assert 'Technical Details' in content
        assert 'CASE_2024_001' in content
        assert 'John Doe' in content
        
        # Check styling and structure
        assert '<style>' in content
        assert 'font-family' in content
        assert 'table' in content
        
    def test_recovery_report_generation(self, tmp_path):
        """Test specialized recovery report"""
        report = ReportGenerator()
        
        recovery_stats = {
            'total_files': 150,
            'total_size_mb': 2048.5,
            'largest_file': 'video.mp4',
            'largest_size': 500 * 1024 * 1024,  # 500MB
            'file_types': {
                '.jpg': {'count': 75, 'size': 150 * 1024 * 1024},
                '.pdf': {'count': 25, 'size': 50 * 1024 * 1024},
                '.docx': {'count': 50, 'size': 25 * 1024 * 1024}
            }
        }
        
        output = tmp_path / "recovery_report.html"
        result = report.generate_recovery_report(recovery_stats, str(output))
        
        assert Path(result).exists()
        content = Path(result).read_text()
        
        # Check recovery-specific content
        assert 'Recovery Summary' in content
        assert '150' in content  # Total files
        assert '2048.50' in content  # Total size
        assert 'File Types Recovered' in content
        assert '.jpg' in content
        assert '.pdf' in content
        assert '.docx' in content


@pytest.fixture
def tmp_path(tmp_path_factory):
    """Create a temporary directory for tests"""
    return tmp_path_factory.mktemp("forensic_test")


# Integration tests
class TestIntegration:
    """Integration tests for the complete forensic workflow"""
    
    def test_complete_forensic_workflow(self, tmp_path):
        """Test complete forensic workflow from imaging to reporting"""
        # This would test the complete workflow but requires significant setup
        # For now, we'll test component integration
        
        # Create mock evidence
        evidence_file = tmp_path / "evidence.bin"
        evidence_file.write_bytes(b"Mock evidence data" * 1000)
        
        # Test imaging
        imager = DiscImager()
        image_path = tmp_path / "evidence.dd"
        result = imager.create_image(str(evidence_file), str(image_path), hash_verify=True)
        
        assert result == str(image_path)
        assert image_path.exists()
        assert Path(f"{image_path}.hashes").exists()
        
        # Test hash verification
        calculator = HashCalculator()
        original_hashes = calculator.calculate_file_hashes(str(evidence_file))
        image_hashes = calculator.calculate_file_hashes(str(image_path))
        
        assert original_hashes['md5'] == image_hashes['md5']
        assert original_hashes['sha256'] == image_hashes['sha256']
        
        # Test basic analysis
        analyzer = AdvancedFileSystemAnalyzer()
        # Note: This will detect as "Unknown" since it's not a real file system
        analysis = analyzer.analyze(str(image_path))
        assert 'fs_type' in analysis
        
        # Test report generation
        report = ReportGenerator()
        report.add_section('Integration Test', {
            'Original Size': len(b"Mock evidence data" * 1000),
            'Image Size': image_path.stat().st_size,
            'Hash Match': 'Verified'
        })
        
        report_path = tmp_path / "integration_report.html"
        result = report.generate('Integration Test', str(report_path), 'html')
        
        assert Path(result).exists()
        content = Path(result).read_text()
        assert 'Integration Test' in content
        assert 'Hash Match' in content
        assert 'Verified' in content


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--cov=core', '--cov=utils', '--cov-report=html'])
