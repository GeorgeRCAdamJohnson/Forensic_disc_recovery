#!/usr/bin/env python3
"""
Example script demonstrating forensic disc recovery tool usage
"""

from core.disc_imager import DiscImager
from core.filesystem_analyzer import FileSystemAnalyzer
from core.recovery_engine import RecoveryEngine
from utils.logger import setup_logger, ForensicLogger
from utils.report_generator import ReportGenerator
from utils.hash_utils import HashCalculator


def example_create_image():
    """Example: Create a forensic disc image"""
    print("Example 1: Creating a forensic disc image")
    print("-" * 50)
    
    logger = setup_logger(__name__, verbose=True)
    imager = DiscImager()
    
    # Note: Replace with actual source path
    source = "test_data/sample.img"
    output = "evidence/disk_image.dd"
    
    try:
        image_path = imager.create_image(source, output, hash_verify=True)
        print(f"✓ Image created: {image_path}")
        
        # Verify the image
        if imager.verify_image(image_path):
            print("✓ Image verification passed")
            
        # Get image info
        info = imager.get_image_info(image_path)
        print(f"✓ Image size: {info['size_mb']:.2f} MB")
        
    except FileNotFoundError:
        print("✗ Source file not found (this is just an example)")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_analyze_filesystem():
    """Example: Analyze a file system"""
    print("Example 2: Analyzing file system")
    print("-" * 50)
    
    analyzer = FileSystemAnalyzer()
    
    # Note: Replace with actual image path
    image_path = "evidence/disk_image.dd"
    
    try:
        analysis = analyzer.analyze(image_path)
        print(f"✓ File system type: {analysis.get('fs_type', 'Unknown')}")
        print(f"✓ Cluster size: {analysis.get('cluster_size', 'Unknown')} bytes")
        print(f"✓ Total size: {analysis.get('total_size', 0) / (1024**3):.2f} GB")
        
        # List partitions
        partitions = analyzer.list_partitions(image_path)
        print(f"✓ Found {len(partitions)} partition(s)")
        
    except FileNotFoundError:
        print("✗ Image file not found (this is just an example)")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_recover_files():
    """Example: Recover deleted files"""
    print("Example 3: Recovering deleted files")
    print("-" * 50)
    
    engine = RecoveryEngine()
    
    # Note: Replace with actual paths
    image_path = "evidence/disk_image.dd"
    output_dir = "recovered"
    
    try:
        # Recover specific file types
        file_types = ['jpeg', 'png', 'pdf']
        count = engine.recover_deleted(image_path, output_dir, file_types)
        print(f"✓ Recovered {count} files")
        
        # Analyze recovered files
        stats = engine.analyze_recovered_files(output_dir)
        print(f"✓ Total size: {stats.get('total_size_mb', 0):.2f} MB")
        
    except FileNotFoundError:
        print("✗ Image file not found (this is just an example)")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_data_carving():
    """Example: Data carving"""
    print("Example 4: Data carving")
    print("-" * 50)
    
    engine = RecoveryEngine()
    
    # Note: Replace with actual paths
    image_path = "evidence/disk_image.dd"
    output_dir = "carved"
    
    try:
        # Carve specific file types
        signatures = ['jpeg', 'png', 'pdf', 'zip']
        count = engine.carve_data(image_path, output_dir, signatures)
        print(f"✓ Carved {count} files")
        
    except FileNotFoundError:
        print("✗ Image file not found (this is just an example)")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_hash_calculation():
    """Example: Calculate file hashes"""
    print("Example 5: Calculating file hashes")
    print("-" * 50)
    
    calculator = HashCalculator()
    
    # Note: Replace with actual file
    file_path = "evidence/disk_image.dd"
    
    try:
        hashes = calculator.calculate_file_hashes(file_path)
        print("✓ File hashes calculated:")
        print(f"  MD5:    {hashes['md5']}")
        print(f"  SHA1:   {hashes['sha1']}")
        print(f"  SHA256: {hashes['sha256']}")
        
    except FileNotFoundError:
        print("✗ File not found (this is just an example)")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_report_generation():
    """Example: Generate forensic report"""
    print("Example 6: Generating forensic report")
    print("-" * 50)
    
    report = ReportGenerator()
    
    # Add sections to report
    report.add_section('Case Information', {
        'Case Number': 'CASE-2025-001',
        'Investigator': 'John Doe',
        'Date': '2025-12-31',
        'Evidence': 'Hard Drive - Serial XYZ123'
    })
    
    report.add_section('Analysis Summary', {
        'File System': 'NTFS',
        'Total Size': '500 GB',
        'Files Recovered': '1,234',
        'Evidence Hash (SHA256)': 'a1b2c3d4...'
    })
    
    try:
        output_path = report.generate('CASE-2025-001', 'reports/case_report.html', 'html')
        print(f"✓ Report generated: {output_path}")
        
    except Exception as e:
        print(f"✗ Error: {e}")
    
    print()


def example_forensic_logging():
    """Example: Forensic logging with chain of custody"""
    print("Example 7: Forensic logging")
    print("-" * 50)
    
    # Create forensic logger
    forensic_log = ForensicLogger(
        case_name='CASE-2025-001',
        investigator='John Doe'
    )
    
    # Log evidence acquisition
    forensic_log.log_evidence_acquisition(
        source='/dev/sda',
        destination='evidence/disk_image.dd',
        hash_md5='abc123...',
        hash_sha256='def456...'
    )
    
    # Log analysis
    forensic_log.log_analysis(
        image_path='evidence/disk_image.dd',
        analysis_type='File System Analysis',
        results={'fs_type': 'NTFS', 'size': '500GB'}
    )
    
    # Log recovery
    forensic_log.log_recovery(
        image_path='evidence/disk_image.dd',
        recovery_type='Deleted File Recovery',
        files_recovered=1234,
        output_dir='recovered/'
    )
    
    print(f"✓ Forensic log created: {forensic_log.log_file}")
    print()


def main():
    """Run all examples"""
    print("=" * 50)
    print("FORENSIC DISC RECOVERY TOOL - USAGE EXAMPLES")
    print("=" * 50)
    print()
    
    print("Note: These are example demonstrations.")
    print("Replace file paths with actual evidence for real use.")
    print()
    
    # Run examples (most will show errors since files don't exist)
    example_create_image()
    example_analyze_filesystem()
    example_recover_files()
    example_data_carving()
    example_hash_calculation()
    example_report_generation()
    example_forensic_logging()
    
    print("=" * 50)
    print("For actual usage, use the CLI: python main.py --help")
    print("=" * 50)


if __name__ == '__main__':
    main()
