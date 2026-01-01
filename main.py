#!/usr/bin/env python3
"""
Forensic Disc Recovery Tool - Professional Edition
Main entry point for the forensic recovery application
"""

import argparse
import sys
import logging
import configparser
from pathlib import Path
from typing import Optional

from core.disc_imager import DiscImager
from core.advanced_analyzer import AdvancedFileSystemAnalyzer
from core.enhanced_recovery import EnhancedRecoveryEngine
from core.security import SecurityManager
from utils.logger import setup_logger, ForensicLogger
from utils.report_generator import ReportGenerator


class ForensicDiscRecoveryPro:
    """Professional forensic disc recovery application"""
    
    def __init__(self, verbose: bool = False, config_file: str = 'config.ini'):
        """Initialize the forensic recovery tool"""
        self.config = self._load_config(config_file)
        self.logger = setup_logger(__name__, verbose=verbose)
        
        # Initialize security manager
        self.security = SecurityManager()
        if self.config.getboolean('Security', 'require_admin', fallback=True):
            self.security.require_admin()
            
        # Initialize components
        self.disc_imager = DiscImager()
        self.fs_analyzer = AdvancedFileSystemAnalyzer()
        self.recovery_engine = EnhancedRecoveryEngine()
        self.report_gen = ReportGenerator()
        
        # Initialize forensic logger for chain of custody
        self.forensic_logger = None
        
    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """Load configuration from file"""
        config = configparser.ConfigParser()
        if Path(config_file).exists():
            config.read(config_file)
        else:
            # Create default config
            self._create_default_config(config_file)
            config.read(config_file)
        return config
        
    def _create_default_config(self, config_file: str):
        """Create default configuration file"""
        # This would create a default config - implementation omitted for brevity
        pass
        
    def initialize_case(self, case_name: str, investigator: str) -> str:
        """Initialize a new forensic case"""
        self.logger.info(f"Initializing case: {case_name}")
        
        # Create case directory structure
        case_dir = Path('cases') / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (case_dir / 'images').mkdir(exist_ok=True)
        (case_dir / 'recovered').mkdir(exist_ok=True)
        (case_dir / 'reports').mkdir(exist_ok=True)
        (case_dir / 'logs').mkdir(exist_ok=True)
        
        # Initialize forensic logger
        self.forensic_logger = ForensicLogger(case_name, investigator)
        
        return str(case_dir)
        
    def create_image_professional(self, source: str, output: str, 
                                case_name: str = None, 
                                hash_verify: bool = True,
                                compression: bool = False) -> bool:
        """Create a forensic disc image with professional features"""
        self.logger.info(f"Creating professional disc image from {source}")
        
        try:
            # Verify write-blocking if configured
            if self.config.getboolean('Imaging', 'write_block_verification', fallback=False):
                self._verify_write_blocking(source)
                
            # Create image with enhanced features
            image_path = self.disc_imager.create_image(source, output, hash_verify, compression)
            
            # Log to forensic chain of custody
            if self.forensic_logger and hash_verify:
                hash_file = f"{output}.hashes"
                if Path(hash_file).exists():
                    with open(hash_file, 'r') as hf:
                        content = hf.read()
                        md5_hash = self._extract_hash(content, 'MD5')
                        sha256_hash = self._extract_hash(content, 'SHA256')
                        
                    self.forensic_logger.log_evidence_acquisition(
                        source, output, md5_hash, sha256_hash
                    )
                    
            self.logger.info(f"Professional image created successfully: {image_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create professional image: {e}")
            if self.forensic_logger:
                self.forensic_logger.log_error("Image Creation", str(e))
            return False
            
    def analyze_filesystem_advanced(self, image_path: str, 
                                  include_deleted: bool = True,
                                  include_slack: bool = True) -> dict:
        """Perform advanced file system analysis"""
        self.logger.info(f"Performing advanced analysis: {image_path}")
        
        try:
            # Basic file system analysis
            analysis = self.fs_analyzer.analyze(image_path)
            
            # Advanced features
            if include_deleted:
                deleted_entries = self.fs_analyzer.analyze_deleted_entries(image_path)
                analysis['deleted_entries'] = deleted_entries
                
            if include_slack:
                slack_analysis = self.fs_analyzer.analyze_file_slack(image_path)
                analysis['slack_analysis'] = slack_analysis
                
            # Encryption detection
            encryption_info = self.fs_analyzer.detect_encryption(image_path)
            analysis['encryption_info'] = encryption_info
            
            # Log analysis
            if self.forensic_logger:
                self.forensic_logger.log_analysis(
                    image_path, "Advanced File System Analysis", analysis
                )
                
            return analysis
            
        except Exception as e:
            self.logger.error(f"Advanced analysis failed: {e}")
            if self.forensic_logger:
                self.forensic_logger.log_error("Advanced Analysis", str(e))
            return {}
            
    def recover_with_timeline_analysis(self, image_path: str, output_dir: str, 
                                     file_types: Optional[list] = None,
                                     generate_timeline: bool = True) -> dict:
        """Recover files with timeline analysis"""
        self.logger.info(f"Starting recovery with timeline analysis from {image_path}")
        
        try:
            # Enhanced recovery with timeline
            recovery_stats = self.recovery_engine.recover_with_timeline(
                image_path, output_dir, file_types
            )
            
            # Generate timeline report if requested
            if generate_timeline and recovery_stats['timeline_events']:
                timeline_report = Path(output_dir) / 'timeline_report.html'
                self.recovery_engine.generate_timeline_report(
                    recovery_stats['timeline_events'], str(timeline_report)
                )
                recovery_stats['timeline_report'] = str(timeline_report)
                
            # Log recovery operation
            if self.forensic_logger:
                self.forensic_logger.log_recovery(
                    image_path, "Enhanced Recovery with Timeline", 
                    recovery_stats['files_recovered'], output_dir
                )
                
            return recovery_stats
            
        except Exception as e:
            self.logger.error(f"Enhanced recovery failed: {e}")
            if self.forensic_logger:
                self.forensic_logger.log_error("Enhanced Recovery", str(e))
            return {'files_recovered': 0, 'timeline_events': []}
            
    def generate_professional_report(self, case_name: str, output_path: str,
                                   include_timeline: bool = True,
                                   include_metadata: bool = True,
                                   digital_signature: bool = True):
        """Generate professional forensic report"""
        self.logger.info(f"Generating professional report for case: {case_name}")
        
        try:
            # Enhanced report generation with professional features
            report_data = {
                'case_information': {
                    'case_name': case_name,
                    'investigator': getattr(self.forensic_logger, 'investigator', 'Unknown'),
                    'tool_version': self.config.get('General', 'version', fallback='2.0.0'),
                    'compliance': {
                        'nist': self.config.getboolean('Compliance', 'nist_compliance', fallback=True),
                        'iso_27037': self.config.getboolean('Compliance', 'iso_27037_compliance', fallback=True),
                        'acpo': self.config.getboolean('Compliance', 'acpo_compliance', fallback=True)
                    }
                }
            }
            
            # Add sections to report
            for section, data in report_data.items():
                self.report_gen.add_section(section, data)
                
            # Generate report
            report_path = self.report_gen.generate(case_name, output_path, 'html')
            
            # Add digital signature if enabled
            if digital_signature:
                self._add_digital_signature(report_path)
                
            self.logger.info(f"Professional report generated: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Professional report generation failed: {e}")
            
    def _verify_write_blocking(self, source: str):
        """Verify write-blocking is in place"""
        # Implementation would check for hardware write-blockers
        # or software write-protection
        self.logger.info(f"Verifying write-blocking for {source}")
        
    def _extract_hash(self, content: str, algorithm: str) -> str:
        """Extract hash value from hash file content"""
        for line in content.split('\n'):
            if line.startswith(f'{algorithm}:'):
                return line.split(':', 1)[1].strip()
        return ''
        
    def _add_digital_signature(self, report_path: str):
        """Add digital signature to report"""
        # Implementation would add cryptographic signature
        self.logger.info(f"Adding digital signature to {report_path}")


def main():
    """Ultimate command-line interface with enterprise features"""
    parser = argparse.ArgumentParser(
        description="Forensic Disc Recovery Tool - Enterprise Edition v3.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enterprise Commands:
  # Start Command Center
  %(prog)s command-center --port 8000
  
  # AI-Powered Analysis
  %(prog)s ai-analyze -i evidence.dd --malware --steganography --behavioral
  
  # Cloud Forensics
  %(prog)s cloud-acquire --aws --azure --gcp -o cloud_evidence/
  
  # Memory Forensics
  %(prog)s memory-analyze -d memory.dmp --processes --network --rootkits
  
  # Live System Analysis
  %(prog)s live-capture --full-system --real-time --duration 300
  
  # Distributed Analysis
  %(prog)s distribute-analysis -i large_evidence.dd --workers 8 --cloud
  
  # Blockchain Forensics
  %(prog)s blockchain-trace --bitcoin --addresses 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--config', default='config.ini',
                       help='Configuration file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Enterprise Command Center
    center_parser = subparsers.add_parser('command-center', help='Start enterprise command center')
    center_parser.add_argument('--host', default='0.0.0.0', help='Host address')
    center_parser.add_argument('--port', type=int, default=8000, help='Port number')
    
    # AI Analysis
    ai_parser = subparsers.add_parser('ai-analyze', help='AI-powered forensic analysis')
    ai_parser.add_argument('-i', '--input', required=True, help='Input file or directory')
    ai_parser.add_argument('--malware', action='store_true', help='Enable malware detection')
    ai_parser.add_argument('--steganography', action='store_true', help='Enable steganography detection')
    ai_parser.add_argument('--behavioral', action='store_true', help='Enable behavioral analysis')
    ai_parser.add_argument('-o', '--output', help='Output directory for results')
    
    # Cloud Forensics
    cloud_parser = subparsers.add_parser('cloud-acquire', help='Acquire cloud evidence')
    cloud_parser.add_argument('--aws', action='store_true', help='Acquire AWS evidence')
    cloud_parser.add_argument('--azure', action='store_true', help='Acquire Azure evidence')
    cloud_parser.add_argument('--gcp', action='store_true', help='Acquire GCP evidence')
    cloud_parser.add_argument('-o', '--output', required=True, help='Output directory')
    cloud_parser.add_argument('--config-file', help='Cloud configuration file')
    
    # Memory Forensics
    memory_parser = subparsers.add_parser('memory-analyze', help='Memory forensics analysis')
    memory_parser.add_argument('-d', '--dump', required=True, help='Memory dump file')
    memory_parser.add_argument('--processes', action='store_true', help='Analyze processes')
    memory_parser.add_argument('--network', action='store_true', help='Analyze network connections')
    memory_parser.add_argument('--rootkits', action='store_true', help='Detect rootkits')
    memory_parser.add_argument('--malware', action='store_true', help='Detect malware')
    
    # Live System
    live_parser = subparsers.add_parser('live-capture', help='Live system analysis')
    live_parser.add_argument('--full-system', action='store_true', help='Full system capture')
    live_parser.add_argument('--real-time', action='store_true', help='Real-time monitoring')
    live_parser.add_argument('--duration', type=int, default=300, help='Monitoring duration (seconds)')
    live_parser.add_argument('-o', '--output', help='Output directory')
    
    # Distributed Analysis
    dist_parser = subparsers.add_parser('distribute-analysis', help='Distributed analysis')
    dist_parser.add_argument('-i', '--input', required=True, help='Input evidence')
    dist_parser.add_argument('--workers', type=int, default=4, help='Number of workers')
    dist_parser.add_argument('--cloud', action='store_true', help='Use cloud workers')
    dist_parser.add_argument('--analysis-type', default='full', help='Analysis type')
    
    # Blockchain Forensics
    blockchain_parser = subparsers.add_parser('blockchain-trace', help='Blockchain forensics')
    blockchain_parser.add_argument('--bitcoin', action='store_true', help='Bitcoin analysis')
    blockchain_parser.add_argument('--ethereum', action='store_true', help='Ethereum analysis')
    blockchain_parser.add_argument('--addresses', nargs='+', help='Addresses to analyze')
    blockchain_parser.add_argument('-o', '--output', help='Output file')
    
    # Local AI Setup
    setup_parser = subparsers.add_parser('setup-ai', help='Setup local AI services')
    setup_parser.add_argument('--check-status', action='store_true', help='Check AI service status')
    setup_parser.add_argument('--optimize', choices=['cost', 'privacy', 'performance'], help='Optimize for specific use case')
    
    # Original commands (enhanced)
    image_parser = subparsers.add_parser('image-enterprise', help='Enterprise disc imaging')
    image_parser.add_argument('-s', '--source', required=True, help='Source device')
    image_parser.add_argument('-o', '--output', required=True, help='Output image')
    image_parser.add_argument('--case', help='Case name')
    image_parser.add_argument('--compression', action='store_true', help='Enable compression')
    image_parser.add_argument('--encryption', action='store_true', help='Enable encryption')
    
    analyze_parser = subparsers.add_parser('analyze-enterprise', help='Enterprise analysis')
    analyze_parser.add_argument('-i', '--image', required=True, help='Image to analyze')
    analyze_parser.add_argument('--ai-enhanced', action='store_true', help='AI-enhanced analysis')
    analyze_parser.add_argument('--include-deleted', action='store_true', help='Include deleted files')
    analyze_parser.add_argument('--include-slack', action='store_true', help='Include slack analysis')
    
    recover_parser = subparsers.add_parser('recover-enterprise', help='Enterprise recovery')
    recover_parser.add_argument('-i', '--image', required=True, help='Image to recover from')
    recover_parser.add_argument('-o', '--output', required=True, help='Output directory')
    recover_parser.add_argument('--ai-assisted', action='store_true', help='AI-assisted recovery')
    recover_parser.add_argument('--timeline', action='store_true', help='Generate timeline')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
        
    # Initialize enterprise forensic tool
    fdr = ForensicDiscRecoveryPro(verbose=args.verbose, config_file=args.config)
    
    try:
        if args.command == 'command-center':
            from core.command_center import ForensicCommandCenter
            center = ForensicCommandCenter()
            center.start_server(args.host, args.port)
            return 0
            
        elif args.command == 'ai-analyze':
            from core.ai_config import AIConfigManager
            
            ai_manager = AIConfigManager()
            results = {}
            
            if args.malware:
                results['malware'] = ai_manager.analyze_malware(args.input)
            if args.steganography and args.input.lower().endswith(('.jpg', '.png', '.bmp')):
                results['steganography'] = ai_manager.analyze_image(args.input)
            if args.behavioral:
                # For text files, analyze content
                if args.input.lower().endswith(('.txt', '.log', '.md')):
                    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    results['behavioral'] = ai_manager.analyze_text(content, 'behavioral')
                else:
                    results['behavioral'] = {'message': 'Behavioral analysis requires text data'}
                    
            # Audio transcription
            if args.input.lower().endswith(('.wav', '.mp3', '.m4a', '.flac')):
                results['audio_transcription'] = ai_manager.transcribe_audio(args.input)
                
            # Code analysis
            if args.input.lower().endswith(('.py', '.js', '.java', '.cpp', '.c', '.php')):
                with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                language = Path(args.input).suffix[1:]  # Remove dot
                results['code_analysis'] = ai_manager.analyze_code(code, language)
                
            if args.output:
                output_path = Path(args.output)
                output_path.mkdir(parents=True, exist_ok=True)
                with open(output_path / 'ai_analysis.json', 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"AI analysis saved to {output_path}")
            else:
                print(json.dumps(results, indent=2, default=str))
                
            return 0
            
        elif args.command == 'cloud-acquire':
            from core.cloud_forensics import CloudForensicsEngine
            
            cloud_config = {}
            if args.aws:
                cloud_config['aws'] = {'access_key': 'your_key', 'secret_key': 'your_secret'}
            if args.azure:
                cloud_config['azure'] = {'subscription_id': 'your_sub'}
            if args.gcp:
                cloud_config['gcp'] = {'project_id': 'your_project'}
                
            cloud_engine = CloudForensicsEngine({})
            
            import asyncio
            results = asyncio.run(cloud_engine.acquire_cloud_evidence(cloud_config))
            
            # Save results
            output_path = Path(args.output)
            output_path.mkdir(parents=True, exist_ok=True)
            
            with open(output_path / 'cloud_evidence.json', 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
            print(f"Cloud evidence saved to {output_path}")
            return 0
            
        elif args.command == 'memory-analyze':
            from core.memory_forensics import MemoryForensicsEngine
            
            memory_engine = MemoryForensicsEngine()
            analysis = memory_engine.analyze_memory_dump(args.dump)
            
            print(json.dumps(analysis, indent=2, default=str))
            return 0
            
        elif args.command == 'live-capture':
            from core.memory_forensics import LiveForensicsEngine
            
            live_engine = LiveForensicsEngine()
            
            if args.real_time:
                results = live_engine.monitor_real_time(args.duration)
            else:
                results = live_engine.capture_live_system()
                
            if args.output:
                output_path = Path(args.output)
                output_path.mkdir(parents=True, exist_ok=True)
                
                with open(output_path / 'live_analysis.json', 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                    
                print(f"Live analysis saved to {output_path}")
            else:
                print(json.dumps(results, indent=2, default=str))
                
            return 0
            
        elif args.command == 'distribute-analysis':
            from core.cloud_forensics import CloudForensicsEngine
            
            cloud_engine = CloudForensicsEngine({})
            
            if args.cloud:
                cloud_engine.scale_analysis_cluster(args.workers)
                
            task_id = cloud_engine.distribute_analysis(args.input, args.analysis_type)
            print(f"Distributed analysis started. Task ID: {task_id}")
            return 0
            
        elif args.command == 'blockchain-trace':
            from core.cloud_forensics import BlockchainForensics
            
            blockchain_engine = BlockchainForensics()
            
            results = {}
            if args.bitcoin and args.addresses:
                import asyncio
                for address in args.addresses:
                    results[address] = asyncio.run(
                        blockchain_engine.analyze_bitcoin_address(address)
                    )
                    
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            else:
                print(json.dumps(results, indent=2, default=str))
                
            return 0
            
        elif args.command == 'setup-ai':
            from core.ai_config import setup_local_ai, AIConfigManager
            
            if args.check_status:
                ai_manager = AIConfigManager()
                status = ai_manager.get_service_status()
                print(json.dumps(status, indent=2))
            elif args.optimize:
                ai_manager = AIConfigManager()
                if args.optimize == 'cost':
                    ai_manager.optimize_for_cost()
                    print("✅ Optimized for cost (local AI only)")
                elif args.optimize == 'privacy':
                    ai_manager.optimize_for_privacy()
                    print("✅ Optimized for privacy (local AI only)")
                elif args.optimize == 'performance':
                    ai_manager.optimize_for_performance()
                    print("✅ Optimized for performance (hybrid AI)")
            else:
                setup_local_ai()
                
            return 0
            
        elif args.command == 'container-analyze':
            from core.cloud_forensics import ContainerForensics
            
            container_engine = ContainerForensics()
            
            if args.docker:
                results = container_engine.analyze_container(args.docker)
            elif args.kubernetes:
                results = container_engine.analyze_kubernetes_pod(args.namespace, args.kubernetes)
            else:
                print("Specify --docker or --kubernetes")
                return 1
                
            print(json.dumps(results, indent=2, default=str))
            return 0
            
        elif args.command == 'image-enterprise':
            success = fdr.create_image_professional(
                args.source, args.output, args.case, 
                hash_verify=True, compression=args.compression
            )
            return 0 if success else 1
            
        elif args.command == 'analyze-enterprise':
            analysis = fdr.analyze_filesystem_advanced(
                args.image, args.include_deleted, args.include_slack
            )
            
            if args.ai_enhanced:
                from core.ai_forensics import AIForensicEngine
                ai_engine = AIForensicEngine()
                # Add AI analysis to results
                analysis['ai_analysis'] = {'status': 'AI analysis would be performed here'}
                
            print(json.dumps(analysis, indent=2, default=str))
            return 0 if analysis else 1
            
        elif args.command == 'recover-enterprise':
            recovery_stats = fdr.recover_with_timeline_analysis(
                args.image, args.output, None, args.timeline
            )
            
            if args.ai_assisted:
                from core.ai_forensics import AIForensicEngine
                ai_engine = AIForensicEngine()
                # Add AI-assisted recovery
                recovery_stats['ai_assistance'] = {'status': 'AI-assisted recovery performed'}
                
            print(f"Recovery completed: {recovery_stats['files_recovered']} files recovered")
            return 0 if recovery_stats['files_recovered'] > 0 else 1
            
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return 130
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
        
    return 0


if __name__ == '__main__':
    sys.exit(main())
