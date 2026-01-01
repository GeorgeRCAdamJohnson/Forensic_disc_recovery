"""
Logger Module
Configures logging for forensic operations with proper chain of custody
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional


def setup_logger(name: str, log_file: Optional[str] = None, 
                verbose: bool = False) -> logging.Logger:
    """
    Set up a logger with file and console handlers
    
    Args:
        name: Logger name (typically __name__)
        log_file: Optional log file path
        verbose: Enable verbose (DEBUG) logging
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Set log level
    log_level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(log_level)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
        
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter if not verbose else detailed_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Always detailed in file
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    else:
        # Create default log file in logs directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_log = log_dir / f'forensic_{timestamp}.log'
        
        file_handler = logging.FileHandler(default_log, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
        
    return logger


class ForensicLogger:
    """
    Specialized logger for forensic operations with chain of custody tracking
    """
    
    def __init__(self, case_name: str, investigator: str):
        """
        Initialize forensic logger
        
        Args:
            case_name: Name/ID of the forensic case
            investigator: Name of the investigator
        """
        self.case_name = case_name
        self.investigator = investigator
        self.log_file = Path('evidence_logs') / f'{case_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger = logging.getLogger(f'forensic.{case_name}')
        self.logger.setLevel(logging.DEBUG)
        
        # Create handler
        handler = logging.FileHandler(self.log_file, encoding='utf-8')
        handler.setLevel(logging.DEBUG)
        
        # Detailed formatter with chain of custody info
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Write header
        self._write_header()
        
    def _write_header(self):
        """Write forensic log header"""
        self.logger.info("=" * 80)
        self.logger.info(f"FORENSIC INVESTIGATION LOG")
        self.logger.info(f"Case: {self.case_name}")
        self.logger.info(f"Investigator: {self.investigator}")
        self.logger.info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info("=" * 80)
        
    def log_evidence_acquisition(self, source: str, destination: str, 
                                hash_md5: str, hash_sha256: str):
        """
        Log evidence acquisition
        
        Args:
            source: Source device/path
            destination: Destination image path
            hash_md5: MD5 hash of acquired evidence
            hash_sha256: SHA256 hash of acquired evidence
        """
        self.logger.info("--- EVIDENCE ACQUISITION ---")
        self.logger.info(f"Source: {source}")
        self.logger.info(f"Destination: {destination}")
        self.logger.info(f"MD5: {hash_md5}")
        self.logger.info(f"SHA256: {hash_sha256}")
        self.logger.info(f"Acquired by: {self.investigator}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        
    def log_analysis(self, image_path: str, analysis_type: str, results: dict):
        """
        Log analysis operation
        
        Args:
            image_path: Path to analyzed image
            analysis_type: Type of analysis performed
            results: Analysis results dictionary
        """
        self.logger.info("--- ANALYSIS OPERATION ---")
        self.logger.info(f"Image: {image_path}")
        self.logger.info(f"Analysis Type: {analysis_type}")
        self.logger.info(f"Results: {results}")
        self.logger.info(f"Performed by: {self.investigator}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        
    def log_recovery(self, image_path: str, recovery_type: str, 
                    files_recovered: int, output_dir: str):
        """
        Log recovery operation
        
        Args:
            image_path: Path to source image
            recovery_type: Type of recovery performed
            files_recovered: Number of files recovered
            output_dir: Output directory for recovered files
        """
        self.logger.info("--- RECOVERY OPERATION ---")
        self.logger.info(f"Source Image: {image_path}")
        self.logger.info(f"Recovery Type: {recovery_type}")
        self.logger.info(f"Files Recovered: {files_recovered}")
        self.logger.info(f"Output Directory: {output_dir}")
        self.logger.info(f"Performed by: {self.investigator}")
        self.logger.info(f"Timestamp: {datetime.now().isoformat()}")
        
    def log_error(self, operation: str, error: str):
        """
        Log error during forensic operation
        
        Args:
            operation: Operation being performed
            error: Error description
        """
        self.logger.error("--- ERROR ENCOUNTERED ---")
        self.logger.error(f"Operation: {operation}")
        self.logger.error(f"Error: {error}")
        self.logger.error(f"Timestamp: {datetime.now().isoformat()}")
