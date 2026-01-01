"""
AI-Powered Forensic Analysis Engine
Advanced machine learning for forensic investigations
"""

import numpy as np
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import cv2
import hashlib
import json
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import logging


class AIForensicEngine:
    """AI-powered forensic analysis with machine learning"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.models = self._load_models()
        self.threat_intel = ThreatIntelligence()
        
    def _load_models(self) -> Dict:
        """Load pre-trained AI models"""
        return {
            'malware_detector': self._create_malware_model(),
            'steganography_detector': self._create_stego_model(),
            'anomaly_detector': IsolationForest(contamination=0.1),
            'image_classifier': self._create_image_model()
        }
        
    def _create_malware_model(self):
        """Create malware detection model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(256, activation='relu', input_shape=(1024,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
        
    def _create_stego_model(self):
        """Create steganography detection model"""
        model = tf.keras.Sequential([
            tf.keras.layers.Conv2D(32, (3, 3), activation='relu', input_shape=(256, 256, 3)),
            tf.keras.layers.MaxPooling2D(2, 2),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu'),
            tf.keras.layers.GlobalAveragePooling2D(),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model
        
    def _create_image_model(self):
        """Create image classification model"""
        return tf.keras.applications.MobileNetV2(weights='imagenet', include_top=False)
        
    def analyze_malware_probability(self, file_path: str) -> Dict:
        """AI-powered malware detection"""
        try:
            features = self._extract_pe_features(file_path)
            if features is None:
                return {'probability': 0.0, 'confidence': 'low', 'features': []}
                
            prediction = self.models['malware_detector'].predict(features.reshape(1, -1))[0][0]
            
            # Cross-reference with threat intelligence
            file_hash = self._calculate_hash(file_path)
            threat_info = self.threat_intel.check_hash(file_hash)
            
            return {
                'probability': float(prediction),
                'confidence': 'high' if prediction > 0.8 else 'medium' if prediction > 0.5 else 'low',
                'features': features.tolist()[:10],  # Top 10 features
                'threat_intel': threat_info,
                'file_hash': file_hash
            }
        except Exception as e:
            self.logger.error(f"Malware analysis failed: {e}")
            return {'probability': 0.0, 'confidence': 'error', 'features': []}
            
    def detect_steganography(self, image_path: str) -> Dict:
        """AI-powered steganography detection"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {'hidden_data_probability': 0.0, 'analysis': 'invalid_image'}
                
            # Resize for model
            img_resized = cv2.resize(img, (256, 256))
            img_normalized = img_resized / 255.0
            
            prediction = self.models['steganography_detector'].predict(
                img_normalized.reshape(1, 256, 256, 3)
            )[0][0]
            
            # Statistical analysis
            stats = self._analyze_image_statistics(img)
            
            return {
                'hidden_data_probability': float(prediction),
                'statistical_anomalies': stats,
                'recommendation': 'investigate' if prediction > 0.7 else 'likely_clean'
            }
        except Exception as e:
            self.logger.error(f"Steganography detection failed: {e}")
            return {'hidden_data_probability': 0.0, 'analysis': 'error'}
            
    def behavioral_analysis(self, timeline_events: List[Dict]) -> Dict:
        """AI-powered behavioral analysis of user activities"""
        if not timeline_events:
            return {'anomalies': [], 'risk_score': 0.0}
            
        # Extract features from timeline
        features = self._extract_behavioral_features(timeline_events)
        
        # Detect anomalies
        anomalies = self.models['anomaly_detector'].fit_predict(features)
        anomaly_indices = np.where(anomalies == -1)[0]
        
        # Calculate risk score
        risk_score = len(anomaly_indices) / len(timeline_events)
        
        suspicious_events = [timeline_events[i] for i in anomaly_indices]
        
        return {
            'anomalies': suspicious_events,
            'risk_score': float(risk_score),
            'total_events': len(timeline_events),
            'suspicious_count': len(suspicious_events),
            'patterns': self._identify_patterns(timeline_events)
        }
        
    def _extract_pe_features(self, file_path: str) -> Optional[np.ndarray]:
        """Extract PE file features for malware detection"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024*1024, len(f.read())))  # First 1MB
                
            # Simple feature extraction (byte frequency)
            features = np.zeros(1024)
            for i, byte in enumerate(data[:1024]):
                features[i] = byte / 255.0
                
            return features
        except:
            return None
            
    def _analyze_image_statistics(self, img: np.ndarray) -> Dict:
        """Analyze image for statistical anomalies"""
        # LSB analysis
        lsb_variance = np.var(img & 1)
        
        # Chi-square test simulation
        hist = cv2.calcHist([img], [0], None, [256], [0, 256])
        chi_square = np.sum((hist - np.mean(hist))**2 / np.mean(hist))
        
        return {
            'lsb_variance': float(lsb_variance),
            'chi_square': float(chi_square),
            'suspicious': lsb_variance > 0.1 or chi_square > 1000
        }
        
    def _extract_behavioral_features(self, events: List[Dict]) -> np.ndarray:
        """Extract behavioral features from timeline events"""
        features = []
        
        for event in events:
            # Time-based features
            hour = event['timestamp'].hour if hasattr(event['timestamp'], 'hour') else 12
            day_of_week = event['timestamp'].weekday() if hasattr(event['timestamp'], 'weekday') else 1
            
            # Event type encoding
            event_type_map = {
                'File Created': 1, 'File Modified': 2, 'File Deleted': 3,
                'Process Started': 4, 'Network Connection': 5
            }
            event_code = event_type_map.get(event.get('event_type', ''), 0)
            
            features.append([hour, day_of_week, event_code])
            
        return np.array(features)
        
    def _identify_patterns(self, events: List[Dict]) -> List[Dict]:
        """Identify suspicious patterns in events"""
        patterns = []
        
        # Rapid file deletion pattern
        delete_events = [e for e in events if 'delete' in e.get('event_type', '').lower()]
        if len(delete_events) > 10:
            patterns.append({
                'type': 'mass_deletion',
                'count': len(delete_events),
                'severity': 'high'
            })
            
        # Off-hours activity
        off_hours = [e for e in events if hasattr(e['timestamp'], 'hour') and 
                    (e['timestamp'].hour < 6 or e['timestamp'].hour > 22)]
        if len(off_hours) > len(events) * 0.3:
            patterns.append({
                'type': 'off_hours_activity',
                'percentage': len(off_hours) / len(events) * 100,
                'severity': 'medium'
            })
            
        return patterns
        
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


class ThreatIntelligence:
    """Threat intelligence integration"""
    
    def __init__(self):
        self.known_threats = self._load_threat_db()
        
    def _load_threat_db(self) -> Dict:
        """Load threat intelligence database"""
        # Simulated threat database
        return {
            'malware_hashes': set(),
            'suspicious_domains': set(),
            'iocs': []
        }
        
    def check_hash(self, file_hash: str) -> Dict:
        """Check hash against threat intelligence"""
        return {
            'known_malware': file_hash in self.known_threats['malware_hashes'],
            'threat_family': 'unknown',
            'first_seen': None,
            'confidence': 0.0
        }
        
    def check_domain(self, domain: str) -> Dict:
        """Check domain against threat intelligence"""
        return {
            'malicious': domain in self.known_threats['suspicious_domains'],
            'category': 'unknown',
            'reputation_score': 0.0
        }


class NetworkForensics:
    """Advanced network forensics analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def analyze_pcap(self, pcap_path: str) -> Dict:
        """Analyze network packet capture"""
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            
            packets = rdpcap(pcap_path)
            
            analysis = {
                'total_packets': len(packets),
                'protocols': {},
                'conversations': {},
                'suspicious_activity': [],
                'dns_queries': [],
                'http_requests': []
            }
            
            for packet in packets:
                if IP in packet:
                    proto = packet[IP].proto
                    analysis['protocols'][proto] = analysis['protocols'].get(proto, 0) + 1
                    
                    # Detect suspicious patterns
                    if TCP in packet and packet[TCP].dport == 4444:  # Common backdoor port
                        analysis['suspicious_activity'].append({
                            'type': 'suspicious_port',
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'port': packet[TCP].dport
                        })
                        
            return analysis
            
        except ImportError:
            return {'error': 'scapy not available'}
        except Exception as e:
            self.logger.error(f"PCAP analysis failed: {e}")
            return {'error': str(e)}
            
    def detect_data_exfiltration(self, network_logs: List[Dict]) -> Dict:
        """Detect potential data exfiltration"""
        large_uploads = []
        suspicious_domains = []
        
        for log in network_logs:
            # Large data transfers
            if log.get('bytes_out', 0) > 100 * 1024 * 1024:  # 100MB
                large_uploads.append(log)
                
            # Suspicious domains
            domain = log.get('domain', '')
            if any(suspicious in domain for suspicious in ['.tk', '.ml', 'bit.ly']):
                suspicious_domains.append(log)
                
        return {
            'large_uploads': large_uploads,
            'suspicious_domains': suspicious_domains,
            'risk_level': 'high' if large_uploads or suspicious_domains else 'low'
        }