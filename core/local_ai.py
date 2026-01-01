"""
Local AI Integration for Forensic Analysis
Ollama, Hugging Face Transformers, and other local AI tools
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import subprocess
import torch
from transformers import pipeline, AutoTokenizer, AutoModel
import ollama
import whisper
import cv2
import numpy as np


class LocalAIForensics:
    """Local AI tools for forensic analysis - no API costs"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.ollama_available = self._check_ollama()
        self.whisper_model = None
        self.hf_models = {}
        
    def _check_ollama(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=5)
            return response.status_code == 200
        except:
            return False
            
    def analyze_text_with_ollama(self, text: str, model: str = "llama2") -> Dict:
        """Analyze text using local Ollama model"""
        if not self.ollama_available:
            return {'error': 'Ollama not available'}
            
        try:
            # Forensic-specific prompt
            prompt = f"""
            Analyze this text for forensic investigation purposes:
            
            Text: {text[:2000]}  # Limit text length
            
            Identify:
            1. Suspicious keywords or phrases
            2. Potential evidence of malicious activity
            3. Communication patterns
            4. Timestamps or dates mentioned
            5. Technical indicators (IPs, domains, file paths)
            
            Provide analysis in JSON format.
            """
            
            response = ollama.chat(model=model, messages=[
                {'role': 'user', 'content': prompt}
            ])
            
            return {
                'model': model,
                'analysis': response['message']['content'],
                'suspicious_indicators': self._extract_indicators(response['message']['content']),
                'confidence': 0.8  # Local model confidence
            }
            
        except Exception as e:
            self.logger.error(f"Ollama analysis failed: {e}")
            return {'error': str(e)}
            
    def analyze_code_with_ollama(self, code: str, language: str = "unknown") -> Dict:
        """Analyze code for malicious patterns using Ollama"""
        if not self.ollama_available:
            return {'error': 'Ollama not available'}
            
        try:
            prompt = f"""
            Analyze this {language} code for potential security issues or malicious behavior:
            
            Code:
            {code[:1500]}
            
            Look for:
            1. Suspicious function calls
            2. Network connections
            3. File system operations
            4. Encryption/obfuscation
            5. Privilege escalation attempts
            
            Rate risk level (1-10) and explain findings.
            """
            
            response = ollama.chat(model="codellama", messages=[
                {'role': 'user', 'content': prompt}
            ])
            
            return {
                'language': language,
                'analysis': response['message']['content'],
                'risk_indicators': self._extract_risk_indicators(response['message']['content']),
                'model': 'codellama'
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def transcribe_audio_evidence(self, audio_path: str) -> Dict:
        """Transcribe audio evidence using local Whisper"""
        try:
            if self.whisper_model is None:
                self.whisper_model = whisper.load_model("base")
                
            result = self.whisper_model.transcribe(audio_path)
            
            # Analyze transcription with Ollama if available
            analysis = {}
            if self.ollama_available and result['text']:
                analysis = self.analyze_text_with_ollama(result['text'])
                
            return {
                'transcription': result['text'],
                'language': result.get('language', 'unknown'),
                'segments': result.get('segments', []),
                'forensic_analysis': analysis,
                'model': 'whisper-base'
            }
            
        except Exception as e:
            self.logger.error(f"Audio transcription failed: {e}")
            return {'error': str(e)}
            
    def analyze_image_with_local_cv(self, image_path: str) -> Dict:
        """Analyze images using local OpenCV and basic ML"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {'error': 'Could not load image'}
                
            # Basic image analysis
            height, width, channels = img.shape
            
            # Detect faces (potential privacy concerns)
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            faces = face_cascade.detectMultiScale(gray, 1.1, 4)
            
            # Check for potential steganography (basic statistical analysis)
            stego_score = self._basic_stego_detection(img)
            
            # Extract EXIF if available
            exif_data = self._extract_basic_exif(image_path)
            
            return {
                'dimensions': {'width': width, 'height': height, 'channels': channels},
                'faces_detected': len(faces),
                'steganography_score': stego_score,
                'exif_data': exif_data,
                'file_size': Path(image_path).stat().st_size,
                'analysis_method': 'local_opencv'
            }
            
        except Exception as e:
            return {'error': str(e)}
            
    def analyze_document_with_huggingface(self, text: str) -> Dict:
        """Analyze documents using local Hugging Face models"""
        try:
            # Load sentiment analysis model (lightweight)
            if 'sentiment' not in self.hf_models:
                self.hf_models['sentiment'] = pipeline(
                    "sentiment-analysis",
                    model="distilbert-base-uncased-finetuned-sst-2-english",
                    device=0 if torch.cuda.is_available() else -1
                )
                
            # Load NER model for entity extraction
            if 'ner' not in self.hf_models:
                self.hf_models['ner'] = pipeline(
                    "ner",
                    model="dbmdz/bert-large-cased-finetuned-conll03-english",
                    device=0 if torch.cuda.is_available() else -1
                )
                
            # Analyze sentiment
            sentiment = self.hf_models['sentiment'](text[:512])  # Limit length
            
            # Extract entities
            entities = self.hf_models['ner'](text[:512])
            
            # Group entities by type
            entity_groups = {}
            for entity in entities:
                entity_type = entity['entity'].replace('B-', '').replace('I-', '')
                if entity_type not in entity_groups:
                    entity_groups[entity_type] = []
                entity_groups[entity_type].append(entity['word'])
                
            return {
                'sentiment': sentiment[0] if sentiment else None,
                'entities': entity_groups,
                'forensic_relevance': self._assess_forensic_relevance(entity_groups),
                'model': 'local_huggingface'
            }
            
        except Exception as e:
            self.logger.error(f"HuggingFace analysis failed: {e}")
            return {'error': str(e)}
            
    def malware_analysis_local(self, file_path: str) -> Dict:
        """Local malware analysis using multiple approaches"""
        results = {
            'file_path': file_path,
            'file_size': Path(file_path).stat().st_size,
            'analysis_methods': []
        }
        
        # 1. Static analysis with strings
        strings_analysis = self._extract_suspicious_strings(file_path)
        results['strings_analysis'] = strings_analysis
        results['analysis_methods'].append('strings_extraction')
        
        # 2. Entropy analysis
        entropy_score = self._calculate_entropy(file_path)
        results['entropy_score'] = entropy_score
        results['analysis_methods'].append('entropy_analysis')
        
        # 3. PE header analysis (if Windows executable)
        if file_path.lower().endswith('.exe'):
            pe_analysis = self._basic_pe_analysis(file_path)
            results['pe_analysis'] = pe_analysis
            results['analysis_methods'].append('pe_analysis')
            
        # 4. Code analysis with Ollama (if available)
        if self.ollama_available:
            try:
                with open(file_path, 'rb') as f:
                    sample_bytes = f.read(1024).decode('utf-8', errors='ignore')
                code_analysis = self.analyze_code_with_ollama(sample_bytes)
                results['ai_analysis'] = code_analysis
                results['analysis_methods'].append('ollama_code_analysis')
            except:
                pass
                
        # Calculate overall risk score
        results['risk_score'] = self._calculate_risk_score(results)
        
        return results
        
    def _extract_indicators(self, text: str) -> List[str]:
        """Extract suspicious indicators from text"""
        indicators = []
        
        # Simple regex patterns for common indicators
        import re
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        indicators.extend(re.findall(ip_pattern, text))
        
        # Domain names
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        indicators.extend(re.findall(domain_pattern, text))
        
        # File paths
        path_pattern = r'[A-Za-z]:\\[^\\/:*?"<>|\r\n]+|/[^\\/:*?"<>|\r\n]+'
        indicators.extend(re.findall(path_pattern, text))
        
        return list(set(indicators))  # Remove duplicates
        
    def _extract_risk_indicators(self, analysis: str) -> List[str]:
        """Extract risk indicators from code analysis"""
        risk_keywords = [
            'suspicious', 'malicious', 'dangerous', 'risk', 'threat',
            'vulnerability', 'exploit', 'backdoor', 'trojan', 'virus'
        ]
        
        indicators = []
        for keyword in risk_keywords:
            if keyword.lower() in analysis.lower():
                indicators.append(keyword)
                
        return indicators
        
    def _basic_stego_detection(self, img: np.ndarray) -> float:
        """Basic steganography detection using statistical analysis"""
        try:
            # LSB analysis - check for unusual patterns in least significant bits
            lsb_layer = img & 1
            lsb_variance = np.var(lsb_layer)
            
            # Chi-square test simulation
            hist = cv2.calcHist([img], [0], None, [256], [0, 256])
            chi_square = np.sum((hist - np.mean(hist))**2 / np.mean(hist))
            
            # Normalize score (0-1, higher = more suspicious)
            score = min(1.0, (lsb_variance * chi_square) / 10000)
            return float(score)
            
        except:
            return 0.0
            
    def _extract_basic_exif(self, image_path: str) -> Dict:
        """Extract basic EXIF data"""
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            image = Image.open(image_path)
            exifdata = image.getexif()
            
            exif_dict = {}
            for tag_id in exifdata:
                tag = TAGS.get(tag_id, tag_id)
                data = exifdata.get(tag_id)
                exif_dict[tag] = str(data)
                
            return exif_dict
            
        except:
            return {}
            
    def _assess_forensic_relevance(self, entities: Dict) -> Dict:
        """Assess forensic relevance of extracted entities"""
        relevance_score = 0
        relevant_entities = []
        
        # High relevance entity types
        high_relevance = ['PER', 'ORG', 'LOC']  # Person, Organization, Location
        
        for entity_type, entity_list in entities.items():
            if entity_type in high_relevance:
                relevance_score += len(entity_list) * 2
                relevant_entities.extend(entity_list)
            else:
                relevance_score += len(entity_list)
                
        return {
            'relevance_score': min(10, relevance_score),  # Cap at 10
            'high_value_entities': relevant_entities[:10]  # Top 10
        }
        
    def _extract_suspicious_strings(self, file_path: str) -> Dict:
        """Extract suspicious strings from file"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Extract printable strings
            strings = []
            current_string = ""
            
            for byte in content:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""
                    
            # Filter for suspicious patterns
            suspicious_strings = []
            suspicious_keywords = [
                'password', 'admin', 'root', 'backdoor', 'shell',
                'cmd.exe', 'powershell', 'wget', 'curl', 'download'
            ]
            
            for string in strings:
                for keyword in suspicious_keywords:
                    if keyword.lower() in string.lower():
                        suspicious_strings.append(string)
                        break
                        
            return {
                'total_strings': len(strings),
                'suspicious_strings': suspicious_strings[:20],  # Top 20
                'suspicious_count': len(suspicious_strings)
            }
            
        except:
            return {'error': 'Could not extract strings'}
            
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate file entropy (measure of randomness)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if not data:
                return 0.0
                
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
                
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * np.log2(probability)
                    
            return entropy
            
        except:
            return 0.0
            
    def _basic_pe_analysis(self, file_path: str) -> Dict:
        """Basic PE file analysis"""
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if dos_header[:2] != b'MZ':
                    return {'error': 'Not a valid PE file'}
                    
                # Get PE header offset
                pe_offset = int.from_bytes(dos_header[60:64], 'little')
                
                # Read PE signature
                f.seek(pe_offset)
                pe_signature = f.read(4)
                
                if pe_signature != b'PE\x00\x00':
                    return {'error': 'Invalid PE signature'}
                    
                # Read COFF header
                coff_header = f.read(20)
                machine = int.from_bytes(coff_header[0:2], 'little')
                num_sections = int.from_bytes(coff_header[2:4], 'little')
                timestamp = int.from_bytes(coff_header[4:8], 'little')
                
                return {
                    'machine_type': hex(machine),
                    'num_sections': num_sections,
                    'timestamp': timestamp,
                    'is_pe': True
                }
                
        except:
            return {'error': 'PE analysis failed'}
            
    def _calculate_risk_score(self, analysis_results: Dict) -> float:
        """Calculate overall risk score from analysis results"""
        score = 0.0
        
        # Entropy score (high entropy = potential packing/encryption)
        entropy = analysis_results.get('entropy_score', 0)
        if entropy > 7.5:
            score += 3.0
        elif entropy > 6.0:
            score += 1.5
            
        # Suspicious strings
        strings_analysis = analysis_results.get('strings_analysis', {})
        suspicious_count = strings_analysis.get('suspicious_count', 0)
        score += min(3.0, suspicious_count * 0.5)
        
        # AI analysis risk indicators
        ai_analysis = analysis_results.get('ai_analysis', {})
        risk_indicators = ai_analysis.get('risk_indicators', [])
        score += min(2.0, len(risk_indicators) * 0.5)
        
        # Normalize to 0-10 scale
        return min(10.0, score)


def setup_local_ai_environment():
    """Setup script for local AI tools"""
    print("🤖 Setting up Local AI Environment for Forensics...")
    
    setup_commands = [
        "# Install Ollama (if not installed)",
        "# curl -fsSL https://ollama.ai/install.sh | sh",
        "",
        "# Pull forensic-useful models",
        "ollama pull llama2",
        "ollama pull codellama", 
        "ollama pull mistral",
        "",
        "# Install Python packages",
        "pip install torch transformers whisper-openai opencv-python pillow",
        "",
        "# Test installation",
        "python -c \"import torch; print('PyTorch:', torch.__version__)\"",
        "python -c \"import transformers; print('Transformers available')\"",
        "python -c \"import whisper; print('Whisper available')\"",
    ]
    
    for cmd in setup_commands:
        print(cmd)
        
    return {
        'ollama_models': ['llama2', 'codellama', 'mistral'],
        'python_packages': ['torch', 'transformers', 'whisper-openai', 'opencv-python'],
        'estimated_disk_space': '10-15 GB for models',
        'estimated_setup_time': '30-60 minutes'
    }