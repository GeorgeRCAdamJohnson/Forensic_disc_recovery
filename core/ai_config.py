"""
AI Configuration Manager
Switch between local AI (Ollama, HuggingFace) and cloud services
"""

import json
import logging
from typing import Dict, List, Optional, Union
from pathlib import Path
import requests
from .local_ai import LocalAIForensics
from .ai_forensics import AIForensicEngine


class AIConfigManager:
    """Manage AI service configuration and routing"""
    
    def __init__(self, config_path: str = "ai_config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.logger = logging.getLogger(__name__)
        self.local_ai = LocalAIForensics()
        self.cloud_ai = AIForensicEngine() if self.config.get('cloud_enabled') else None
        
    def _load_config(self) -> Dict:
        """Load AI configuration"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return self._create_default_config()
        
    def _create_default_config(self) -> Dict:
        """Create default AI configuration"""
        config = {
            "ai_preference": "local",  # local, cloud, hybrid
            "local_services": {
                "ollama": {
                    "enabled": True,
                    "url": "http://localhost:11434",
                    "models": {
                        "text_analysis": "llama2",
                        "code_analysis": "codellama", 
                        "general": "mistral"
                    }
                },
                "huggingface": {
                    "enabled": True,
                    "models": {
                        "sentiment": "distilbert-base-uncased-finetuned-sst-2-english",
                        "ner": "dbmdz/bert-large-cased-finetuned-conll03-english"
                    }
                },
                "whisper": {
                    "enabled": True,
                    "model": "base"
                }
            },
            "cloud_services": {
                "enabled": False,
                "openai": {
                    "api_key": "",
                    "model": "gpt-3.5-turbo"
                },
                "anthropic": {
                    "api_key": "",
                    "model": "claude-3-sonnet"
                }
            },
            "fallback_strategy": "local_only",  # local_only, cloud_fallback, best_available
            "privacy_mode": True,  # Prefer local processing for sensitive data
            "cost_optimization": True  # Prefer free/local services
        }
        
        self._save_config(config)
        return config
        
    def _save_config(self, config: Dict):
        """Save configuration to file"""
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
            
    def analyze_text(self, text: str, analysis_type: str = "general") -> Dict:
        """Route text analysis to appropriate AI service"""
        if self.config["privacy_mode"] and self._contains_sensitive_data(text):
            return self._analyze_text_local(text, analysis_type)
            
        preference = self.config["ai_preference"]
        
        if preference == "local" or not self.cloud_ai:
            return self._analyze_text_local(text, analysis_type)
        elif preference == "cloud":
            return self._analyze_text_cloud(text, analysis_type)
        else:  # hybrid
            return self._analyze_text_hybrid(text, analysis_type)
            
    def analyze_code(self, code: str, language: str = "unknown") -> Dict:
        """Route code analysis to appropriate AI service"""
        # Always use local for code analysis (privacy)
        if self.config["privacy_mode"]:
            return self.local_ai.analyze_code_with_ollama(code, language)
            
        # Try local first, fallback to cloud if needed
        local_result = self.local_ai.analyze_code_with_ollama(code, language)
        if 'error' not in local_result:
            return local_result
            
        if self.cloud_ai and self.config["fallback_strategy"] == "cloud_fallback":
            return self._analyze_code_cloud(code, language)
            
        return local_result
        
    def analyze_malware(self, file_path: str) -> Dict:
        """Route malware analysis to appropriate service"""
        # Always local for malware analysis (security)
        local_result = self.local_ai.malware_analysis_local(file_path)
        
        # Add cloud analysis only if explicitly enabled and not privacy mode
        if (not self.config["privacy_mode"] and 
            self.cloud_ai and 
            self.config["ai_preference"] == "hybrid"):
            
            try:
                cloud_result = self.cloud_ai.analyze_malware_probability(file_path)
                local_result['cloud_analysis'] = cloud_result
            except:
                pass
                
        return local_result
        
    def transcribe_audio(self, audio_path: str) -> Dict:
        """Route audio transcription to appropriate service"""
        # Always use local Whisper for privacy
        return self.local_ai.transcribe_audio_evidence(audio_path)
        
    def analyze_image(self, image_path: str) -> Dict:
        """Route image analysis to appropriate service"""
        local_result = self.local_ai.analyze_image_with_local_cv(image_path)
        
        # Add steganography detection if available
        if self.cloud_ai and not self.config["privacy_mode"]:
            try:
                stego_result = self.cloud_ai.detect_steganography(image_path)
                local_result['advanced_stego_analysis'] = stego_result
            except:
                pass
                
        return local_result
        
    def _analyze_text_local(self, text: str, analysis_type: str) -> Dict:
        """Analyze text using local services"""
        results = {}
        
        # Ollama analysis
        if self.config["local_services"]["ollama"]["enabled"]:
            model = self.config["local_services"]["ollama"]["models"].get(
                analysis_type, "llama2"
            )
            ollama_result = self.local_ai.analyze_text_with_ollama(text, model)
            results['ollama'] = ollama_result
            
        # HuggingFace analysis
        if self.config["local_services"]["huggingface"]["enabled"]:
            hf_result = self.local_ai.analyze_document_with_huggingface(text)
            results['huggingface'] = hf_result
            
        return {
            'service': 'local',
            'cost': 0.0,
            'privacy': 'high',
            'results': results
        }
        
    def _analyze_text_cloud(self, text: str, analysis_type: str) -> Dict:
        """Analyze text using cloud services"""
        if not self.cloud_ai:
            return {'error': 'Cloud AI not configured'}
            
        # This would integrate with cloud services
        return {
            'service': 'cloud',
            'cost': 'estimated_cost',
            'privacy': 'low',
            'results': {'message': 'Cloud analysis would be implemented here'}
        }
        
    def _analyze_text_hybrid(self, text: str, analysis_type: str) -> Dict:
        """Analyze text using hybrid approach"""
        local_result = self._analyze_text_local(text, analysis_type)
        
        # Add cloud analysis for comparison
        if not self._contains_sensitive_data(text):
            cloud_result = self._analyze_text_cloud(text, analysis_type)
            return {
                'service': 'hybrid',
                'local': local_result,
                'cloud': cloud_result,
                'recommendation': 'local' if self.config["privacy_mode"] else 'best_available'
            }
            
        return local_result
        
    def _analyze_code_cloud(self, code: str, language: str) -> Dict:
        """Analyze code using cloud services (if privacy allows)"""
        return {'message': 'Cloud code analysis not implemented for privacy reasons'}
        
    def _contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive data"""
        sensitive_keywords = [
            'password', 'ssn', 'social security', 'credit card',
            'bank account', 'personal', 'confidential', 'classified'
        ]
        
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in sensitive_keywords)
        
    def get_service_status(self) -> Dict:
        """Get status of all AI services"""
        status = {
            'local_services': {},
            'cloud_services': {},
            'recommendations': []
        }
        
        # Check Ollama
        try:
            response = requests.get('http://localhost:11434/api/tags', timeout=5)
            status['local_services']['ollama'] = {
                'available': response.status_code == 200,
                'models': response.json().get('models', []) if response.status_code == 200 else []
            }
        except:
            status['local_services']['ollama'] = {'available': False, 'models': []}
            
        # Check HuggingFace
        try:
            import transformers
            status['local_services']['huggingface'] = {
                'available': True,
                'version': transformers.__version__
            }
        except ImportError:
            status['local_services']['huggingface'] = {'available': False}
            
        # Check Whisper
        try:
            import whisper
            status['local_services']['whisper'] = {
                'available': True,
                'models': whisper.available_models()
            }
        except ImportError:
            status['local_services']['whisper'] = {'available': False}
            
        # Generate recommendations
        if not status['local_services']['ollama']['available']:
            status['recommendations'].append(
                "Install Ollama for local text/code analysis: curl -fsSL https://ollama.ai/install.sh | sh"
            )
            
        if not status['local_services']['huggingface']['available']:
            status['recommendations'].append(
                "Install transformers: pip install transformers torch"
            )
            
        if not status['local_services']['whisper']['available']:
            status['recommendations'].append(
                "Install Whisper: pip install openai-whisper"
            )
            
        return status
        
    def optimize_for_cost(self):
        """Optimize configuration for minimal cost"""
        self.config["ai_preference"] = "local"
        self.config["fallback_strategy"] = "local_only"
        self.config["cost_optimization"] = True
        self.config["cloud_services"]["enabled"] = False
        self._save_config(self.config)
        
    def optimize_for_privacy(self):
        """Optimize configuration for maximum privacy"""
        self.config["ai_preference"] = "local"
        self.config["privacy_mode"] = True
        self.config["fallback_strategy"] = "local_only"
        self.config["cloud_services"]["enabled"] = False
        self._save_config(self.config)
        
    def optimize_for_performance(self):
        """Optimize configuration for best performance"""
        self.config["ai_preference"] = "hybrid"
        self.config["fallback_strategy"] = "best_available"
        self.config["cloud_services"]["enabled"] = True
        self._save_config(self.config)


def setup_local_ai():
    """Interactive setup for local AI services"""
    print("🤖 Local AI Setup for Forensic Analysis")
    print("=" * 50)
    
    # Check current status
    ai_manager = AIConfigManager()
    status = ai_manager.get_service_status()
    
    print("\n📊 Current Service Status:")
    for service, info in status['local_services'].items():
        status_icon = "✅" if info['available'] else "❌"
        print(f"   {status_icon} {service.title()}: {'Available' if info['available'] else 'Not Available'}")
        
    print("\n🔧 Setup Recommendations:")
    for rec in status['recommendations']:
        print(f"   • {rec}")
        
    print("\n💡 Configuration Options:")
    print("   1. Cost-Optimized (Local only, $0 cost)")
    print("   2. Privacy-Focused (Local only, maximum privacy)")
    print("   3. Performance-Optimized (Hybrid, best results)")
    
    choice = input("\nSelect configuration (1-3): ").strip()
    
    if choice == "1":
        ai_manager.optimize_for_cost()
        print("✅ Configured for cost optimization")
    elif choice == "2":
        ai_manager.optimize_for_privacy()
        print("✅ Configured for privacy optimization")
    elif choice == "3":
        ai_manager.optimize_for_performance()
        print("✅ Configured for performance optimization")
    else:
        print("Using default configuration")
        
    return ai_manager