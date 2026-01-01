"""
Local AI Demo - What the system can do
Demonstrates forensic AI capabilities without external dependencies
"""

import re
import hashlib
import json
from pathlib import Path
from typing import Dict, List

class LocalAIDemo:
    """Demonstrate local AI forensic capabilities"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'password', 'admin', 'backdoor', 'malware', 'trojan', 'virus',
            'exploit', 'payload', 'shell', 'cmd.exe', 'powershell',
            'whoami', 'netstat', 'tasklist', 'registry', 'encrypt'
        ]
        
        self.network_indicators = [
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
            r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',   # Domains
            r':\d{1,5}\b'                          # Ports
        ]
        
    def analyze_text_content(self, text: str) -> Dict:
        """Analyze text for forensic indicators"""
        results = {
            'suspicious_keywords': [],
            'network_indicators': [],
            'sensitive_data': [],
            'risk_score': 0,
            'analysis_summary': []
        }
        
        text_lower = text.lower()
        
        # Find suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword in text_lower:
                results['suspicious_keywords'].append(keyword)
                results['risk_score'] += 1
                
        # Find network indicators
        for pattern in self.network_indicators:
            matches = re.findall(pattern, text)
            results['network_indicators'].extend(matches)
            results['risk_score'] += len(matches) * 0.5
            
        # Find sensitive data patterns
        # Credit card numbers
        cc_pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        cc_matches = re.findall(cc_pattern, text)
        if cc_matches:
            results['sensitive_data'].extend([f"Credit Card: {cc}" for cc in cc_matches])
            results['risk_score'] += len(cc_matches) * 3
            
        # SSN pattern
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        ssn_matches = re.findall(ssn_pattern, text)
        if ssn_matches:
            results['sensitive_data'].extend([f"SSN: {ssn}" for ssn in ssn_matches])
            results['risk_score'] += len(ssn_matches) * 3
            
        # Generate analysis summary
        if results['risk_score'] > 10:
            results['analysis_summary'].append("HIGH RISK: Multiple threat indicators detected")
        elif results['risk_score'] > 5:
            results['analysis_summary'].append("MEDIUM RISK: Some suspicious activity detected")
        else:
            results['analysis_summary'].append("LOW RISK: Minimal suspicious indicators")
            
        if results['suspicious_keywords']:
            results['analysis_summary'].append(f"Found {len(results['suspicious_keywords'])} suspicious keywords")
            
        if results['network_indicators']:
            results['analysis_summary'].append(f"Found {len(results['network_indicators'])} network indicators")
            
        if results['sensitive_data']:
            results['analysis_summary'].append(f"ALERT: {len(results['sensitive_data'])} sensitive data items found")
            
        return results
        
    def analyze_code_file(self, file_path: str) -> Dict:
        """Analyze code file for malicious patterns"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
        except:
            return {'error': 'Could not read file'}
            
        results = {
            'file_path': file_path,
            'file_size': len(code),
            'malicious_functions': [],
            'suspicious_imports': [],
            'risk_indicators': [],
            'risk_score': 0
        }
        
        # Check for malicious function calls
        malicious_functions = [
            'os.system', 'subprocess.call', 'subprocess.run', 'eval', 'exec',
            'socket.socket', 'base64.decode', 'urllib.request', 'requests.get'
        ]
        
        for func in malicious_functions:
            if func in code:
                results['malicious_functions'].append(func)
                results['risk_score'] += 2
                
        # Check for suspicious imports
        suspicious_imports = [
            'import os', 'import subprocess', 'import socket', 'import base64',
            'import urllib', 'import requests', 'import ctypes', 'import winreg'
        ]
        
        for imp in suspicious_imports:
            if imp in code:
                results['suspicious_imports'].append(imp)
                results['risk_score'] += 1
                
        # Check for specific risk indicators
        risk_patterns = [
            ('Command execution', ['os.system', 'subprocess']),
            ('Network communication', ['socket', 'urllib', 'requests']),
            ('Encoding/Obfuscation', ['base64', 'encode', 'decode']),
            ('File system access', ['os.walk', 'open(', 'file']),
            ('Registry access', ['winreg', 'registry']),
            ('Privilege escalation', ['admin', 'root', 'sudo'])
        ]
        
        for risk_name, patterns in risk_patterns:
            for pattern in patterns:
                if pattern in code.lower():
                    results['risk_indicators'].append(risk_name)
                    break
                    
        return results
        
    def calculate_file_entropy(self, file_path: str) -> float:
        """Calculate file entropy (measure of randomness/encryption)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except:
            return 0.0
            
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
                entropy -= probability * (probability.bit_length() - 1)
                
        return entropy
        
    def demo_analysis(self):
        """Run demonstration analysis"""
        print("🤖 Local AI Forensic Analysis Demo")
        print("=" * 50)
        
        # Test 1: Analyze investigation text
        print("\n📄 Analyzing Investigation Text...")
        try:
            with open('test_investigation.txt', 'r') as f:
                text_content = f.read()
                
            text_results = self.analyze_text_content(text_content)
            
            print(f"✅ Text Analysis Complete:")
            print(f"   Risk Score: {text_results['risk_score']:.1f}/10")
            print(f"   Suspicious Keywords: {len(text_results['suspicious_keywords'])}")
            print(f"   Network Indicators: {len(text_results['network_indicators'])}")
            print(f"   Sensitive Data Items: {len(text_results['sensitive_data'])}")
            
            for summary in text_results['analysis_summary']:
                print(f"   • {summary}")
                
        except FileNotFoundError:
            print("❌ Test file not found")
            
        # Test 2: Analyze malware code
        print("\n🦠 Analyzing Malware Code...")
        try:
            code_results = self.analyze_code_file('test_malware.py')
            
            print(f"✅ Code Analysis Complete:")
            print(f"   Risk Score: {code_results['risk_score']}/10")
            print(f"   Malicious Functions: {len(code_results['malicious_functions'])}")
            print(f"   Suspicious Imports: {len(code_results['suspicious_imports'])}")
            print(f"   Risk Indicators: {code_results['risk_indicators']}")
            
            if code_results['malicious_functions']:
                print(f"   ⚠️  Detected: {', '.join(code_results['malicious_functions'][:5])}")
                
        except FileNotFoundError:
            print("❌ Test malware file not found")
            
        # Test 3: File entropy analysis
        print("\n📊 File Entropy Analysis...")
        for test_file in ['test_malware.py', 'test_investigation.txt']:
            try:
                entropy = self.calculate_file_entropy(test_file)
                print(f"   {test_file}: {entropy:.2f} (Higher = more random/encrypted)")
            except:
                print(f"   {test_file}: Could not analyze")
                
        print("\n🎯 Demo Complete!")
        print("\nThis demonstrates LOCAL AI capabilities:")
        print("• Pattern recognition and analysis")
        print("• Threat indicator extraction") 
        print("• Risk scoring and assessment")
        print("• No external API calls required")
        print("• Complete privacy and control")
        
        return True

if __name__ == "__main__":
    demo = LocalAIDemo()
    demo.demo_analysis()