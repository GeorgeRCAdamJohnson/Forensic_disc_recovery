#!/usr/bin/env python3
"""
Test Local AI Integration
Quick test of forensic AI capabilities
"""

import sys
import json
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_ai_config():
    """Test AI configuration manager"""
    print("🤖 Testing Local AI Configuration...")
    
    try:
        from core.ai_config import AIConfigManager
        
        # Initialize AI manager
        ai_manager = AIConfigManager()
        print("✅ AI Config Manager initialized")
        
        # Check service status
        status = ai_manager.get_service_status()
        print(f"📊 Service Status:")
        
        for service, info in status['local_services'].items():
            status_icon = "✅" if info['available'] else "❌"
            print(f"   {status_icon} {service.title()}: {'Available' if info['available'] else 'Not Available'}")
            
        if status['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in status['recommendations']:
                print(f"   • {rec}")
                
        return ai_manager, status
        
    except Exception as e:
        print(f"❌ Error testing AI config: {e}")
        return None, None

def test_local_ai_analysis():
    """Test local AI analysis capabilities"""
    print("\n🔍 Testing Local AI Analysis...")
    
    try:
        from core.local_ai import LocalAIForensics
        
        local_ai = LocalAIForensics()
        print("✅ Local AI Engine initialized")
        
        # Test text analysis (without Ollama for now)
        test_text = "This is a suspicious message containing password and admin credentials"
        
        # Test document analysis with HuggingFace (if available)
        try:
            result = local_ai.analyze_document_with_huggingface(test_text)
            print("✅ HuggingFace analysis working")
            print(f"   Sentiment: {result.get('sentiment', 'N/A')}")
            print(f"   Entities: {list(result.get('entities', {}).keys())}")
        except Exception as e:
            print(f"⚠️  HuggingFace not available: {e}")
            
        # Test basic string analysis
        indicators = local_ai._extract_indicators(test_text)
        print(f"✅ Indicator extraction: {len(indicators)} indicators found")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing local AI: {e}")
        return False

def test_malware_analysis():
    """Test malware analysis on a sample file"""
    print("\n🦠 Testing Malware Analysis...")
    
    try:
        from core.local_ai import LocalAIForensics
        
        # Create a test file
        test_file = Path("test_sample.txt")
        test_content = """
        import os
        import subprocess
        
        def suspicious_function():
            os.system("cmd.exe /c whoami")
            subprocess.call(["powershell", "-Command", "Get-Process"])
            password = "admin123"
            return password
        """
        
        test_file.write_text(test_content)
        
        local_ai = LocalAIForensics()
        result = local_ai.malware_analysis_local(str(test_file))
        
        print("✅ Malware analysis completed")
        print(f"   Risk Score: {result.get('risk_score', 0)}/10")
        print(f"   Analysis Methods: {result.get('analysis_methods', [])}")
        print(f"   Entropy Score: {result.get('entropy_score', 0):.2f}")
        
        # Cleanup
        test_file.unlink()
        
        return result
        
    except Exception as e:
        print(f"❌ Error testing malware analysis: {e}")
        return None

def test_image_analysis():
    """Test image analysis capabilities"""
    print("\n🖼️  Testing Image Analysis...")
    
    try:
        from core.local_ai import LocalAIForensics
        import numpy as np
        import cv2
        
        # Create a test image
        test_image = np.random.randint(0, 255, (100, 100, 3), dtype=np.uint8)
        test_image_path = "test_image.jpg"
        cv2.imwrite(test_image_path, test_image)
        
        local_ai = LocalAIForensics()
        result = local_ai.analyze_image_with_local_cv(test_image_path)
        
        print("✅ Image analysis completed")
        print(f"   Dimensions: {result.get('dimensions', {})}")
        print(f"   Faces detected: {result.get('faces_detected', 0)}")
        print(f"   Steganography score: {result.get('steganography_score', 0):.3f}")
        
        # Cleanup
        Path(test_image_path).unlink()
        
        return result
        
    except Exception as e:
        print(f"❌ Error testing image analysis: {e}")
        return None

def main():
    """Run all tests"""
    print("🚀 Forensic AI Integration Test Suite")
    print("=" * 50)
    
    # Test 1: AI Configuration
    ai_manager, status = test_ai_config()
    
    # Test 2: Local AI Analysis
    local_ai_working = test_local_ai_analysis()
    
    # Test 3: Malware Analysis
    malware_result = test_malware_analysis()
    
    # Test 4: Image Analysis
    image_result = test_image_analysis()
    
    # Summary
    print("\n📋 Test Summary:")
    print("=" * 30)
    
    tests_passed = 0
    total_tests = 4
    
    if ai_manager:
        print("✅ AI Configuration Manager: PASS")
        tests_passed += 1
    else:
        print("❌ AI Configuration Manager: FAIL")
        
    if local_ai_working:
        print("✅ Local AI Analysis: PASS")
        tests_passed += 1
    else:
        print("❌ Local AI Analysis: FAIL")
        
    if malware_result:
        print("✅ Malware Analysis: PASS")
        tests_passed += 1
    else:
        print("❌ Malware Analysis: FAIL")
        
    if image_result:
        print("✅ Image Analysis: PASS")
        tests_passed += 1
    else:
        print("❌ Image Analysis: FAIL")
        
    print(f"\n🎯 Overall: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! Local AI integration is working!")
    elif tests_passed > 0:
        print("⚠️  Partial functionality available. Check missing dependencies.")
    else:
        print("❌ Tests failed. Check installation and dependencies.")
        
    # Show next steps
    if status and status.get('recommendations'):
        print(f"\n💡 To enable full functionality:")
        for rec in status['recommendations']:
            print(f"   • {rec}")

if __name__ == "__main__":
    main()