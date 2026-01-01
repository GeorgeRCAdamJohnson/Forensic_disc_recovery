# Local AI Setup Guide - Zero API Costs

## 🤖 **Why Local AI for Forensics?**

- **💰 Zero API Costs** - No OpenAI/Anthropic bills
- **🔒 Complete Privacy** - Sensitive data never leaves your system  
- **⚡ No Rate Limits** - Process unlimited evidence
- **🌐 Offline Capable** - Works without internet
- **🎯 Forensic-Optimized** - Models tuned for investigation tasks

## 🚀 **Quick Setup (5 minutes)**

### 1. Install Ollama (Local LLM Server)
```bash
# Linux/Mac
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download from https://ollama.ai/download/windows
```

### 2. Pull Forensic Models
```bash
# General text analysis
ollama pull llama2

# Code analysis  
ollama pull codellama

# Fast, efficient model
ollama pull mistral

# Specialized models
ollama pull dolphin-mistral  # Uncensored for forensics
ollama pull neural-chat      # Conversation analysis
```

### 3. Install Python Dependencies
```bash
pip install ollama openai-whisper transformers torch opencv-python
```

### 4. Setup Forensic Tool
```bash
python main.py setup-ai --optimize privacy
```

## 🎯 **Usage Examples**

### Analyze Suspicious Text/Logs
```bash
python main.py ai-analyze -i suspicious.txt --behavioral
```

### Code Malware Analysis  
```bash
python main.py ai-analyze -i malware.py --malware
```

### Audio Evidence Transcription
```bash
python main.py ai-analyze -i evidence.wav
```

### Image Steganography Detection
```bash
python main.py ai-analyze -i suspect.jpg --steganography
```

## 📊 **Cost Comparison**

| Service | Cost per 1M tokens | Local AI Cost |
|---------|-------------------|---------------|
| GPT-4 | $30 | **$0** |
| Claude-3 | $15 | **$0** |
| GPT-3.5 | $2 | **$0** |
| **Ollama** | **$0** | **$0** |

**Savings for large investigations: $1000s+**

## 🔧 **Configuration Options**

### Privacy-First (Recommended for Forensics)
```bash
python main.py setup-ai --optimize privacy
```
- All processing local
- Zero data transmission
- Maximum security

### Cost-Optimized
```bash
python main.py setup-ai --optimize cost  
```
- Local-only processing
- No API costs ever
- Good performance

### Performance-Optimized
```bash
python main.py setup-ai --optimize performance
```
- Hybrid local/cloud
- Best accuracy
- Higher costs

## 🎯 **Forensic-Specific Models**

### Text Analysis Models
- **llama2** - General investigation text
- **mistral** - Fast document analysis  
- **dolphin-mistral** - Uncensored content analysis
- **neural-chat** - Communication pattern analysis

### Code Analysis Models
- **codellama** - Malware source code analysis
- **starcoder** - Multi-language code review
- **wizardcoder** - Vulnerability detection

### Specialized Models
- **whisper** - Audio evidence transcription
- **clip** - Image-text correlation
- **sentence-transformers** - Semantic similarity

## 🚀 **Advanced Setup**

### GPU Acceleration (Optional)
```bash
# Install CUDA support for faster processing
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
```

### Custom Forensic Models
```bash
# Train custom models on your investigation data
python train_custom_model.py --data investigation_logs/ --type malware_detection
```

### Distributed Processing
```bash
# Run multiple Ollama instances for parallel processing
ollama serve --host 0.0.0.0:11434 &
ollama serve --host 0.0.0.0:11435 &
```

## 🔍 **Model Recommendations by Use Case**

### 🕵️ **Criminal Investigations**
- **Primary**: llama2 (general), codellama (malware)
- **Audio**: whisper-large (best accuracy)
- **Privacy**: All local processing

### 🏢 **Corporate Forensics**  
- **Primary**: mistral (fast), neural-chat (emails)
- **Code**: starcoder (source code review)
- **Hybrid**: Local + cloud for non-sensitive data

### 🛡️ **Government/Military**
- **Primary**: dolphin-mistral (uncensored)
- **Security**: Air-gapped local processing only
- **Custom**: Train domain-specific models

## 📈 **Performance Benchmarks**

### Local vs Cloud Processing Times
```
Text Analysis (1000 words):
- Ollama (local): 2-5 seconds
- GPT-4 API: 3-8 seconds + network latency

Code Analysis (500 lines):
- CodeLlama (local): 5-10 seconds  
- GPT-4 API: 8-15 seconds + network latency

Audio Transcription (1 hour):
- Whisper (local): 5-10 minutes
- Cloud services: 10-20 minutes + upload time
```

## 🔒 **Security Benefits**

1. **Data Never Leaves Your System**
   - No cloud transmission
   - No API logging
   - Complete control

2. **Compliance Ready**
   - GDPR compliant
   - HIPAA compliant  
   - Government security standards

3. **Audit Trail**
   - All processing local
   - Complete forensic chain of custody
   - No third-party dependencies

## 💡 **Pro Tips**

1. **Use GPU if available** - 5-10x faster processing
2. **Batch process files** - More efficient than one-by-one
3. **Custom prompts** - Tailor analysis to your investigation type
4. **Model switching** - Use different models for different evidence types
5. **Offline capability** - Perfect for air-gapped environments

## 🆘 **Troubleshooting**

### Ollama Not Starting
```bash
# Check if port is available
netstat -an | grep 11434

# Restart Ollama
ollama serve
```

### Out of Memory Errors
```bash
# Use smaller models
ollama pull llama2:7b  # Instead of 13b/70b

# Reduce context length
ollama run llama2 --ctx-size 2048
```

### Slow Performance
```bash
# Enable GPU acceleration
export CUDA_VISIBLE_DEVICES=0

# Use faster models
ollama pull mistral:7b
```

---

**🎯 Result: Professional forensic AI capabilities with zero ongoing costs and maximum privacy!**