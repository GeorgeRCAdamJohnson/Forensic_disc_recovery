# Quick Start Guide - Forensic Disc Recovery Tool

## Installation

1. Ensure Python 3.8+ is installed
2. Navigate to the project directory:
   ```bash
   cd forensic_disc_Recovery
   ```

## Basic Usage

### 1. Create a Forensic Image

```bash
python main.py image -s /dev/sda -o evidence/disk.dd
```

This creates:
- `evidence/disk.dd` - The disc image
- `evidence/disk.dd.hashes` - Hash verification file

### 2. Analyze the File System

```bash
python main.py analyze -i evidence/disk.dd
```

Save analysis to a report:
```bash
python main.py analyze -i evidence/disk.dd -r reports/analysis.html
```

### 3. Recover Deleted Files

Recover all file types:
```bash
python main.py recover -i evidence/disk.dd -o recovered/
```

Recover specific types only:
```bash
python main.py recover -i evidence/disk.dd -o recovered/ -t jpg,pdf,docx
```

### 4. Data Carving

```bash
python main.py carve -i evidence/disk.dd -o carved/ -sig jpeg,png,pdf
```

## Typical Workflow

```bash
# Step 1: Create forensic image
python main.py image -s /dev/sdb -o case001/evidence.dd

# Step 2: Analyze the file system
python main.py analyze -i case001/evidence.dd -r case001/analysis.html

# Step 3: Recover deleted files
python main.py recover -i case001/evidence.dd -o case001/recovered/

# Step 4: Data carving for additional recovery
python main.py carve -i case001/evidence.dd -o case001/carved/
```

## Tips

- Always work with copies, never modify original evidence
- Use `-v` flag for verbose output: `python main.py -v recover ...`
- Check `logs/` directory for operation logs
- Hash files are automatically created and should be preserved
- Reports are saved in HTML format by default

## Getting Help

View all commands:
```bash
python main.py --help
```

View help for specific command:
```bash
python main.py recover --help
```

## Running Examples

```bash
python examples.py
```

## Running Tests

```bash
python -m pytest tests/ -v
```
