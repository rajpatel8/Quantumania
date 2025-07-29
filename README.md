# README.md

# Quantum Crypto Scanner

A tool to scan codebases for quantum-vulnerable cryptography and provide NIST-approved migration recommendations.

## Current Status: Step 1 - Base Integration

This is **Step 1** of the development process. Currently implemented:

✅ **Completed in Step 1:**
- Basic project structure
- Foundation with sonar-cryptography-inspired detection
- File scanning for common crypto patterns (RSA, ECC, DH, weak hashes)
- Quantum vulnerability identification
- JSON and summary report generation
- CLI interface
- Docker support

🚧 **Coming in Future Steps:**
- Integration with actual PQCA/sonar-cryptography
- epap011/Crypto-Scanner-PQC semantic analysis
- CBOM generation with cbomkit
- NIST PQC recommendations with OQS examples
- Semgrep rule integration
- Enhanced multi-language support

## Installation

### Method 1: Local Installation

```bash
# Clone the repository
git clone https://github.com/rajpatel8/Quantumania
cd quantum-crypto-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### Method 2: Docker

```bash
# Build the Docker image
docker build -t quantum-crypto-scanner .

# Run the scanner
docker run -v /path/to/your/code:/code quantum-crypto-scanner /code
```

## Usage

### Basic Scan

```bash
# Scan a codebase and show summary
quantum-crypto-scan /path/to/your/codebase

# Output JSON format
quantum-crypto-scan /path/to/your/codebase --format json

# Save to file
quantum-crypto-scan /path/to/your/codebase --output scan_results.json
```

### Example Output

```
🛡️  QUANTUM CRYPTOGRAPHY VULNERABILITY SCAN REPORT
============================================================

📊 SCAN SUMMARY:
• Target: /path/to/codebase
• Files Scanned: 45
• Crypto Findings: 12
• Quantum Vulnerable: 8

🚨 RISK BREAKDOWN:
• Critical Risk: 6
• High Risk: 2
• Medium Risk: 0
• Low Risk: 0

📋 QUANTUM-VULNERABLE FINDINGS:

• src/crypto/auth.py:23
  Algorithm: RSA
  Risk: CRITICAL
  Timeline: 2030-2035
  Code: private_key = RSA.generate(2048)

• src/utils/signing.py:15
  Algorithm: ECC
  Risk: CRITICAL
  Timeline: 2030-2035
  Code: key = ec.generate_private_key(ec.SECP256R1(), default_backend())
```

## Testing

Create test files to verify the scanner works:

### test_samples/vulnerable_code.py
```python
# Various quantum-vulnerable crypto patterns for testing

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib

# RSA usage (quantum-vulnerable)
def generate_rsa_key():
    key = RSA.generate(2048)
    return key

# ECC usage (quantum-vulnerable) 
def generate_ecc_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

# Weak hash (partially quantum-vulnerable)
def weak_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()

# Strong symmetric crypto (quantum-resistant for now)
def aes_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)
```

### test_samples/vulnerable_code.java
```java
// Java crypto patterns for testing

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import javax.crypto.KeyGenerator;

public class CryptoExample {
    
    // RSA usage (quantum-vulnerable)
    public KeyPair generateRSAKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    // ECC usage (quantum-vulnerable)
    public KeyPair generateECCKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        return keyGen.generateKeyPair();
    }
    
    // Weak hash
    public String weakHash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(input.getBytes());
        return bytesToHex(hash);
    }
}
```

### Run Tests

```bash
# Test the scanner on sample files
quantum-crypto-scan test_samples/ --format summary

# Expected output should show several quantum-vulnerable findings
```

## Project Structure

```
quantum-crypto-scanner/
├── quantum_crypto_scanner/
│   ├── __init__.py
│   └── main.py                 # Main scanner implementation
├── test_samples/               # Test files with vulnerable crypto
│   ├── vulnerable_code.py
│   └── vulnerable_code.java
├── tests/                      # Unit tests
│   └── test_scanner.py
├── requirements.txt            # Python dependencies
├── setup.py                   # Package setup
├── Dockerfile                 # Docker configuration
├── .gitignore
└── README.md
```

## Development Roadmap

### Step 1: ✅ Base Integration (Current)
- [x] Project structure
- [x] Basic crypto pattern detection  
- [x] Quantum vulnerability identification
- [x] CLI interface
- [x] Docker support

### Step 2: 🔄 Sonar-Cryptography Integration (Next)
- [ ] Integrate actual PQCA/sonar-cryptography
- [ ] Enhanced AST-based detection
- [ ] CBOM generation foundation

### Step 3: 🔄 PQC Scanner Integration
- [ ] Integrate epap011/Crypto-Scanner-PQC
- [ ] Semantic analysis engine
- [ ] Enhanced pattern matching

### Step 4: 🔄 CBOM & Inventory
- [ ] Integrate PQCA/cbomkit
- [ ] Standardized crypto inventory
- [ ] CI/CD integration patterns

### Step 5: 🔄 NIST PQC Recommendations
- [ ] OQS integration for examples
- [ ] NIST mapping engine
- [ ] Migration code generation

### Step 6: 🔄 Advanced Features
- [ ] Semgrep rule integration
- [ ] Performance impact analysis
- [ ] Multi-format reporting

## Contributing

This is a step-by-step development project. Each step builds on the previous one:

1. Test the current step thoroughly
2. Provide feedback on what works/doesn't work
3. Request the next step implementation
4. Repeat until complete

## License

MIT License - see LICENSE file for details.
