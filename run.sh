#!/bin/bash

# Quantum Crypto Scanner - Complete Setup and Run Script
# This script sets up and runs the quantum crypto vulnerability scanner

set -e  # Exit on any error

echo "🛡️  Quantum Crypto Scanner - Setup and Run Script"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if we're in the right directory
if [ ! -f "setup.py" ] || [ ! -f "README.md" ]; then
    print_error "Please run this script from the quantum-crypto-scanner project root directory"
    print_info "Expected files: setup.py, README.md"
    exit 1
fi

print_status "Found project files - proceeding with setup"

# Step 1: Python Environment Setup
echo ""
echo "🐍 Step 1: Setting up Python environment..."

# Check Python version
python_version=$(python3 --version 2>/dev/null || echo "Not found")
print_info "Python version: $python_version"

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_info "Creating virtual environment..."
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Step 2: Install Dependencies
echo ""
echo "📦 Step 2: Installing dependencies..."

# Upgrade pip
pip install --upgrade pip

# Install requirements
if [ -f "requirements.txt" ]; then
    print_info "Installing from requirements.txt..."
    pip install -r requirements.txt
else
    print_warning "requirements.txt not found, installing basic dependencies..."
    pip install pathlib2 typing-extensions lxml pytest pytest-cov
fi

# Install the package
print_info "Installing quantum-crypto-scanner package..."
pip install -e .

print_status "Dependencies installed successfully"

# Step 3: Verify Installation
echo ""
echo "🔧 Step 3: Verifying installation..."

# Test import
python3 -c "
try:
    from quantum_crypto_scanner import QuantumCryptoScanner
    print('✅ Base scanner import successful')
except ImportError as e:
    print(f'❌ Base scanner import failed: {e}')
    exit(1)

try:
    from quantum_crypto_scanner.sonar_engine import SonarCryptographyEngine
    from quantum_crypto_scanner.cbom_generator import CBOMGenerator
    print('✅ Enhanced Step 2 components available')
    step2_available = True
except ImportError:
    print('⚠️  Step 2 components not available - running in Step 1 mode')
    step2_available = False
"

# Test CLI command
if command -v quantum-crypto-scan &> /dev/null; then
    print_status "CLI command 'quantum-crypto-scan' is available"
else
    print_warning "CLI command not found in PATH, using python -m instead"
fi

# Step 4: Create Test Samples (if they don't exist)
echo ""
echo "📝 Step 4: Ensuring test samples exist..."

mkdir -p test_samples

if [ ! -f "test_samples/vulnerable_code.py" ]; then
    print_info "Creating test_samples/vulnerable_code.py..."
    cat > test_samples/vulnerable_code.py << 'EOF'
"""
Sample vulnerable code for testing the scanner
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import hashlib

# RSA usage (quantum-vulnerable)
def generate_rsa_key():
    key = RSA.generate(2048)
    return key

def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

# ECC usage (quantum-vulnerable) 
def generate_ecc_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

def ecdsa_sign(message, private_key):
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

# Weak hash (partially quantum-vulnerable)
def weak_hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

def weak_hash_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

# Strong symmetric crypto (quantum-resistant for now)
def aes_encrypt(data, key):
    from Crypto.Cipher import AES
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

# Safe function without crypto
def safe_function():
    return "This function doesn't use cryptography"
EOF
fi

if [ ! -f "test_samples/vulnerable_code.java" ]; then
    print_info "Creating test_samples/vulnerable_code.java..."
    cat > test_samples/vulnerable_code.java << 'EOF'
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.KeyGenerator;

public class VulnerableCode {
    
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
    
    // ECDSA usage (quantum-vulnerable)
    public byte[] ecdsaSign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
    
    // Weak hash
    public String weakHashSHA1(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(input.getBytes());
        return bytesToHex(hash);
    }
    
    public String weakHashMD5(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes());
        return bytesToHex(hash);
    }
    
    // AES (quantum-resistant for now)
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
EOF
fi

print_status "Test samples ready"

# Step 5: Run the Scanner
echo ""
echo "🔍 Step 5: Running Quantum Crypto Scanner..."

# Create results directory
mkdir -p results
cd results

# Function to run scanner with error handling
run_scan() {
    local format=$1
    local output_file=$2
    local description=$3
    
    print_info "Running scan: $description"
    
    if command -v quantum-crypto-scan &> /dev/null; then
        quantum-crypto-scan ../test_samples --format "$format" --output "$output_file" || {
            print_warning "CLI command failed, trying python module..."
            python3 -m quantum_crypto_scanner.main ../test_samples --format "$format" --output "$output_file"
        }
    else
        python3 -m quantum_crypto_scanner.main ../test_samples --format "$format" --output "$output_file"
    fi
    
    if [ -f "$output_file" ]; then
        print_status "✅ $description completed -> $output_file"
    else
        print_warning "⚠️  $description output file not created"
    fi
}

# Run different scan formats
echo ""
echo "📊 Running scans with different output formats..."

# 1. Enhanced Summary (Step 2)
echo ""
echo "1️⃣  Enhanced Summary Report..."
run_scan "enhanced_summary" "enhanced_summary.txt" "Enhanced Summary"

# 2. JSON Report  
echo ""
echo "2️⃣  JSON Report..."
run_scan "json" "scan_results.json" "JSON Report"

# 3. CBOM (Cryptography Bill of Materials)
echo ""
echo "3️⃣  CBOM Report..."
run_scan "cbom" "cbom_report.json" "CBOM"

# 4. Legacy Summary (Step 1 compatibility)
echo ""
echo "4️⃣  Legacy Summary..."
run_scan "summary" "legacy_summary.txt" "Legacy Summary"

cd ..

# Step 6: Display Results
echo ""
echo "📋 Step 6: Displaying scan results..."

echo ""
echo "=================================================="
echo "🏆 SCAN RESULTS SUMMARY"
echo "=================================================="

# Show enhanced summary if available
if [ -f "results/enhanced_summary.txt" ]; then
    echo ""
    echo "📊 ENHANCED SUMMARY REPORT:"
    echo "------------------------"
    head -n 30 results/enhanced_summary.txt
    echo ""
    echo "(Full report saved to: results/enhanced_summary.txt)"
elif [ -f "results/legacy_summary.txt" ]; then
    echo ""
    echo "📊 SUMMARY REPORT:"
    echo "-----------------"
    head -n 30 results/legacy_summary.txt
    echo ""
    echo "(Full report saved to: results/legacy_summary.txt)"
fi

# Show JSON snippet
if [ -f "results/scan_results.json" ]; then
    echo ""
    echo "📄 JSON RESULTS SNIPPET:"
    echo "------------------------"
    echo "Structure preview:"
    python3 -c "
import json
try:
    with open('results/scan_results.json', 'r') as f:
        data = json.load(f)
    print('Keys:', list(data.keys()))
    if 'summary' in data:
        print('Summary keys:', list(data['summary'].keys()))
except Exception as e:
    print(f'Error reading JSON: {e}')
" 2>/dev/null || echo "JSON structure not available"
fi

# Show CBOM info
if [ -f "results/cbom_report.json" ]; then
    echo ""
    echo "📋 CBOM (Crypto Bill of Materials) INFO:"
    echo "----------------------------------------"
    python3 -c "
import json
try:
    with open('results/cbom_report.json', 'r') as f:
        cbom = json.load(f)
    print(f'CBOM Format: {cbom.get(\"bomFormat\", \"Unknown\")}')
    print(f'Spec Version: {cbom.get(\"specVersion\", \"Unknown\")}')
    print(f'Components: {len(cbom.get(\"components\", []))}')
    print(f'Vulnerabilities: {len(cbom.get(\"vulnerabilities\", []))}')
    if 'quantumReadiness' in cbom:
        qr = cbom['quantumReadiness']
        print(f'Quantum Readiness: {qr.get(\"status\", \"Unknown\")} (Score: {qr.get(\"score\", 0)})')
except Exception as e:
    print(f'Error reading CBOM: {e}')
" 2>/dev/null || echo "CBOM analysis not available"
fi

# Step 7: File Summary
echo ""
echo "📁 Generated Files:"
echo "==================="
if [ -d "results" ]; then
    ls -la results/ | grep -v "^total" | tail -n +2 | while read line; do
        echo "📄 $line"
    done
fi

echo ""
echo "🎯 Quick Access Commands:"
echo "========================="
echo "View enhanced summary:  cat results/enhanced_summary.txt"
echo "View JSON results:      cat results/scan_results.json | jq ."
echo "View CBOM:             cat results/cbom_report.json | jq ."
echo "View legacy summary:    cat results/legacy_summary.txt"

echo ""
echo "🔍 Re-run specific scans:"
echo "========================="
echo "Enhanced scan:          quantum-crypto-scan test_samples/ --format enhanced_summary"
echo "JSON output:            quantum-crypto-scan test_samples/ --format json"
echo "CBOM generation:        quantum-crypto-scan test_samples/ --format cbom"
echo "Legacy mode:            quantum-crypto-scan test_samples/ --legacy-mode"

echo ""
echo "🧪 Run tests:"
echo "============="
echo "pytest tests/ -v"

print_status "Quantum Crypto Scanner setup and execution completed!"
print_info "Check the 'results/' directory for all generated reports"

# Optional: Run tests
echo ""
read -p "🧪 Would you like to run the test suite? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🧪 Running test suite..."
    pytest tests/ -v --tb=short || print_warning "Some tests may have failed - check output above"
fi

echo ""
print_status "🎉 All done! Happy quantum crypto hunting! 🔒"