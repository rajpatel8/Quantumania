#!/bin/bash
# test_fixes.sh - Test the Step 2 fixes

echo "🧪 Testing Quantum Crypto Scanner Step 2 Fixes"
echo "=============================================="

# Set up environment
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

echo ""
echo "1️⃣ Testing Step 2 component availability..."
python3 -c "
try:
    from quantum_crypto_scanner import QuantumCryptoScanner
    print('✅ Main scanner imports successfully')
    
    scanner = QuantumCryptoScanner()
    print('✅ Scanner initializes successfully')
    
    # Test Step 2 component availability
    try:
        from quantum_crypto_scanner.sonar_engine import SonarCryptographyEngine, EnhancedCryptoAnalyzer
        from quantum_crypto_scanner.cbom_generator import CBOMGenerator
        print('✅ Step 2 components available')
        STEP2_AVAILABLE = True
    except ImportError as e:
        print(f'⚠️ Step 2 components not available: {e}')
        print('📝 Will test fallback mode')
        STEP2_AVAILABLE = False
    
    # Test backward compatibility methods
    if hasattr(scanner, '_scan_file_for_crypto'):
        print('✅ Backward compatibility method _scan_file_for_crypto available')
    else:
        print('❌ Missing _scan_file_for_crypto method')
        
    if hasattr(scanner, '_identify_quantum_vulnerable'):
        print('✅ Backward compatibility method _identify_quantum_vulnerable available')
    else:
        print('❌ Missing _identify_quantum_vulnerable method')
        
except Exception as e:
    print(f'❌ Import/initialization failed: {e}')
    exit(1)
"

echo ""
echo "2️⃣ Running specific failing tests..."

echo ""
echo "🔬 Test: Scanner initialization and setup"
python3 -c "
from quantum_crypto_scanner import QuantumCryptoScanner
scanner = QuantumCryptoScanner()
result = scanner.setup_environment()
print(f'Setup result: {result}')
scanner.cleanup()
print('✅ Setup and cleanup test passed')
"

echo ""
echo "🔬 Test: Basic scan functionality"
python3 -c "
import tempfile
from pathlib import Path
from quantum_crypto_scanner import QuantumCryptoScanner

# Create test file
with tempfile.TemporaryDirectory() as temp_dir:
    test_file = Path(temp_dir) / 'test.py'
    test_file.write_text('''
from Crypto.PublicKey import RSA
import hashlib

def test():
    key = RSA.generate(2048)
    hash_val = hashlib.md5(b'test').hexdigest()
    return key, hash_val
''')
    
    scanner = QuantumCryptoScanner()
    scanner.setup_environment()
    
    try:
        results = scanner.scan_codebase(str(temp_dir))
        print(f'✅ Scan completed successfully')
        
        # Check data structure
        assert 'target_path' in results, 'Missing target_path in results'
        assert 'scan_metadata' in results, 'Missing scan_metadata in results'
        assert 'sonar_cryptography_results' in results, 'Missing sonar_cryptography_results'
        
        sonar_results = results['sonar_cryptography_results']
        assert 'crypto_findings' in sonar_results, 'Missing crypto_findings'
        assert 'files_analyzed' in sonar_results, 'Missing files_analyzed'
        assert 'files_scanned' in sonar_results, 'Missing files_scanned (backward compatibility)'
        
        print(f'✅ Data structure validation passed')
        print(f'   Files analyzed: {sonar_results[\"files_analyzed\"]}')
        print(f'   Crypto findings: {len(sonar_results[\"crypto_findings\"])}')
        
    finally:
        scanner.cleanup()
"

echo ""
echo "3️⃣ Running pytest on specific failing tests..."

echo ""
echo "🧪 Running individual test methods:"

# Test each failing method individually
echo "   - test_scanner_initialization"
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_scanner_initialization -v

echo "   - test_setup_environment"  
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_setup_environment -v

echo "   - test_file_crypto_detection"
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_file_crypto_detection -v

echo "   - test_quantum_vulnerability_identification"
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_quantum_vulnerability_identification -v

echo "   - test_full_codebase_scan"
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_full_codebase_scan -v

echo "   - test_report_generation_json"
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_report_generation_json -v

echo ""
echo "4️⃣ Running full test suite..."
python3 -m pytest tests/test_scanner.py -v --tb=short

echo ""
echo "5️⃣ Testing CLI functionality..."
echo "🖥️ Testing CLI with test samples..."

# Test CLI
if [ -d "test_samples" ]; then
    echo "   - Legacy mode"
    python3 -m quantum_crypto_scanner.main test_samples/ --legacy-mode --format summary
    
    echo "   - Enhanced mode"  
    python3 -m quantum_crypto_scanner.main test_samples/ --format enhanced_summary
    
    echo "   - CBOM generation"
    python3 -m quantum_crypto_scanner.main test_samples/ --format cbom > /dev/null
    
    echo "✅ CLI tests completed"
else
    echo "⚠️ test_samples directory not found - skipping CLI tests"
fi

echo ""
echo "🏁 Test Summary Complete!"
echo "Check the output above for any remaining issues."