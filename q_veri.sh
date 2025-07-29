#!/bin/bash
# quick_verify.sh - Quick verification of current state

echo "🔍 Quick Verification of Quantum Crypto Scanner"
echo "=============================================="

echo ""
echo "1️⃣ Testing results structure..."
python3 debug_results.py

echo ""
echo "2️⃣ Running a simple pytest test..."
python3 -m pytest tests/test_scanner.py::TestQuantumCryptoScanner::test_report_generation_json -v

echo ""
echo "3️⃣ Testing CLI basic functionality..."
echo "Creating minimal test file..."
mkdir -p temp_test
cat > temp_test/simple.py << 'EOF'
from Crypto.PublicKey import RSA
def test():
    return RSA.generate(2048)
EOF

echo "Testing CLI scan..."
quantum-crypto-scan temp_test/ --format summary | head -20

echo ""
echo "Cleaning up..."
rm -rf temp_test

echo ""
echo "✅ Verification complete!"