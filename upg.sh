# Step 2 Upgrade Commands - Run these in your quantum_crypto_scanner directory

echo "🚀 Upgrading Quantum Crypto Scanner from Step 1 to Step 2..."

# 1. Backup current Step 1 files
echo "📦 Creating backup of Step 1 files..."
cp quantum_crypto_scanner/main.py quantum_crypto_scanner/main_step1_backup.py
cp quantum_crypto_scanner/__init__.py quantum_crypto_scanner/__init___step1_backup.py
cp requirements.txt requirements_step1_backup.txt
cp setup.py setup_step1_backup.py

# 2. Install enhanced dependencies
echo "📥 Installing enhanced dependencies..."
pip install lxml pyyaml jinja2 click

# 3. Create the new Step 2 files
echo "📝 Creating Step 2 files..."

# You need to create these files with content from the artifacts:
echo "⚠️  MANUAL STEP: Create these files from the artifacts above:"
echo "   - quantum_crypto_scanner/sonar_engine.py"
echo "   - quantum_crypto_scanner/cbom_generator.py" 
echo "   - tests/test_enhanced_scanner.py"
echo "   - Replace quantum_crypto_scanner/main.py with Step 2 version"
echo "   - Replace quantum_crypto_scanner/__init__.py with Step 2 version"
echo "   - Replace requirements.txt with Step 2 version"
echo "   - Replace setup.py with Step 2 version"

# 4. Reinstall package
echo "🔧 Reinstalling package..."
pip install -e .

# 5. Test Step 2 installation
echo "🧪 Testing Step 2 installation..."

# Test that Step 2 components load
python -c "
try:
    from quantum_crypto_scanner import QuantumCryptoScanner
    from quantum_crypto_scanner.sonar_engine import SonarCryptographyEngine
    from quantum_crypto_scanner.cbom_generator import CBOMGenerator
    print('✅ Step 2 components loaded successfully')
except ImportError as e:
    print(f'❌ Step 2 component import failed: {e}')
    print('⚠️  Will fall back to Step 1 compatibility mode')
"

# Test backward compatibility
echo "🔙 Testing Step 1 backward compatibility..."
quantum-crypto-scan test_samples/ --legacy-mode --format summary

# Test Step 2 enhanced features
echo "✨ Testing Step 2 enhanced features..."
quantum-crypto-scan test_samples/ --format enhanced_summary

# Test CBOM generation
echo "📋 Testing CBOM generation..."
quantum-crypto-scan test_samples/ --format cbom

# Run test suite
echo "🧪 Running test suite..."
pytest tests/ -v

echo "🎉 Step 2 upgrade complete!"
echo ""
echo "📊 Quick comparison:"
echo "Step 1 (legacy mode):    quantum-crypto-scan test_samples/ --legacy-mode"
echo "Step 2 (enhanced):       quantum-crypto-scan test_samples/ --format enhanced_summary"
echo "Step 2 (CBOM):          quantum-crypto-scan test_samples/ --format cbom"