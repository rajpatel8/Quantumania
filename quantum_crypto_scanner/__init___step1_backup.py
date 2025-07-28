"""
Quantum Crypto Scanner - Enhanced Version 2.0
A tool to scan codebases for quantum-vulnerable cryptography with CBOM generation
"""

__version__ = "0.2.0"
__author__ = "Lord Rajkumar"

from .main import QuantumCryptoScanner

# Step 2 enhanced components
try:
    from .sonar_engine import SonarCryptographyEngine, EnhancedCryptoAnalyzer
    from .cbom_generator import CBOMGenerator
    ENHANCED_FEATURES = True
except ImportError:
    # Graceful degradation if enhanced components aren't available
    ENHANCED_FEATURES = False

__all__ = ["QuantumCryptoScanner"]

if ENHANCED_FEATURES:
    __all__.extend(["SonarCryptographyEngine", "EnhancedCryptoAnalyzer", "CBOMGenerator"])

# Installation instructions helper
def check_installation():
    """Check if all Step 2 components are properly installed"""
    missing_components = []
    
    try:
        from .sonar_engine import SonarCryptographyEngine
    except ImportError:
        missing_components.append("sonar_engine")
    
    try:
        from .cbom_generator import CBOMGenerator
    except ImportError:
        missing_components.append("cbom_generator")
    
    if missing_components:
        print(f"⚠️ Missing Step 2 components: {', '.join(missing_components)}")
        print("📝 Run with Step 1 compatibility mode or check installation")
        return False
    else:
        print("✅ All Step 2 components available")
        return True
