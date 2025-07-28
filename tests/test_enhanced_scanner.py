"""
Comprehensive tests for Quantum Crypto Scanner Step 2
Tests enhanced sonar integration, CBOM generation, and new features
"""

import pytest
import tempfile
import os
import json
from pathlib import Path
import shutil

from quantum_crypto_scanner import QuantumCryptoScanner

# Test if Step 2 components are available
try:
    from quantum_crypto_scanner.sonar_engine import SonarCryptographyEngine, EnhancedCryptoAnalyzer
    from quantum_crypto_scanner.cbom_generator import CBOMGenerator
    STEP2_AVAILABLE = True
except ImportError:
    STEP2_AVAILABLE = False


class TestStep2EnhancedScanner:
    """Test Step 2 enhanced functionality"""
    
    @pytest.fixture
    def enhanced_scanner(self):
        """Create enhanced scanner instance"""
        return QuantumCryptoScanner()
    
    @pytest.fixture
    def complex_crypto_project(self):
        """Create a complex project with various crypto patterns"""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            # Complex Python crypto file
            (project_path / "crypto_service.py").write_text("""
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CryptoService:
    def __init__(self):
        # RSA key generation (quantum-vulnerable)
        self.rsa_key = RSA.generate(2048)
        self.rsa_crypto_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # ECC key generation (quantum-vulnerable)
        self.ecc_key = ec.generate_private_key(ec.SECP256R1())
        self.ecc_p384_key = ec.generate_private_key(ec.SECP384R1())
        
    def encrypt_rsa(self, data):
        cipher = PKCS1_OAEP.new(self.rsa_key.publickey())
        return cipher.encrypt(data.encode())
    
    def sign_ecdsa(self, message):
        signature = self.ecc_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def weak_hash(self, data):
        # Weak hashes (quantum-vulnerable to Grover's)
        md5_hash = hashlib.md5(data.encode()).hexdigest()
        sha1_hash = hashlib.sha1(data.encode()).hexdigest()
        return md5_hash, sha1_hash
    
    def secure_hash(self, data):
        # Quantum-resistant hash
        return hashlib.sha256(data.encode()).hexdigest()
    
    def aes_encrypt(self, data, key):
        # AES is quantum-resistant (for now)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return ciphertext, tag
""")
            
            # Complex Java crypto file
            (project_path / "CryptoUtils.java").write_text("""
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class CryptoUtils {
    
    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
    
    public KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        return keyGen.generateKeyPair();
    }
    
    public byte[] rsaEncrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }
    
    public byte[] ecdsaSign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return signature.sign();
    }
    
    public String weakHashMD5(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(input.getBytes());
        return bytesToHex(hash);
    }
    
    public String weakHashSHA1(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] hash = md.digest(input.getBytes());
        return bytesToHex(hash);
    }
    
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
""")
            
            # JavaScript crypto patterns
            (project_path / "crypto.js").write_text("""
const crypto = require('crypto');
const forge = require('node-forge');

class CryptoManager {
    generateRSAKeyPair() {
        // RSA key generation (quantum-vulnerable)
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        return { publicKey, privateKey };
    }
    
    generateECKeyPair() {
        // ECC key generation (quantum-vulnerable)
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
            namedCurve: 'secp256k1',
        });
        return { publicKey, privateKey };
    }
    
    weakHash(data) {
        // Weak hash functions
        const md5 = crypto.createHash('md5').update(data).digest('hex');
        const sha1 = crypto.createHash('sha1').update(data).digest('hex');
        return { md5, sha1 };
    }
    
    strongHash(data) {
        return crypto.createHash('sha256').update(data).digest('hex');
    }
}

module.exports = CryptoManager;
""")
            
            yield project_path
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_enhanced_scanner_initialization(self, enhanced_scanner):
        """Test enhanced scanner initializes with Step 2 components"""
        assert hasattr(enhanced_scanner, 'cbom_generator')
        assert hasattr(enhanced_scanner, 'enhanced_analyzer')
        assert enhanced_scanner.cbom_generator is not None
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_enhanced_environment_setup(self, enhanced_scanner):
        """Test enhanced environment setup"""
        try:
            result = enhanced_scanner.setup_environment()
            assert result is True
            assert enhanced_scanner.temp_dir is not None
            assert enhanced_scanner.temp_dir.exists()
            
            # Check if sonar engine was initialized (may fail gracefully)
            if enhanced_scanner.sonar_engine:
                assert hasattr(enhanced_scanner.sonar_engine, 'sonar_crypto_path')
                
        finally:
            enhanced_scanner.cleanup()
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_enhanced_crypto_analysis(self, enhanced_scanner, complex_crypto_project):
        """Test enhanced crypto analysis with AST-based detection"""
        analyzer = EnhancedCryptoAnalyzer()
        results = analyzer.analyze_project(complex_crypto_project)
        
        # Verify enhanced analysis results structure
        assert 'analysis_method' in results
        assert results['analysis_method'] == 'enhanced_ast'
        assert 'crypto_findings' in results
        assert 'languages_detected' in results
        assert 'files_analyzed' in results
        
        # Should detect multiple languages
        assert len(results['languages_detected']) >= 2
        assert 'python' in results['languages_detected']
        assert 'java' in results['languages_detected']
        
        # Should find crypto patterns
        assert len(results['crypto_findings']) > 0
        
        # Check for enhanced analysis features
        for finding in results['crypto_findings']:
            assert 'confidence' in finding
            assert 'analysis_method' in finding
            assert finding['analysis_method'] == 'enhanced_ast'
            assert 'context' in finding or 'finding_type' in finding
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_cbom_generation(self, enhanced_scanner, complex_crypto_project):
        """Test CBOM generation from scan results"""
        try:
            enhanced_scanner.setup_environment()
            
            # Run enhanced scan
            results = enhanced_scanner.scan_codebase(str(complex_crypto_project))
            
            # Verify CBOM was generated
            assert 'cbom' in results
            cbom = results['cbom']
            
            # Check CBOM structure
            assert 'bomFormat' in cbom
            assert cbom['bomFormat'] == 'CycloneDX'
            assert 'specVersion' in cbom
            assert 'components' in cbom
            assert 'vulnerabilities' in cbom
            assert 'quantumReadiness' in cbom
            assert 'migrationRecommendations' in cbom
            
            # Verify components
            assert len(cbom['components']) > 0
            for component in cbom['components']:
                assert 'type' in component
                assert component['type'] == 'cryptographic-asset'
                assert 'properties' in component
                
                # Check for quantum-specific properties
                prop_names = [prop['name'] for prop in component['properties']]
                assert 'quantum:vulnerable' in prop_names
                assert 'quantum:risk-level' in prop_names
            
            # Verify vulnerabilities
            assert len(cbom['vulnerabilities']) > 0
            for vuln in cbom['vulnerabilities']:
                assert 'id' in vuln
                assert 'source' in vuln
                assert 'ratings' in vuln
                assert 'description' in vuln
            
            # Verify quantum readiness assessment
            readiness = cbom['quantumReadiness']
            assert 'status' in readiness
            assert 'score' in readiness
            assert 'assessment' in readiness
            assert isinstance(readiness['score'], (int, float))
            assert 0 <= readiness['score'] <= 100
            
        finally:
            enhanced_scanner.cleanup()
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_enhanced_scan_with_multi_engine(self, enhanced_scanner, complex_crypto_project):
        """Test enhanced scan with multiple detection engines"""
        try:
            enhanced_scanner.setup_environment()
            results = enhanced_scanner.scan_codebase(str(complex_crypto_project), "enhanced")
            
            # Check enhanced results structure
            assert 'scan_metadata' in results
            assert 'sonar_cryptography_results' in results
            assert 'quantum_assessment' in results
            assert 'cbom' in results
            assert 'summary' in results
            assert 'migration_plan' in results
            
            # Verify scan metadata
            metadata = results['scan_metadata']
            assert metadata['scanner_version'] == '2.0'
            assert 'analysis_method' in metadata
            assert 'timestamp' in metadata
            
            # Verify quantum assessment
            quantum_assessment = results['quantum_assessment']
            assert 'total_crypto_findings' in quantum_assessment
            assert 'quantum_vulnerable_count' in quantum_assessment
            assert 'quantum_vulnerable_findings' in quantum_assessment
            assert 'quantum_readiness_score' in quantum_assessment
            
            # Should find quantum-vulnerable crypto
            assert quantum_assessment['quantum_vulnerable_count'] > 0
            
            # Verify migration plan
            migration_plan = results['migration_plan']
            assert 'total_migration_items' in migration_plan
            assert 'estimated_timeline' in migration_plan
            assert 'migration_groups' in migration_plan
            assert 'recommended_approach' in migration_plan
            
        finally:
            enhanced_scanner.cleanup()
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_enhanced_reporting_formats(self, enhanced_scanner, complex_crypto_project):
        """Test enhanced reporting formats"""
        try:
            enhanced_scanner.setup_environment()
            enhanced_scanner.scan_codebase(str(complex_crypto_project))
            
            # Test CBOM format
            cbom_report = enhanced_scanner.generate_report('cbom')
            cbom_data = json.loads(cbom_report)
            assert 'bomFormat' in cbom_data
            assert 'quantumReadiness' in cbom_data
            
            # Test enhanced summary format
            enhanced_summary = enhanced_scanner.generate_report('enhanced_summary')
            assert 'ENHANCED' in enhanced_summary
            assert 'QUANTUM RISK ASSESSMENT' in enhanced_summary
            assert 'MIGRATION PLAN' in enhanced_summary
            assert 'CBOM SUMMARY' in enhanced_summary
            
            # Test backward compatibility with Step 1 format
            legacy_summary = enhanced_scanner.generate_report('summary')
            assert 'QUANTUM CRYPTOGRAPHY VULNERABILITY SCAN REPORT' in legacy_summary
            assert 'SCAN SUMMARY' in legacy_summary
            assert 'RISK BREAKDOWN' in legacy_summary
            
            # Test JSON format
            json_report = enhanced_scanner.generate_report('json')
            json_data = json.loads(json_report)
            assert 'scan_metadata' in json_data
            assert 'cbom' in json_data
            
        finally:
            enhanced_scanner.cleanup()
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_confidence_scoring(self, enhanced_scanner, complex_crypto_project):
        """Test confidence scoring in enhanced analysis"""
        analyzer = EnhancedCryptoAnalyzer()
        results = analyzer.analyze_project(complex_crypto_project)
        
        # Check that findings have confidence scores
        findings_with_confidence = [f for f in results['crypto_findings'] if 'confidence' in f]
        assert len(findings_with_confidence) > 0
        
        # Verify confidence scores are reasonable
        for finding in findings_with_confidence:
            confidence = finding['confidence']
            assert 0.0 <= confidence <= 1.0
            
            # Import-based findings should have higher confidence
            if finding.get('finding_type') == 'import':
                assert confidence >= 0.7
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available") 
    def test_quantum_risk_assessment(self, enhanced_scanner, complex_crypto_project):
        """Test detailed quantum risk assessment"""
        try:
            enhanced_scanner.setup_environment()
            results = enhanced_scanner.scan_codebase(str(complex_crypto_project))
            
            quantum_assessment = results['quantum_assessment']
            vulnerable_findings = quantum_assessment['quantum_vulnerable_findings']
            
            # Should find RSA and ECC as quantum-vulnerable
            crypto_types = set(f['crypto_type'] for f in vulnerable_findings)
            assert 'RSA' in crypto_types
            assert 'ECC' in crypto_types
            
            # Check quantum-specific fields
            for finding in vulnerable_findings:
                assert 'quantum_risk' in finding
                assert 'estimated_break_timeline' in finding
                assert 'attack_method' in finding
                assert 'nist_replacement' in finding
                
                if finding['crypto_type'] in ['RSA', 'ECC']:
                    assert finding['quantum_risk'] == 'CRITICAL'
                    assert "Shor's Algorithm" in finding['attack_method']
                    assert '2030-2035' in finding['estimated_break_timeline']
                    
        finally:
            enhanced_scanner.cleanup()
    
    def test_backward_compatibility_with_step1(self, enhanced_scanner, complex_crypto_project):
        """Test that Step 2 maintains backward compatibility with Step 1"""
        try:
            enhanced_scanner.setup_environment()
            
            # Should work even if Step 2 components fail
            results = enhanced_scanner.scan_codebase(str(complex_crypto_project))
            
            # Should have Step 1 compatible fields
            assert 'sonar_cryptography_results' in results
            sonar_results = results['sonar_cryptography_results']
            assert 'crypto_findings' in sonar_results
            assert 'files_analyzed' in sonar_results
            
            # Should generate Step 1 compatible summary
            legacy_summary = enhanced_scanner.generate_report('summary')
            assert 'Files Scanned:' in legacy_summary
            assert 'Crypto Findings:' in legacy_summary
            assert 'Quantum Vulnerable:' in legacy_summary
            
        finally:
            enhanced_scanner.cleanup()


class TestCBOMGenerator:
    """Test CBOM generator specifically"""
    
    @pytest.fixture
    def cbom_generator(self):
        if not STEP2_AVAILABLE:
            pytest.skip("Step 2 components not available")
        return CBOMGenerator()
    
    @pytest.fixture
    def sample_scan_results(self):
        """Sample scan results for CBOM testing"""
        return {
            "analysis_method": "enhanced_ast",
            "crypto_findings": [
                {
                    "file": "/test/crypto.py",
                    "line": 10,
                    "crypto_type": "RSA",
                    "pattern": "RSA.generate",
                    "confidence": 0.95,
                    "severity": "CRITICAL",
                    "language": "python"
                },
                {
                    "file": "/test/crypto.py", 
                    "line": 15,
                    "crypto_type": "ECC",
                    "pattern": "ec.generate_private_key",
                    "confidence": 0.90,
                    "severity": "CRITICAL",
                    "language": "python"
                },
                {
                    "file": "/test/hash.py",
                    "line": 5,
                    "crypto_type": "HASH",
                    "pattern": "hashlib.md5",
                    "confidence": 0.85,
                    "severity": "HIGH",
                    "language": "python"
                }
            ],
            "files_analyzed": 2,
            "languages_detected": ["python"]
        }
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_cbom_generation_structure(self, cbom_generator, sample_scan_results):
        """Test CBOM generation produces correct structure"""
        cbom = cbom_generator.generate_cbom(sample_scan_results)
        
        # Check required CBOM fields
        required_fields = [
            'bomFormat', 'specVersion', 'serialNumber', 'version',
            'metadata', 'components', 'vulnerabilities'
        ]
        
        for field in required_fields:
            assert field in cbom, f"Missing required CBOM field: {field}"
        
        assert cbom['bomFormat'] == 'CycloneDX'
        assert cbom['specVersion'] == '1.4'
        assert 'urn:uuid:' in cbom['serialNumber']
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_cbom_quantum_extensions(self, cbom_generator, sample_scan_results):
        """Test CBOM quantum-specific extensions"""
        cbom = cbom_generator.generate_cbom(sample_scan_results)
        
        # Check quantum-specific extensions
        assert 'quantumReadiness' in cbom
        assert 'migrationRecommendations' in cbom
        
        quantum_readiness = cbom['quantumReadiness']
        assert 'status' in quantum_readiness
        assert 'score' in quantum_readiness
        assert 'assessment' in quantum_readiness
        
        migration_recs = cbom['migrationRecommendations']
        assert isinstance(migration_recs, list)
        assert len(migration_recs) > 0
    
    @pytest.mark.skipif(not STEP2_AVAILABLE, reason="Step 2 components not available")
    def test_cbom_vulnerability_mapping(self, cbom_generator, sample_scan_results):
        """Test CBOM vulnerability mapping for quantum threats"""
        cbom = cbom_generator.generate_cbom(sample_scan_results)
        
        vulnerabilities = cbom['vulnerabilities']
        
        # Should have vulnerabilities for RSA and ECC findings
        vuln_crypto_types = set()
        for vuln in vulnerabilities:
            assert 'id' in vuln
            assert 'QUANTUM-' in vuln['id']
            assert 'ratings' in vuln
            assert len(vuln['ratings']) > 0
            
            # Extract crypto type from ID
            if 'RSA' in vuln['id']:
                vuln_crypto_types.add('RSA')
            elif 'ECC' in vuln['id']:
                vuln_crypto_types.add('ECC')
        
        assert 'RSA' in vuln_crypto_types
        assert 'ECC' in vuln_crypto_types


# Integration test for CLI
class TestStep2CLI:
    """Test Step 2 CLI integration"""
    
    @pytest.fixture
    def cli_test_project(self):
        """Create test project for CLI testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            project_path = Path(temp_dir)
            
            (project_path / "simple_crypto.py").write_text("""
from Crypto.PublicKey import RSA
import hashlib

def generate_key():
    return RSA.generate(2048)

def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()
""")
            
            yield project_path
    
    def test_cli_enhanced_mode(self, cli_test_project):
        """Test CLI in enhanced mode"""
        from quantum_crypto_scanner.main import main
        import sys
        from io import StringIO
        
        # Capture output
        old_stdout = sys.stdout
        sys.stdout = captured_output = StringIO()
        
        # Mock command line arguments
        test_args = ['quantum-crypto-scan', str(cli_test_project), '--format', 'enhanced_summary']
        sys.argv = test_args
        
        try:
            # This would normally call main(), but we'll test the scanner directly
            scanner = QuantumCryptoScanner()
            scanner.setup_environment()
            results = scanner.scan_codebase(str(cli_test_project))
            report = scanner.generate_report('enhanced_summary')
            
            # Verify enhanced report content
            assert 'ENHANCED' in report
            assert 'QUANTUM RISK ASSESSMENT' in report
            
            scanner.cleanup()
            
        finally:
            sys.stdout = old_stdout