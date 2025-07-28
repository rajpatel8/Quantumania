# quantum_crypto_scanner/main.py
"""
Quantum Crypto Vulnerability Scanner
Step 1: Base setup with sonar-cryptography integration
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import shutil

class QuantumCryptoScanner:
    """Main scanner class that orchestrates different detection engines"""
    
    def __init__(self, project_root: str = None):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.temp_dir = None
        self.sonar_cryptography_path = None
        self.scan_results = {}
        
    def setup_environment(self):
        """Setup the scanning environment and dependencies"""
        print("🔧 Setting up Quantum Crypto Scanner environment...")
        
        # Create temporary directory for tools
        self.temp_dir = Path(tempfile.mkdtemp(prefix="quantum_scanner_"))
        print(f"📁 Created temp directory: {self.temp_dir}")
        
        # Clone sonar-cryptography
        self._clone_sonar_cryptography()
        
        return True
    
    def _clone_sonar_cryptography(self):
        """Clone and setup sonar-cryptography as the base detection engine"""
        print("📥 Cloning PQCA/sonar-cryptography...")
        
        sonar_repo = "https://github.com/PQCA/sonar-cryptography.git"
        self.sonar_cryptography_path = self.temp_dir / "sonar-cryptography"
        
        try:
            subprocess.run([
                "git", "clone", sonar_repo, str(self.sonar_cryptography_path)
            ], check=True, capture_output=True)
            
            print(f"✅ Cloned sonar-cryptography to {self.sonar_cryptography_path}")
            
            # Verify the structure
            if (self.sonar_cryptography_path / "sonar-cryptography-plugin").exists():
                print("✅ Found sonar-cryptography-plugin directory")
            else:
                print("⚠️  Warning: Expected plugin directory not found")
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to clone sonar-cryptography: {e}")
            raise
    
    def scan_codebase(self, target_path: str) -> Dict[str, Any]:
        """Main scanning function"""
        target = Path(target_path)
        
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        
        print(f"🔍 Starting quantum crypto vulnerability scan on: {target}")
        
        # Step 1: Use sonar-cryptography for base detection
        sonar_results = self._run_sonar_cryptography_scan(target)
        
        # For now, just return sonar results
        # In future steps, we'll add more detection engines
        self.scan_results = {
            "target_path": str(target),
            "sonar_cryptography_results": sonar_results,
            "summary": self._generate_summary(sonar_results)
        }
        
        return self.scan_results
    
    def _run_sonar_cryptography_scan(self, target_path: Path) -> Dict[str, Any]:
        """Run sonar-cryptography detection on the target codebase"""
        print("🔎 Running sonar-cryptography detection...")
        
        # For this step, we'll implement a basic file scanner that looks for 
        # crypto patterns similar to what sonar-cryptography would detect
        # In a full implementation, we'd integrate with the actual sonar plugin
        
        results = {
            "crypto_findings": [],
            "files_scanned": 0,
            "quantum_vulnerable": []
        }
        
        # Scan supported file types
        supported_extensions = {'.py', '.java', '.js', '.ts', '.go', '.cpp', '.c', '.cs'}
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                results["files_scanned"] += 1
                file_findings = self._scan_file_for_crypto(file_path)
                if file_findings:
                    results["crypto_findings"].extend(file_findings)
        
        # Identify quantum-vulnerable crypto
        results["quantum_vulnerable"] = self._identify_quantum_vulnerable(results["crypto_findings"])
        
        print(f"✅ Sonar scan complete: {len(results['crypto_findings'])} crypto findings, "
              f"{len(results['quantum_vulnerable'])} quantum-vulnerable")
        
        return results
    
    # def _scan_file_for_crypto(self, file_path: Path) -> List[Dict[str, Any]]:
        """Scan a single file for cryptographic usage patterns"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Define crypto patterns to look for
                crypto_patterns = {
                    # RSA patterns
                    'RSA': [
                        'RSA.generate', 'generateKeyPair("RSA"', 'RSA.importKey',
                        'Cipher.new(RSA', 'rsa.generate_private_key', 'RSAPrivateKey',
                        'RSAPublicKey', 'PKCS1_OAEP', 'PKCS1_v1_5'
                    ],
                    # ECC patterns  
                    'ECC': [
                        'ECDSA', 'ECDH', 'secp256r1', 'secp384r1', 'secp521r1',
                        'P-256', 'P-384', 'P-521', 'elliptic.ec', 'EC.generate',
                        'ECDSAPrivateKey', 'ECDSAPublicKey'
                    ],
                    # DH patterns
                    'DH': [
                        'DiffieHellman', 'DHParameterSpec', 'generateKeyPair("DH"',
                        'DH.generate', 'diffie_hellman'
                    ],
                    # Hash functions (some quantum-vulnerable contexts)
                    'HASH': [
                        'SHA1', 'MD5', 'sha1', 'md5', 'MessageDigest.getInstance("SHA-1")',
                        'MessageDigest.getInstance("MD5")'
                    ]
                }
                
                for line_num, line in enumerate(lines, 1):
                    for crypto_type, patterns in crypto_patterns.items():
                        for pattern in patterns:
                            if pattern in line:
                                findings.append({
                                    'file': str(file_path),
                                    'line': line_num,
                                    'line_content': line.strip(),
                                    'crypto_type': crypto_type,
                                    'pattern': pattern,
                                    'severity': self._get_severity(crypto_type, pattern)
                                })
                                
        except Exception as e:
            print(f"⚠️  Error scanning {file_path}: {e}")
            
        return findings
    # quantum_crypto_scanner/main.py - UPDATED VERSION
# Just replace the _scan_file_for_crypto method (around line 120)

def _scan_file_for_crypto(self, file_path: Path) -> List[Dict[str, Any]]:
    """Scan a single file for cryptographic usage patterns"""
    findings = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            
            # UPDATED crypto patterns with better coverage
            crypto_patterns = {
                # RSA patterns
                'RSA': [
                    'RSA.generate', 'generateKeyPair("RSA"', 'RSA.importKey',
                    'Cipher.new(RSA', 'rsa.generate_private_key', 'RSAPrivateKey',
                    'RSAPublicKey', 'PKCS1_OAEP', 'PKCS1_v1_5'
                ],
                # ECC patterns - ENHANCED with case variations
                'ECC': [
                    'ECDSA', 'ECDH', 'secp256r1', 'secp384r1', 'secp521r1',
                    'SECP256R1', 'SECP384R1', 'SECP521R1',  # Added uppercase
                    'P-256', 'P-384', 'P-521', 'elliptic.ec', 'EC.generate',
                    'ECDSAPrivateKey', 'ECDSAPublicKey',
                    'ec.generate_private_key', 'ec.ECDSA', 'ec.SECP256R1'  # Added missing
                ],
                # DH patterns
                'DH': [
                    'DiffieHellman', 'DHParameterSpec', 'generateKeyPair("DH"',
                    'DH.generate', 'diffie_hellman'
                ],
                # Hash functions - ENHANCED
                'HASH': [
                    'SHA1', 'MD5', 'sha1', 'md5', 'MessageDigest.getInstance("SHA-1")',
                    'MessageDigest.getInstance("MD5")', 'hashlib.sha1', 'hashlib.md5'
                ]
            }
            
            for line_num, line in enumerate(lines, 1):
                for crypto_type, patterns in crypto_patterns.items():
                    for pattern in patterns:
                        if pattern in line:
                            findings.append({
                                'file': str(file_path),
                                'line': line_num,
                                'line_content': line.strip(),
                                'crypto_type': crypto_type,
                                'pattern': pattern,
                                'severity': self._get_severity(crypto_type, pattern)
                            })
                            
    except Exception as e:
        print(f"⚠️  Error scanning {file_path}: {e}")
        
    return findings

    def _get_severity(self, crypto_type: str, pattern: str) -> str:
        """Determine severity level based on crypto type and pattern"""
        # Quantum-vulnerable algorithms get high severity
        if crypto_type in ['RSA', 'ECC', 'DH']:
            return 'CRITICAL'
        elif crypto_type == 'HASH' and ('SHA1' in pattern or 'MD5' in pattern):
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _identify_quantum_vulnerable(self, crypto_findings: List[Dict]) -> List[Dict]:
        """Identify which crypto findings are quantum-vulnerable"""
        quantum_vulnerable = []
        
        for finding in crypto_findings:
            if finding['crypto_type'] in ['RSA', 'ECC', 'DH']:
                # These are definitely quantum-vulnerable
                quantum_vulnerable.append({
                    **finding,
                    'quantum_risk': 'CRITICAL',
                    'estimated_break_timeline': '2030-2035',
                    'reason': f"{finding['crypto_type']} is vulnerable to Shor's algorithm"
                })
            elif finding['crypto_type'] == 'HASH':
                # Some hash usage contexts are quantum-vulnerable
                if 'SHA1' in finding['pattern'] or 'MD5' in finding['pattern']:
                    quantum_vulnerable.append({
                        **finding,
                        'quantum_risk': 'HIGH',
                        'estimated_break_timeline': '2035-2040',
                        'reason': f"Weak hash function vulnerable to Grover's algorithm"
                    })
        
        return quantum_vulnerable
    
    def _generate_summary(self, sonar_results: Dict) -> Dict[str, Any]:
        """Generate a summary of scan results"""
        return {
            'total_files_scanned': sonar_results['files_scanned'],
            'total_crypto_findings': len(sonar_results['crypto_findings']),
            'quantum_vulnerable_count': len(sonar_results['quantum_vulnerable']),
            'risk_breakdown': self._calculate_risk_breakdown(sonar_results['quantum_vulnerable'])
        }
    
    def _calculate_risk_breakdown(self, quantum_vulnerable: List[Dict]) -> Dict[str, int]:
        """Calculate risk level breakdown"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in quantum_vulnerable:
            risk_level = vuln.get('quantum_risk', 'MEDIUM')
            breakdown[risk_level] += 1
            
        return breakdown
    
    def generate_report(self, format_type: str = 'json') -> str:
        """Generate a report of the scan results"""
        if not self.scan_results:
            raise ValueError("No scan results available. Run scan_codebase() first.")
        
        if format_type == 'json':
            return json.dumps(self.scan_results, indent=2)
        elif format_type == 'summary':
            return self._generate_text_summary()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_text_summary(self) -> str:
        """Generate a human-readable text summary"""
        summary = self.scan_results['summary']
        
        report = f"""
🛡️  QUANTUM CRYPTOGRAPHY VULNERABILITY SCAN REPORT
{'='*60}

📊 SCAN SUMMARY:
• Target: {self.scan_results['target_path']}
• Files Scanned: {summary['total_files_scanned']}
• Crypto Findings: {summary['total_crypto_findings']}
• Quantum Vulnerable: {summary['quantum_vulnerable_count']}

🚨 RISK BREAKDOWN:
• Critical Risk: {summary['risk_breakdown']['CRITICAL']}
• High Risk: {summary['risk_breakdown']['HIGH']}
• Medium Risk: {summary['risk_breakdown']['MEDIUM']}
• Low Risk: {summary['risk_breakdown']['LOW']}

📋 QUANTUM-VULNERABLE FINDINGS:
"""
        
        for vuln in self.scan_results['sonar_cryptography_results']['quantum_vulnerable'][:10]:  # Show top 10
            report += f"""
• {vuln['file']}:{vuln['line']}
  Algorithm: {vuln['crypto_type']}
  Risk: {vuln['quantum_risk']}
  Timeline: {vuln['estimated_break_timeline']}
  Code: {vuln['line_content'][:80]}...
"""
        
        if len(self.scan_results['sonar_cryptography_results']['quantum_vulnerable']) > 10:
            remaining = len(self.scan_results['sonar_cryptography_results']['quantum_vulnerable']) - 10
            report += f"\n... and {remaining} more findings\n"
        
        return report
    
    def cleanup(self):
        """Clean up temporary files and directories"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            print(f"🧹 Cleaned up temp directory: {self.temp_dir}")


# CLI Interface
def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Quantum Crypto Vulnerability Scanner - Step 1')
    parser.add_argument('target', help='Path to the codebase to scan')
    parser.add_argument('--format', choices=['json', 'summary'], default='summary',
                       help='Output format (default: summary)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    
    args = parser.parse_args()
    
    scanner = QuantumCryptoScanner()
    
    try:
        # Setup environment
        scanner.setup_environment()
        
        # Run scan
        results = scanner.scan_codebase(args.target)
        
        # Generate report
        report = scanner.generate_report(args.format)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"📄 Report saved to: {args.output}")
        else:
            print(report)
            
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        sys.exit(1)
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()