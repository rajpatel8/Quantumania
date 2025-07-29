# quantum_crypto_scanner/main.py - STEP 2 VERSION
"""
Quantum Crypto Vulnerability Scanner - Step 2
Enhanced with real PQCA/sonar-cryptography integration and CBOM generation
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile
import shutil

# Step 2 imports
from .sonar_engine import SonarCryptographyEngine, EnhancedCryptoAnalyzer
from .cbom_generator import CBOMGenerator

try:
    from .pqc_scanner_integration import PQCSemanticAnalyzer
    from .html_report_generator import HTMLReportGenerator
    STEP3_AVAILABLE = True
except ImportError:
    STEP3_AVAILABLE = False
    print("⚠️ Step 3 components not available - using Step 2 mode")

class QuantumCryptoScanner:
    """
    Enhanced scanner with real sonar-cryptography integration and CBOM generation
    Step 2: Moving beyond regex to AST-based analysis with standardized output
    """
    
    def __init__(self, project_root: str = None):
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.temp_dir = None
        self.sonar_cryptography_path = None
        self.scan_results = {}
        
        # Step 2 components
        self.sonar_engine = None
        self.cbom_generator = CBOMGenerator()
        self.enhanced_analyzer = EnhancedCryptoAnalyzer()

        if STEP3_AVAILABLE:
            self.pqc_analyzer = PQCSemanticAnalyzer()
            self.html_report_generator = HTMLReportGenerator()
        else:
            self.pqc_analyzer = None
            self.html_report_generator = None
        
    def setup_environment(self):
        """Setup the enhanced scanning environment with sonar integration"""
        print("🔧 Setting up Enhanced Quantum Crypto Scanner environment...")
        
        # Create temporary directory for tools
        self.temp_dir = Path(tempfile.mkdtemp(prefix="quantum_scanner_"))
        print(f"📁 Created temp directory: {self.temp_dir}")
        
        # Clone and setup sonar-cryptography
        success = self._setup_sonar_cryptography()
        if success:
            print("✅ Enhanced scanner environment ready")
        else:
            print("⚠️ Enhanced scanner setup with warnings - falling back to AST analysis")
        
        return True
    
    def _setup_sonar_cryptography(self) -> bool:
        """Setup real sonar-cryptography integration"""
        print("📥 Setting up PQCA/sonar-cryptography integration...")
        
        try:
            # Clone sonar-cryptography repository
            sonar_repo = "https://github.com/PQCA/sonar-cryptography.git"
            self.sonar_cryptography_path = self.temp_dir / "sonar-cryptography"
            
            subprocess.run([
                "git", "clone", sonar_repo, str(self.sonar_cryptography_path)
            ], check=True, capture_output=True, timeout=60)
            
            print(f"✅ Cloned sonar-cryptography to {self.sonar_cryptography_path}")
            
            # Initialize the sonar engine
            self.sonar_engine = SonarCryptographyEngine(self.sonar_cryptography_path)
            
            # Try to setup the sonar scanner
            setup_success = self.sonar_engine.setup_sonar_scanner()
            if setup_success:
                print("✅ Sonar scanner integration successful")
            else:
                print("⚠️ Sonar scanner setup failed - will use enhanced AST analysis")
                
            return True
            
        except subprocess.TimeoutExpired:
            print("⚠️ Git clone timed out - using cached or fallback methods")
            return False
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to clone sonar-cryptography: {e}")
            return False
        except Exception as e:
            print(f"⚠️ Sonar setup error: {e}")
            return False
    
    
    
    def scan_codebase(self, target_path: str, output_format: str = "enhanced") -> Dict[str, Any]:
        """
        Enhanced scanning with sonar integration and CBOM generation
        """
        target = Path(target_path)
        
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        
        print(f"🔍 Starting enhanced quantum crypto scan on: {target}")
        
        # Step 2: Use enhanced detection engines
        if self.sonar_engine:
            print("🧠 Using sonar-cryptography enhanced analysis...")
            sonar_results = self.sonar_engine.scan_project(target)
        else:
            print("🧠 Using enhanced AST-based analysis...")
            sonar_results = self.enhanced_analyzer.analyze_project(target)
        
        # Step 1 compatibility: Also run legacy detection for comparison
        if output_format == "enhanced":
            legacy_results = self._run_legacy_scan(target)
            
            # Merge results for comprehensive coverage
            merged_results = self._merge_scan_results(sonar_results, legacy_results)
        else:
            merged_results = sonar_results
        
        # Generate quantum vulnerability assessment
        quantum_assessment = self._assess_quantum_vulnerabilities(merged_results)
        
        # Generate CBOM
        cbom = self.cbom_generator.generate_cbom(merged_results)
        
        # Create comprehensive results
        self.scan_results = {
            # Step 1 backward compatibility - target_path at top level
            "target_path": str(target),
            
            # Step 2 enhanced structure
            "scan_metadata": {
                "target_path": str(target),
                "scanner_version": "2.0",
                "analysis_method": merged_results.get("analysis_method", "enhanced_ast"),
                "timestamp": cbom["metadata"]["timestamp"]
            },
            "sonar_cryptography_results": merged_results,
            "quantum_assessment": quantum_assessment,
            "cbom": cbom,
            "summary": self._generate_enhanced_summary(merged_results, quantum_assessment),
            "migration_plan": self._generate_migration_plan(quantum_assessment)
        }
        
        return self.scan_results
    
    def _run_legacy_scan(self, target_path: Path) -> Dict[str, Any]:
        """Run Step 1 legacy scan for compatibility and comparison"""
        results = {
            "analysis_method": "legacy_regex",
            "crypto_findings": [],
            "files_analyzed": 0,
            "languages_detected": []
        }
        
        # Scan supported file types with Step 1 patterns
        supported_extensions = {'.py', '.java', '.js', '.ts', '.go', '.cpp', '.c', '.cs'}
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                results["files_analyzed"] += 1
                file_findings = self._legacy_scan_file(file_path)
                if file_findings:
                    results["crypto_findings"].extend(file_findings)
        
        return results
    
    def _legacy_scan_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Legacy Step 1 file scanning for comparison"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                # Step 1 crypto patterns
                crypto_patterns = {
                    'RSA': ['RSA.generate', 'generateKeyPair("RSA"', 'PKCS1_OAEP'],
                    'ECC': ['ECDSA', 'ec.generate_private_key', 'SECP256R1'],
                    'HASH': ['hashlib.sha1', 'hashlib.md5', 'MessageDigest.getInstance("MD5")']
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
                                    'analysis_method': 'legacy_regex',
                                    'confidence': 0.6,  # Lower confidence for regex
                                    'severity': self._get_severity(crypto_type, pattern)
                                })
                                
        except Exception as e:
            print(f"⚠️ Error in legacy scan of {file_path}: {e}")
            
        return findings
    
    def _merge_scan_results(self, sonar_results: Dict[str, Any], legacy_results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge results from different detection engines"""
        print("🔄 Merging scan results from multiple engines...")
        
        # Start with the more advanced sonar results
        merged = sonar_results.copy()
        merged["analysis_method"] = "enhanced_multi_engine"
        
        # Add legacy findings that weren't caught by enhanced analysis
        sonar_patterns = set()
        for finding in sonar_results.get("crypto_findings", []):
            key = f"{finding.get('file', '')}-{finding.get('line', 0)}-{finding.get('pattern', '')}"
            sonar_patterns.add(key)
        
        additional_findings = []
        for finding in legacy_results.get("crypto_findings", []):
            key = f"{finding.get('file', '')}-{finding.get('line', 0)}-{finding.get('pattern', '')}"
            if key not in sonar_patterns:
                finding["source"] = "legacy_detection"
                additional_findings.append(finding)
        
        merged["crypto_findings"].extend(additional_findings)
        
        # Update file counts
        all_files = set()
        for finding in merged["crypto_findings"]:
            all_files.add(finding.get('file', ''))
        merged["files_analyzed"] = len(all_files)
        
        print(f"✅ Merged results: {len(merged['crypto_findings'])} total findings")
        return merged
    
    def _assess_quantum_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced quantum vulnerability assessment"""
        findings = scan_results.get("crypto_findings", [])
        
        quantum_vulnerable = []
        risk_timeline = {}
        migration_priorities = []
        
        for finding in findings:
            if finding['crypto_type'] in ['RSA', 'ECC', 'DH']:
                quantum_risk = {
                    **finding,
                    'quantum_risk': 'CRITICAL',
                    'estimated_break_timeline': '2030-2035',
                    'attack_method': "Shor's Algorithm",
                    'migration_priority': 1,
                    'nist_replacement': self._get_nist_replacement(finding['crypto_type'])
                }
                quantum_vulnerable.append(quantum_risk)
                
            elif finding['crypto_type'] == 'HASH':
                pattern = finding.get('pattern', '').upper()
                if any(weak in pattern for weak in ['MD5', 'SHA1']):
                    quantum_risk = {
                        **finding,
                        'quantum_risk': 'HIGH',
                        'estimated_break_timeline': '2035-2040',
                        'attack_method': "Grover's Algorithm",
                        'migration_priority': 2,
                        'nist_replacement': 'SHA-256 or SHA-3'
                    }
                    quantum_vulnerable.append(quantum_risk)
        
        return {
            "total_crypto_findings": len(findings),
            "quantum_vulnerable_count": len(quantum_vulnerable),
            "quantum_vulnerable_findings": quantum_vulnerable,
            "risk_distribution": self._calculate_risk_distribution(quantum_vulnerable),
            "quantum_readiness_score": self._calculate_readiness_score(findings, quantum_vulnerable)
        }
    
    def _generate_enhanced_summary(self, scan_results: Dict[str, Any], quantum_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate enhanced summary with CBOM metrics"""
        return {
            'total_files_scanned': scan_results.get("files_analyzed", 0),
            'total_crypto_findings': len(scan_results.get("crypto_findings", [])),
            'quantum_vulnerable_count': quantum_assessment["quantum_vulnerable_count"],
            'risk_breakdown': quantum_assessment["risk_distribution"],
            'quantum_readiness_score': quantum_assessment["quantum_readiness_score"],
            'analysis_method': scan_results.get("analysis_method", "enhanced"),
            'languages_detected': scan_results.get("languages_detected", []),
            'confidence_average': self._calculate_average_confidence(scan_results.get("crypto_findings", []))
        }
    
    def _generate_migration_plan(self, quantum_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Generate actionable migration plan"""
        vulnerable_findings = quantum_assessment["quantum_vulnerable_findings"]
        
        # Group by priority and crypto type
        migration_groups = {}
        for finding in vulnerable_findings:
            priority = finding.get('migration_priority', 3)
            crypto_type = finding['crypto_type']
            
            key = f"P{priority}-{crypto_type}"
            if key not in migration_groups:
                migration_groups[key] = {
                    'priority': priority,
                    'crypto_type': crypto_type,
                    'findings': [],
                    'estimated_effort': 'TBD'
                }
            migration_groups[key]['findings'].append(finding)
        
        # Generate timeline and effort estimates
        migration_plan = {
            'total_migration_items': len(vulnerable_findings),
            'estimated_timeline': self._estimate_migration_timeline(vulnerable_findings),
            'migration_groups': list(migration_groups.values()),
            'recommended_approach': self._get_migration_approach(vulnerable_findings)
        }
        
        return migration_plan
    
    def generate_report(self, format_type: str = 'enhanced_summary') -> str:
        """Generate enhanced reports with CBOM support"""
        if not self.scan_results:
            raise ValueError("No scan results available. Run scan_codebase() first.")
        
        if format_type == 'cbom':
            return json.dumps(self.scan_results['cbom'], indent=2)
        elif format_type == 'json':
            return json.dumps(self.scan_results, indent=2)
        elif format_type == 'enhanced_summary':
            return self._generate_enhanced_text_summary()
        elif format_type == 'summary':
            # Backward compatibility with Step 1
            return self._generate_legacy_summary()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_enhanced_text_summary(self) -> str:
        """Generate enhanced human-readable summary"""
        summary = self.scan_results['summary']
        quantum_assessment = self.scan_results['quantum_assessment']
        cbom = self.scan_results['cbom']
        
        report = f"""
🛡️  QUANTUM CRYPTOGRAPHY VULNERABILITY SCAN REPORT - ENHANCED
{'='*80}

📊 SCAN SUMMARY:
• Target: {self.scan_results['scan_metadata']['target_path']}
• Scanner Version: {self.scan_results['scan_metadata']['scanner_version']}
• Analysis Method: {summary['analysis_method'].replace('_', ' ').title()}
• Files Scanned: {summary['total_files_scanned']}
• Languages: {', '.join(summary.get('languages_detected', ['Unknown']))}
• Crypto Findings: {summary['total_crypto_findings']}
• Detection Confidence: {summary.get('confidence_average', 0):.1%}

🚨 QUANTUM RISK ASSESSMENT:
• Quantum Vulnerable: {summary['quantum_vulnerable_count']}
• Readiness Score: {summary['quantum_readiness_score']:.1f}/100
• Overall Status: {cbom['quantumReadiness']['status'].replace('-', ' ').title()}

📋 RISK BREAKDOWN:
• Critical Risk: {summary['risk_breakdown'].get('CRITICAL', 0)}
• High Risk: {summary['risk_breakdown'].get('HIGH', 0)}
• Medium Risk: {summary['risk_breakdown'].get('MEDIUM', 0)}
• Low Risk: {summary['risk_breakdown'].get('LOW', 0)}

🔄 MIGRATION PLAN:
• Total Items: {self.scan_results['migration_plan']['total_migration_items']}
• Estimated Timeline: {self.scan_results['migration_plan']['estimated_timeline']}
• Priority Groups: {len(self.scan_results['migration_plan']['migration_groups'])}

📋 CBOM SUMMARY:
• Total Crypto Assets: {len(cbom['components'])}
• Quantum Vulnerabilities: {len(cbom['vulnerabilities'])}
• NIST Recommendations: {len(cbom['migrationRecommendations'])}

🔍 TOP QUANTUM-VULNERABLE FINDINGS:
"""
        
        # Show top findings with enhanced details
        top_findings = quantum_assessment["quantum_vulnerable_findings"][:10]
        for i, vuln in enumerate(top_findings, 1):
            confidence_indicator = "🔴" if vuln.get('confidence', 0) > 0.8 else "🟡"
            report += f"""
{i}. {confidence_indicator} {vuln['file']}:{vuln['line']}
   Algorithm: {vuln['crypto_type']} | Risk: {vuln['quantum_risk']} | Timeline: {vuln['estimated_break_timeline']}
   Attack: {vuln['attack_method']} | Confidence: {vuln.get('confidence', 0.5):.1%}
   NIST Replacement: {vuln.get('nist_replacement', 'See migration guide')}
   Code: {vuln['line_content'][:100]}...
"""
        
        if len(quantum_assessment["quantum_vulnerable_findings"]) > 10:
            remaining = len(quantum_assessment["quantum_vulnerable_findings"]) - 10
            report += f"\n... and {remaining} more quantum-vulnerable findings\n"
        
        report += f"""

📈 RECOMMENDATIONS:
{cbom['quantumReadiness']['recommendation']}

🔗 CBOM Generated: {len(cbom['components'])} crypto components catalogued
📄 Full CBOM available in JSON format with --format cbom
"""
        
        return report
    
    def _generate_legacy_summary(self) -> str:
        """Generate Step 1 compatible summary for backward compatibility"""
        # Extract Step 1 compatible data
        legacy_data = {
            'target_path': self.scan_results['scan_metadata']['target_path'],
            'sonar_cryptography_results': {
                'crypto_findings': self.scan_results['sonar_cryptography_results']['crypto_findings'],
                'quantum_vulnerable': self.scan_results['quantum_assessment']['quantum_vulnerable_findings'],
                'files_scanned': self.scan_results['summary']['total_files_scanned']
            },
            'summary': self.scan_results['summary']
        }
        
        # Use Step 1 format
        return self._generate_step1_summary(legacy_data)
    
    def _generate_step1_summary(self, legacy_data: Dict[str, Any]) -> str:
        """Generate Step 1 format summary"""
        summary = legacy_data['summary']
        
        report = f"""
🛡️  QUANTUM CRYPTOGRAPHY VULNERABILITY SCAN REPORT
{'='*60}

📊 SCAN SUMMARY:
• Target: {legacy_data['target_path']}
• Files Scanned: {summary['total_files_scanned']}
• Crypto Findings: {summary['total_crypto_findings']}
• Quantum Vulnerable: {summary['quantum_vulnerable_count']}

🚨 RISK BREAKDOWN:
• Critical Risk: {summary['risk_breakdown'].get('CRITICAL', 0)}
• High Risk: {summary['risk_breakdown'].get('HIGH', 0)}
• Medium Risk: {summary['risk_breakdown'].get('MEDIUM', 0)}
• Low Risk: {summary['risk_breakdown'].get('LOW', 0)}

📋 QUANTUM-VULNERABLE FINDINGS:
"""
        
        for vuln in legacy_data['sonar_cryptography_results']['quantum_vulnerable'][:10]:
            report += f"""
• {vuln['file']}:{vuln['line']}
  Algorithm: {vuln['crypto_type']}
  Risk: {vuln.get('quantum_risk', 'CRITICAL')}
  Timeline: {vuln.get('estimated_break_timeline', '2030-2035')}
  Code: {vuln['line_content'][:80]}...
"""
        
        return report
    
    # Utility methods for Step 2 functionality
    def _get_severity(self, crypto_type: str, pattern: str) -> str:
        """Get severity level (Step 1 compatibility)"""
        if crypto_type in ['RSA', 'ECC', 'DH']:
            return 'CRITICAL'
        elif crypto_type == 'HASH' and ('SHA1' in pattern or 'MD5' in pattern):
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _get_nist_replacement(self, crypto_type: str) -> str:
        """Get NIST PQC replacement recommendation"""
        replacements = {
            'RSA': 'ML-DSA (Dilithium) or ML-KEM (Kyber)',
            'ECC': 'ML-DSA (Dilithium) or SLH-DSA (SPHINCS+)',
            'DH': 'ML-KEM (Kyber)'
        }
        return replacements.get(crypto_type, 'See NIST PQC guidelines')
    
    def _calculate_risk_distribution(self, quantum_vulnerable: List[Dict]) -> Dict[str, int]:
        """Calculate risk distribution"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in quantum_vulnerable:
            risk_level = vuln.get('quantum_risk', 'MEDIUM')
            breakdown[risk_level] += 1
        return breakdown
    
    def _calculate_readiness_score(self, all_findings: List[Dict], quantum_vulnerable: List[Dict]) -> float:
        """Calculate quantum readiness score (0-100)"""
        if not all_findings:
            return 0.0
        
        vulnerable_count = len(quantum_vulnerable)
        total_count = len(all_findings)
        
        readiness_percentage = ((total_count - vulnerable_count) / total_count) * 100
        return round(readiness_percentage, 1)
    
    def _calculate_average_confidence(self, findings: List[Dict]) -> float:
        """Calculate average confidence score"""
        if not findings:
            return 0.0
        
        total_confidence = sum(f.get('confidence', 0.5) for f in findings)
        return total_confidence / len(findings)
    
    def _identify_quantum_vulnerable(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Backward compatibility method for Step 1 tests
        Identifies quantum-vulnerable findings using Step 2 logic
        """
        quantum_vulnerable = []
        
        for finding in findings:
            crypto_type = finding.get('crypto_type', '')
            
            if crypto_type in ['RSA', 'ECC', 'DH']:
                vuln_finding = finding.copy()
                vuln_finding.update({
                    'quantum_risk': 'CRITICAL',
                    'reason': f"{crypto_type} is vulnerable to Shor's Algorithm on quantum computers",
                    'estimated_break_timeline': '2030-2035',
                    'attack_method': "Shor's Algorithm",
                    'nist_replacement': self._get_nist_replacement(crypto_type)
                })
                quantum_vulnerable.append(vuln_finding)
                
            elif crypto_type == 'HASH':
                pattern = finding.get('pattern', '').upper()
                if any(weak in pattern for weak in ['MD5', 'SHA1']):
                    vuln_finding = finding.copy()
                    vuln_finding.update({
                        'quantum_risk': 'HIGH',
                        'reason': f"Weak hash function vulnerable to Grover's Algorithm",
                        'estimated_break_timeline': '2035-2040',
                        'attack_method': "Grover's Algorithm",
                        'nist_replacement': 'SHA-256 or SHA-3'
                    })
                    quantum_vulnerable.append(vuln_finding)
        
        return quantum_vulnerable
    
    def _basic_file_scan(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Basic file scanning for fallback mode
        """
        findings = []
        
        # Basic crypto patterns
        crypto_patterns = {
            'RSA': ['RSA.generate', 'generateKeyPair("RSA"', 'KeyPairGenerator.getInstance("RSA")', 'PKCS1_OAEP'],
            'ECC': ['ECDSA', 'ec.generate_private_key', 'SECP256R1', 'KeyPairGenerator.getInstance("EC")'],
            'HASH': ['hashlib.sha1', 'hashlib.md5', 'MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-1")']
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
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
                                    'analysis_method': 'basic_fallback',
                                    'confidence': 0.6,
                                    'severity': self._get_severity(crypto_type, pattern)
                                })
        except Exception as e:
            print(f"⚠️ Error in basic file scan of {file_path}: {e}")
            
        return findings
    
    def _fallback_analysis(self, target_path: Path) -> Dict[str, Any]:
        """
        Fallback analysis when Step 2 components aren't available
        Uses basic pattern matching similar to Step 1
        """
        results = {
            "analysis_method": "fallback_basic",
            "crypto_findings": [],
            "files_analyzed": 0,
            "languages_detected": []
        }
        
        # Basic crypto patterns for fallback
        crypto_patterns = {
            'RSA': ['RSA.generate', 'generateKeyPair("RSA"', 'KeyPairGenerator.getInstance("RSA")', 'PKCS1_OAEP'],
            'ECC': ['ECDSA', 'ec.generate_private_key', 'SECP256R1', 'KeyPairGenerator.getInstance("EC")'],
            'HASH': ['hashlib.sha1', 'hashlib.md5', 'MessageDigest.getInstance("MD5")', 'MessageDigest.getInstance("SHA-1")'],
            'AES': ['AES.new', 'KeyGenerator.getInstance("AES")']
        }
        
        # Scan supported file types
        supported_extensions = {'.py': 'python', '.java': 'java', '.js': 'javascript', '.ts': 'typescript', '.go': 'go', '.cpp': 'cpp', '.c': 'c', '.cs': 'csharp'}
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                results["files_analyzed"] += 1
                language = supported_extensions[file_path.suffix]
                if language not in results["languages_detected"]:
                    results["languages_detected"].append(language)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.split('\n')
                        
                        for line_num, line in enumerate(lines, 1):
                            for crypto_type, patterns in crypto_patterns.items():
                                for pattern in patterns:
                                    if pattern in line:
                                        results["crypto_findings"].append({
                                            'file': str(file_path),
                                            'line': line_num,
                                            'line_content': line.strip(),
                                            'crypto_type': crypto_type,
                                            'pattern': pattern,
                                            'analysis_method': 'fallback_basic',
                                            'confidence': 0.6,
                                            'severity': self._get_severity(crypto_type, pattern),
                                            'language': language
                                        })
                except Exception as e:
                    print(f"⚠️ Error scanning {file_path}: {e}")
        
        return results
    
    def _generate_basic_cbom(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate basic CBOM when Step 2 components aren't available
        """
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": "quantum-crypto-scanner", "version": "0.2.0"}],
                "component": {"type": "application", "name": "scanned-project"}
            },
            "components": [],
            "vulnerabilities": [],
            "quantumReadiness": {
                "status": "unknown",
                "score": 0,
                "assessment": "Basic scan - upgrade to Step 2 for full CBOM"
            },
            "migrationRecommendations": []
        }

    def _estimate_migration_timeline(self, vulnerable_findings: List[Dict]) -> str:
        """Estimate migration timeline"""
        critical_count = len([f for f in vulnerable_findings if f.get('quantum_risk') == 'CRITICAL'])
        
        if critical_count == 0:
            return "Low priority - by 2035"
        elif critical_count <= 5:
            return "Medium priority - by 2032"
        else:
            return "High priority - by 2030"
    
    def _get_migration_approach(self, vulnerable_findings: List[Dict]) -> str:
        """Get recommended migration approach"""
        if len(vulnerable_findings) <= 10:
            return "Direct migration to NIST PQC standards"
        else:
            return "Phased hybrid approach with gradual PQC adoption"
    
    def cleanup(self):
        """Clean up temporary files and directories"""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                print(f"🧹 Cleaned up temp directory: {self.temp_dir}")
            except Exception as e:
                print(f"⚠️ Error cleaning up temp directory: {e}")

    def _scan_file_for_crypto(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Backward compatibility method for Step 1 tests
        Scans a single file using Step 2 enhanced analysis
        """
        try:
            # Use enhanced analyzer if available, otherwise fallback
            if STEP2_AVAILABLE and self.enhanced_analyzer:
                # Determine file language
                language_map = {
                    '.py': 'python',
                    '.java': 'java',
                    '.js': 'javascript',
                    '.ts': 'typescript',
                    '.go': 'go',
                    '.cpp': 'cpp',
                    '.c': 'c',
                    '.cs': 'csharp'
                }
                
                language = language_map.get(file_path.suffix, 'unknown')
                if language == 'unknown':
                    return []
                
                # Use enhanced analyzer
                findings = self.enhanced_analyzer.analyze_file(file_path, language)
            else:
                # Fallback to basic pattern matching
                findings = self._basic_file_scan(file_path)
            
            # Convert to Step 1 compatible format if needed
            for finding in findings:
                if 'severity' not in finding:
                    finding['severity'] = self._get_severity(finding['crypto_type'], finding.get('pattern', ''))
            
            return findings
            
        except Exception as e:
            print(f"⚠️ Error in file scan compatibility method: {e}")
            return []
        
        
# Enhanced CLI Interface for Step 2
# # def main():
#     """Enhanced CLI interface with CBOM and advanced features"""
#     import argparse
    
#     parser = argparse.ArgumentParser(description='Quantum Crypto Scanner - Enhanced v2.0')
#     parser.add_argument('target', help='Path to the codebase to scan')
#     parser.add_argument('--format', choices=['json', 'summary', 'enhanced_summary', 'cbom'], 
#                        default='enhanced_summary', help='Output format (default: enhanced_summary)')
#     parser.add_argument('--output', '-o', help='Output file (default: stdout)')
#     parser.add_argument('--legacy-mode', action='store_true', 
#                        help='Run in Step 1 compatibility mode')
#     parser.add_argument('--cbom-only', action='store_true', 
#                        help='Generate only CBOM output')
    
#     args = parser.parse_args()
    
#     scanner = QuantumCryptoScanner()
    
#     try:
#         # Setup enhanced environment
#         scanner.setup_environment()
        
#         # Determine output format
#         if args.cbom_only:
#             output_format = "enhanced"
#             report_format = "cbom"
#         elif args.legacy_mode:
#             output_format = "legacy"
#             report_format = "summary"
#         else:
#             output_format = "enhanced"
#             report_format = args.format
        
#         # Run enhanced scan
#         print(f"🚀 Running enhanced scan with {output_format} mode...")
#         results = scanner.scan_codebase(args.target, output_format)
        
#         # Generate report
#         report = scanner.generate_report(report_format)
        
#         # Output report
#         if args.output:
#             with open(args.output, 'w') as f:
#                 f.write(report)
#             print(f"📄 Report saved to: {args.output}")
#         else:
#             print(report)
            
#         # Additional Step 2 outputs
#         if not args.cbom_only and not args.legacy_mode:
#             cbom_file = f"{args.target.replace('/', '_')}_cbom.json"
#             with open(cbom_file, 'w') as f:
#                 f.write(scanner.generate_report('cbom'))
#             print(f"📋 CBOM saved to: {cbom_file}")
            
#     except Exception as e:
#         print(f"❌ Error during enhanced scan: {e}")
#         import traceback
#         traceback.print_exc()
#         sys.exit(1)
#     finally:
#         scanner.cleanup()

def _generate_migration_plan_enhanced(self, quantum_assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Generate enhanced migration plan with semantic insights"""
    vulnerable_findings = quantum_assessment["quantum_vulnerable_findings"]
    semantic_insights = quantum_assessment.get("semantic_insights", [])
    
    # Group by priority and complexity
    migration_groups = {}
    for finding in vulnerable_findings:
        priority = finding.get('migration_priority', 3)
        complexity = finding.get('migration_complexity', 'MEDIUM')
        crypto_type = finding['crypto_type']
        
        key = f"P{priority}-{complexity}-{crypto_type}"
        if key not in migration_groups:
            migration_groups[key] = {
                'priority': priority,
                'complexity': complexity,
                'crypto_type': crypto_type,
                'findings': [],
                'estimated_effort': complexity,
                'semantic_context': []
            }
        migration_groups[key]['findings'].append(finding)
        
        # Add semantic context
        if finding.get('semantic_context'):
            migration_groups[key]['semantic_context'].append(finding['semantic_context'])
    
    # Enhanced migration plan
    migration_plan = {
        'total_migration_items': len(vulnerable_findings),
        'estimated_timeline': self._estimate_migration_timeline(vulnerable_findings),
        'migration_groups': list(migration_groups.values()),
        'recommended_approach': self._get_migration_approach_enhanced(vulnerable_findings),
        'semantic_insights': semantic_insights,
        'critical_dependencies': self._identify_critical_dependencies(vulnerable_findings)
    }
    
    return migration_plan

def _generate_semantic_insights(self, context_analysis: Dict[str, Any], quantum_vulnerable: List[Dict]) -> List[Dict[str, Any]]:
    """Generate insights based on semantic analysis"""
    insights = []
    
    # Usage pattern insights
    usage_patterns = context_analysis.get("crypto_usage_patterns", {})
    for crypto_type, pattern_info in usage_patterns.items():
        if crypto_type in ['RSA', 'ECC', 'DH']:
            insights.append({
                "type": "usage_pattern",
                "crypto_type": crypto_type,
                "insight": f"{crypto_type} used in {pattern_info['usage_count']} locations across {pattern_info['files_affected']} files",
                "recommendation": f"Priority migration required for {crypto_type} - affects multiple files",
                "priority": "HIGH" if pattern_info['files_affected'] > 2 else "MEDIUM"
            })
    
    # Architectural insights
    architectural_insights = context_analysis.get("architectural_insights", [])
    for insight in architectural_insights:
        insights.append({
            "type": "architectural",
            "insight": insight,
            "recommendation": "Consider architectural changes during PQC migration",
            "priority": "MEDIUM"
        })
    
    return insights

def _assess_semantic_migration_complexity(self, finding: Dict[str, Any]) -> str:
    """Assess migration complexity based on semantic context"""
    semantic_context = finding.get('semantic_context', '')
    confidence = finding.get('confidence', 0.5)
    
    # High complexity indicators
    if any(indicator in semantic_context.lower() for indicator in ['class_definition', 'inheritance', 'interface']):
        return "HIGH"
    
    # Medium complexity indicators
    if any(indicator in semantic_context.lower() for indicator in ['method_call', 'function_call']):
        return "MEDIUM"
    
    # Low complexity for simple patterns
    if confidence > 0.8:
        return "LOW"
    
    return "MEDIUM"

def _merge_comprehensive_results(self, enhanced_results: Dict[str, Any], legacy_results: Dict[str, Any]) -> Dict[str, Any]:
    """Merge enhanced PQC results with legacy results for comprehensive coverage"""
    print("🔄 Merging comprehensive results from all engines...")
    
    # Start with enhanced results
    merged = enhanced_results.copy()
    merged["analysis_method"] = "comprehensive_multi_engine_pqc"
    
    # Add legacy findings that weren't caught by enhanced analysis
    enhanced_patterns = set()
    for finding in enhanced_results.get("crypto_findings", []):
        key = f"{finding.get('file', '')}-{finding.get('line', 0)}-{finding.get('pattern', '')}"
        enhanced_patterns.add(key)
    
    additional_findings = []
    for finding in legacy_results.get("crypto_findings", []):
        key = f"{finding.get('file', '')}-{finding.get('line', 0)}-{finding.get('pattern', '')}"
        if key not in enhanced_patterns:
            finding["source"] = "legacy_detection"
            additional_findings.append(finding)
    
    merged["crypto_findings"].extend(additional_findings)
    
    # Update file counts
    all_files = set()
    for finding in merged["crypto_findings"]:
        all_files.add(finding.get('file', ''))
    merged["files_analyzed"] = len(all_files)
    merged["files_scanned"] = len(all_files)
    
    print(f"✅ Comprehensive merge complete: {len(merged['crypto_findings'])} total findings")
    return merged

def _assess_quantum_vulnerabilities_enhanced(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Enhanced quantum vulnerability assessment with PQC semantic insights"""
    findings = scan_results.get("crypto_findings", [])
    pqc_analysis = scan_results.get("pqc_semantic_analysis", {})
    
    quantum_vulnerable = []
    semantic_insights = []
    
    for finding in findings:
        crypto_type = finding.get('crypto_type', '')
        
        if crypto_type in ['RSA', 'ECC', 'DH']:
            # Enhanced with semantic context
            semantic_context = finding.get('semantic_context', '')
            pqc_impact = finding.get('pqc_impact', {})
            
            quantum_risk = {
                **finding,
                'quantum_risk': 'CRITICAL',
                'estimated_break_timeline': '2030-2035',
                'attack_method': "Shor's Algorithm",
                'migration_priority': 1,
                'nist_replacement': self._get_nist_replacement(crypto_type),
                'semantic_context': semantic_context,
                'pqc_impact': pqc_impact,
                'migration_complexity': self._assess_semantic_migration_complexity(finding)
            }
            quantum_vulnerable.append(quantum_risk)
            
        elif crypto_type == 'HASH':
            pattern = finding.get('pattern', '').upper()
            if any(weak in pattern for weak in ['MD5', 'SHA1']):
                quantum_risk = {
                    **finding,
                    'quantum_risk': 'HIGH',
                    'estimated_break_timeline': '2035-2040',
                    'attack_method': "Grover's Algorithm",
                    'migration_priority': 2,
                    'nist_replacement': 'SHA-256 or SHA-3',
                    'semantic_context': finding.get('semantic_context', ''),
                    'pqc_impact': finding.get('pqc_impact', {}),
                    'migration_complexity': self._assess_semantic_migration_complexity(finding)
                }
                quantum_vulnerable.append(quantum_risk)
    
    # Generate semantic insights
    if pqc_analysis:
        context_analysis = pqc_analysis.get("context_analysis", {})
        semantic_insights = self._generate_semantic_insights(context_analysis, quantum_vulnerable)
    
    return {
        "total_crypto_findings": len(findings),
        "quantum_vulnerable_count": len(quantum_vulnerable),
        "quantum_vulnerable_findings": quantum_vulnerable,
        "risk_distribution": self._calculate_risk_distribution(quantum_vulnerable),
        "quantum_readiness_score": self._calculate_readiness_score(findings, quantum_vulnerable),
        "semantic_insights": semantic_insights,
        "pqc_context_analysis": pqc_analysis.get("context_analysis", {}),
        "crypto_dependencies": pqc_analysis.get("crypto_dependencies", [])
    }

def _merge_pqc_results(self, sonar_results: Dict[str, Any], pqc_results: Dict[str, Any]) -> Dict[str, Any]:
    """Merge sonar and PQC semantic analysis results"""
    print("🔄 Merging enhanced and PQC semantic analysis results...")
    
    # Start with sonar results
    merged = sonar_results.copy()
    merged["analysis_method"] = "comprehensive_pqc_semantic"
    
    # Add PQC semantic findings
    existing_findings = merged.get("crypto_findings", [])
    pqc_findings = pqc_results.get("semantic_findings", [])
    
    # Convert PQC findings to standard format and avoid duplicates
    for pqc_finding in pqc_findings:
        # Convert to standard format
        standard_finding = {
            'file': pqc_finding.get('file_path', ''),
            'line': pqc_finding.get('line', 0),
            'line_content': f"Semantic: {pqc_finding.get('type', 'unknown')}",
            'crypto_type': pqc_finding.get('crypto_type', 'UNKNOWN'),
            'pattern': pqc_finding.get('pattern', pqc_finding.get('function_name', 'semantic_pattern')),
            'analysis_method': 'pqc_semantic',
            'confidence': pqc_finding.get('confidence', 0.8),
            'severity': self._get_severity(pqc_finding.get('crypto_type', ''), ''),
            'language': pqc_finding.get('language', 'unknown'),
            'semantic_context': pqc_finding.get('semantic_context', ''),
            'pqc_impact': pqc_finding.get('pqc_impact', {})
        }
        
        # Check for duplicates (avoid adding same finding twice)
        is_duplicate = any(
            ef.get('file') == standard_finding['file'] and 
            ef.get('line') == standard_finding['line'] and
            ef.get('crypto_type') == standard_finding['crypto_type']
            for ef in existing_findings
        )
        
        if not is_duplicate:
            existing_findings.append(standard_finding)
    
    merged["crypto_findings"] = existing_findings
    
    # Update metadata
    merged["pqc_semantic_analysis"] = pqc_results
    merged["languages_detected"] = list(set(
        merged.get("languages_detected", []) + 
        pqc_results.get("languages_detected", [])
    ))
    
    # Update file counts
    all_files = set()
    for finding in merged["crypto_findings"]:
        all_files.add(finding.get('file', ''))
    
    merged["files_analyzed"] = len(all_files)
    merged["files_scanned"] = len(all_files)  # Backward compatibility
    
    print(f"✅ Merged PQC results: {len(merged['crypto_findings'])} total findings")
    return merged

def scan_codebase_enhanced(self, target_path: str, output_format: str = "comprehensive", 
                          generate_html: bool = True) -> Dict[str, Any]:
    """
    Step 3: Enhanced scanning with PQC semantic analysis and HTML report generation
    
    Args:
        target_path: Path to scan
        output_format: Output format (comprehensive, legacy, enhanced)
        generate_html: Whether to generate HTML dashboard
        
    Returns:
        Comprehensive scan results with HTML report path
    """
    target = Path(target_path)
    
    if not target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")
    
    print(f"🚀 Starting Step 3 comprehensive quantum crypto scan on: {target}")
    
    # Step 2: Use enhanced detection engines (with fallback)
    if STEP2_AVAILABLE and self.sonar_engine:
        print("🧠 Using sonar-cryptography enhanced analysis...")
        sonar_results = self.sonar_engine.scan_project(target)
    elif STEP2_AVAILABLE and self.enhanced_analyzer:
        print("🧠 Using enhanced AST-based analysis...")
        sonar_results = self.enhanced_analyzer.analyze_project(target)
    else:
        print("🧠 Using fallback analysis...")
        sonar_results = self._fallback_analysis(target)
    
    # Step 3: Add PQC semantic analysis
    if STEP3_AVAILABLE and self.pqc_analyzer:
        print("🧠 Running PQC semantic analysis...")
        pqc_results = self.pqc_analyzer.analyze_project_semantics(target)
        
        # Merge PQC results with existing results
        merged_results = self._merge_pqc_results(sonar_results, pqc_results)
    else:
        print("⚠️ PQC semantic analysis not available - using enhanced analysis only")
        merged_results = sonar_results
    
    # Step 1 compatibility: Also run legacy detection for comparison
    if output_format == "comprehensive":
        legacy_results = self._run_legacy_scan(target)
        
        # Merge all results for comprehensive coverage
        final_results = self._merge_comprehensive_results(merged_results, legacy_results)
    else:
        final_results = merged_results
    
    # Generate quantum vulnerability assessment (enhanced with PQC insights)
    quantum_assessment = self._assess_quantum_vulnerabilities_enhanced(final_results)
    
    # Generate CBOM (with fallback)
    if STEP2_AVAILABLE and self.cbom_generator:
        cbom = self.cbom_generator.generate_cbom(final_results)
    else:
        cbom = self._generate_basic_cbom(final_results)
    
    # Create comprehensive results
    self.scan_results = {
        # Step 1 backward compatibility
        "target_path": str(target),
        
        # Step 2 enhanced structure
        "scan_metadata": {
            "target_path": str(target),
            "scanner_version": "3.0",  # Updated version
            "analysis_method": final_results.get("analysis_method", "comprehensive_pqc"),
            "timestamp": cbom["metadata"]["timestamp"],
            "step3_features_enabled": STEP3_AVAILABLE
        },
        "sonar_cryptography_results": final_results,
        "quantum_assessment": quantum_assessment,
        "cbom": cbom,
        "summary": self._generate_enhanced_summary(final_results, quantum_assessment),
        "migration_plan": self._generate_migration_plan_enhanced(quantum_assessment),
        
        # Step 3: PQC semantic analysis results
        "pqc_semantic_analysis": pqc_results if STEP3_AVAILABLE and self.pqc_analyzer else {},
        "html_report_path": None  # Will be set if HTML is generated
    }
    
    # Step 3: Generate HTML dashboard report
    if generate_html and STEP3_AVAILABLE and self.html_generator:
        print("📊 Generating HTML dashboard report...")
        try:
            html_path = self.html_generator.generate_html_report(
                self.scan_results, 
                f"quantum_scan_results_{target.name}"
            )
            self.scan_results["html_report_path"] = html_path
            print(f"✅ HTML dashboard generated: {html_path}")
        except Exception as e:
            print(f"⚠️ HTML generation failed: {e}")
            self.scan_results["html_report_path"] = None
    
    return self.scan_results

def _get_migration_approach_enhanced(self, vulnerable_findings: List[Dict]) -> str:
    """Get enhanced migration approach recommendation"""
    high_complexity = len([f for f in vulnerable_findings if f.get('migration_complexity') == 'HIGH'])
    total_count = len(vulnerable_findings)
    
    if high_complexity > total_count * 0.5:
        return "Phased migration with extensive testing and gradual rollout recommended"
    elif total_count <= 10:
        return "Direct migration to NIST PQC standards with hybrid transition period"
    else:
        return "Comprehensive migration strategy with risk-based prioritization"


def _identify_critical_dependencies(self, vulnerable_findings: List[Dict]) -> List[Dict[str, Any]]:
    """Identify critical dependencies for migration planning"""
    dependencies = []
    
    # Group by file to identify files with multiple vulnerabilities
    file_groups = {}
    for finding in vulnerable_findings:
        file_path = finding.get('file', 'unknown')
        if file_path not in file_groups:
            file_groups[file_path] = []
        file_groups[file_path].append(finding)
    
    # Identify critical files
    for file_path, findings in file_groups.items():
        if len(findings) > 2:  # Files with multiple crypto vulnerabilities
            dependencies.append({
                'file': file_path,
                'vulnerability_count': len(findings),
                'crypto_types': list(set(f['crypto_type'] for f in findings)),
                'priority': 'HIGH',
                'reason': 'Multiple crypto vulnerabilities in single file'
            })
    
    return dependencies

def main():
    """Enhanced CLI interface for Step 3 with HTML dashboard generation"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Quantum Crypto Scanner - Step 3 Enhanced v3.0')
    parser.add_argument('target', help='Path to the codebase to scan')
    parser.add_argument('--format', choices=['json', 'summary', 'enhanced_summary', 'cbom', 'comprehensive'], 
                       default='comprehensive', help='Output format (default: comprehensive)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--html', action='store_true', default=True,
                       help='Generate HTML dashboard (default: True)')
    parser.add_argument('--no-html', action='store_false', dest='html',
                       help='Disable HTML dashboard generation')
    parser.add_argument('--legacy-mode', action='store_true', 
                       help='Run in Step 1 compatibility mode')
    parser.add_argument('--cbom-only', action='store_true', 
                       help='Generate only CBOM output')
    parser.add_argument('--pqc-analysis', action='store_true', default=True,
                       help='Enable PQC semantic analysis (default: True)')
    
    args = parser.parse_args()
    
    scanner = QuantumCryptoScanner()
    
    try:
        # Setup environment
        scanner.setup_environment()
        
        # Determine scan mode and output format
        if args.cbom_only:
            scan_mode = "enhanced"
            report_format = "cbom"
            generate_html = False
        elif args.legacy_mode:
            scan_mode = "legacy" 
            report_format = "summary"
            generate_html = False
        else:
            scan_mode = "comprehensive"
            report_format = args.format
            generate_html = args.html and STEP3_AVAILABLE
        
        # Run scan
        if STEP3_AVAILABLE and scan_mode == "comprehensive":
            print(f"🚀 Running Step 3 comprehensive scan...")
            results = scanner.scan_codebase_enhanced(args.target, scan_mode, generate_html)
        else:
            print(f"🚀 Running Step 2 enhanced scan...")
            results = scanner.scan_codebase(args.target, scan_mode)
        
        # Generate report
        report = scanner.generate_report(report_format)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"📄 Report saved to: {args.output}")
        else:
            print(report)
        
        # Show HTML dashboard info
        if results.get("html_report_path"):
            print(f"\n🌐 HTML Dashboard generated: {results['html_report_path']}")
            print(f"📊 Open in browser to view interactive results")
            
        # Additional Step 3 outputs
        if not args.cbom_only and not args.legacy_mode and STEP3_AVAILABLE:
            # Save comprehensive results
            results_file = f"{args.target.replace('/', '_')}_comprehensive_results.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"📋 Comprehensive results saved to: {results_file}")
            
            # Save CBOM
            cbom_file = f"{args.target.replace('/', '_')}_cbom.json"
            with open(cbom_file, 'w') as f:
                f.write(scanner.generate_report('cbom'))
            print(f"📋 CBOM saved to: {cbom_file}")
            
    except Exception as e:
        print(f"❌ Error during Step 3 scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    main()