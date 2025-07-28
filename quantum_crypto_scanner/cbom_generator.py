# quantum_crypto_scanner/cbom_generator.py
"""
Step 2: CBOM (Cryptography Bill of Materials) Generation
Integrates with PQCA/cbomkit concepts for standardized crypto inventory
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import hashlib

class CBOMGenerator:
    """
    Generate CBOM (Cryptography Bill of Materials) from crypto scan results
    Compatible with emerging CBOM standards and PQCA/cbomkit formats
    """
    
    def __init__(self):
        self.cbom_version = "1.0"
        self.spec_version = "1.4"  # Following CycloneDX CBOM spec
        self.quantum_risk_assessor = QuantumRiskAssessor()
        
    def generate_cbom(self, scan_results: Dict[str, Any], project_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate a complete CBOM from scan results"""
        print("📋 Generating Cryptography Bill of Materials (CBOM)...")
        
        # Extract project metadata
        if not project_info:
            project_info = self._extract_project_info(scan_results)
            
        # Generate CBOM structure
        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": self.spec_version,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": self._generate_metadata(project_info, scan_results),
            "components": self._generate_crypto_components(scan_results),
            "services": [],
            "dependencies": self._generate_crypto_dependencies(scan_results),
            "compositions": [self._generate_composition(scan_results)],
            "vulnerabilities": self._generate_quantum_vulnerabilities(scan_results),
            "properties": self._generate_cbom_properties(scan_results)
        }
        
        # Add quantum-specific extensions
        cbom["quantumReadiness"] = self._assess_quantum_readiness(scan_results)
        cbom["migrationRecommendations"] = self._generate_migration_recommendations(scan_results)
        
        print(f"✅ Generated CBOM with {len(cbom['components'])} crypto components")
        return cbom
    
    def _generate_metadata(self, project_info: Dict[str, Any], scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate CBOM metadata section"""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Quantum Crypto Scanner",
                    "name": "quantum-crypto-scanner",
                    "version": "0.2.0",
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": self._calculate_tool_hash()
                        }
                    ]
                }
            ],
            "authors": [
                {
                    "name": "Quantum Crypto Scanner",
                    "email": "contact@quantum-crypto-scanner.org"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": project_info.get("name", "unknown-project"),
                "name": project_info.get("name", "Unknown Project"),
                "version": project_info.get("version", "1.0.0"),
                "description": f"Cryptographic inventory for {project_info.get('name', 'project')}"
            },
            "properties": [
                {
                    "name": "quantum-crypto-scanner:scan-method",
                    "value": scan_results.get("analysis_method", "enhanced_ast")
                },
                {
                    "name": "quantum-crypto-scanner:files-scanned",
                    "value": str(scan_results.get("files_analyzed", 0))
                }
            ]
        }
    
    def _generate_crypto_components(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate crypto components from scan findings"""
        components = []
        component_tracker = {}  # Track unique components
        
        for finding in scan_results.get("crypto_findings", []):
            component_key = self._create_component_key(finding)
            
            if component_key not in component_tracker:
                component = {
                    "type": "cryptographic-asset",
                    "bom-ref": f"crypto-{uuid.uuid4()}",
                    "name": f"{finding['crypto_type']}-{finding.get('pattern', 'unknown')}",
                    "version": "unknown",
                    "description": f"{finding['crypto_type']} cryptographic usage",
                    "scope": "required",
                    "hashes": [],
                    "licenses": [],
                    "properties": [
                        {
                            "name": "crypto:algorithm-type",
                            "value": finding['crypto_type']
                        },
                        {
                            "name": "crypto:pattern",
                            "value": finding.get('pattern', 'unknown')
                        },
                        {
                            "name": "crypto:language",
                            "value": finding.get('language', 'unknown')
                        },
                        {
                            "name": "crypto:confidence",
                            "value": str(finding.get('confidence', 0.5))
                        },
                        {
                            "name": "crypto:severity",
                            "value": finding.get('severity', 'MEDIUM')
                        }
                    ]
                }
                
                # Add quantum risk assessment
                quantum_risk = self.quantum_risk_assessor.assess_crypto_component(finding)
                component["properties"].extend([
                    {
                        "name": "quantum:vulnerable",
                        "value": str(quantum_risk["is_quantum_vulnerable"])
                    },
                    {
                        "name": "quantum:risk-level",
                        "value": quantum_risk["risk_level"]
                    },
                    {
                        "name": "quantum:break-timeline",
                        "value": quantum_risk["estimated_break_timeline"]
                    },
                    {
                        "name": "quantum:attack-method",
                        "value": quantum_risk["attack_method"]
                    }
                ])
                
                components.append(component)
                component_tracker[component_key] = component["bom-ref"]
        
        return components
    
    def _generate_crypto_dependencies(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate dependency relationships between crypto components"""
        dependencies = []
        
        # Group findings by file to understand dependencies
        file_groups = {}
        for finding in scan_results.get("crypto_findings", []):
            file_path = finding.get("file", "unknown")
            if file_path not in file_groups:
                file_groups[file_path] = []
            file_groups[file_path].append(finding)
        
        # Create dependencies for files with multiple crypto components
        for file_path, findings in file_groups.items():
            if len(findings) > 1:
                file_ref = f"file-{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
                dependsOn = []
                
                for finding in findings:
                    component_key = self._create_component_key(finding)
                    dependsOn.append(f"crypto-component-{component_key}")
                
                dependencies.append({
                    "ref": file_ref,
                    "dependsOn": dependsOn
                })
        
        return dependencies
    
    def _generate_composition(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate composition information"""
        return {
            "aggregate": "complete",
            "assemblies": [
                {
                    "bom-ref": "cryptographic-inventory",
                    "dependencies": [f"crypto-{i}" for i in range(len(scan_results.get("crypto_findings", [])))]
                }
            ]
        }
    
    def _generate_quantum_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate quantum-specific vulnerability information"""
        vulnerabilities = []
        vuln_id_counter = 1
        
        for finding in scan_results.get("crypto_findings", []):
            if finding['crypto_type'] in ['RSA', 'ECC', 'DH']:
                vuln = {
                    "bom-ref": f"quantum-vuln-{vuln_id_counter}",
                    "id": f"QUANTUM-{finding['crypto_type']}-{vuln_id_counter}",
                    "source": {
                        "name": "Quantum Crypto Scanner",
                        "url": "https://github.com/quantum-crypto-scanner"
                    },
                    "references": [
                        {
                            "id": "NIST-PQC",
                            "source": {
                                "name": "NIST Post-Quantum Cryptography",
                                "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
                            }
                        }
                    ],
                    "ratings": [
                        {
                            "source": {
                                "name": "Quantum Crypto Scanner"
                            },
                            "score": 9.0 if finding['crypto_type'] in ['RSA', 'ECC'] else 7.0,
                            "severity": "critical" if finding['crypto_type'] in ['RSA', 'ECC'] else "high",
                            "method": "CVSSv3",
                            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                        }
                    ],
                    "cwes": [327],  # Use of a Broken or Risky Cryptographic Algorithm
                    "description": f"{finding['crypto_type']} cryptographic algorithm vulnerable to quantum attacks via Shor's algorithm",
                    "detail": f"Found {finding['crypto_type']} usage at {finding.get('file', 'unknown')}:{finding.get('line', 0)}. This algorithm will be broken by sufficiently powerful quantum computers.",
                    "recommendation": self._get_quantum_recommendation(finding['crypto_type']),
                    "affects": [
                        {
                            "ref": f"crypto-component-{self._create_component_key(finding)}"
                        }
                    ]
                }
                
                vulnerabilities.append(vuln)
                vuln_id_counter += 1
        
        return vulnerabilities
    
    def _generate_cbom_properties(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate CBOM-level properties"""
        total_findings = len(scan_results.get("crypto_findings", []))
        quantum_vulnerable = len([f for f in scan_results.get("crypto_findings", []) 
                                 if f['crypto_type'] in ['RSA', 'ECC', 'DH']])
        
        return [
            {
                "name": "cbom:total-crypto-assets",
                "value": str(total_findings)
            },
            {
                "name": "cbom:quantum-vulnerable-count",
                "value": str(quantum_vulnerable)
            },
            {
                "name": "cbom:quantum-safe-percentage",
                "value": str(round((total_findings - quantum_vulnerable) / max(total_findings, 1) * 100, 2))
            },
            {
                "name": "cbom:languages-analyzed",
                "value": ",".join(scan_results.get("languages_detected", []))
            },
            {
                "name": "cbom:scan-timestamp",
                "value": datetime.now(timezone.utc).isoformat()
            }
        ]
    
    def _assess_quantum_readiness(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall quantum readiness of the project"""
        findings = scan_results.get("crypto_findings", [])
        total_crypto = len(findings)
        
        if total_crypto == 0:
            return {
                "status": "unknown",
                "score": 0,
                "assessment": "No cryptographic usage detected"
            }
        
        quantum_vulnerable = len([f for f in findings if f['crypto_type'] in ['RSA', 'ECC', 'DH']])
        weak_crypto = len([f for f in findings if f['crypto_type'] == 'HASH' and 
                          any(weak in f.get('pattern', '') for weak in ['MD5', 'SHA1'])])
        
        quantum_safe_percentage = (total_crypto - quantum_vulnerable - weak_crypto) / total_crypto * 100
        
        if quantum_safe_percentage >= 90:
            status = "quantum-ready"
            score = 90 + (quantum_safe_percentage - 90)
        elif quantum_safe_percentage >= 70:
            status = "mostly-ready"
            score = 70 + (quantum_safe_percentage - 70)
        elif quantum_safe_percentage >= 40:
            status = "needs-attention"
            score = 40 + (quantum_safe_percentage - 40)
        else:
            status = "high-risk"
            score = quantum_safe_percentage
        
        return {
            "status": status,
            "score": round(score, 1),
            "assessment": f"{quantum_safe_percentage:.1f}% quantum-safe cryptography",
            "total_crypto_assets": total_crypto,
            "quantum_vulnerable_assets": quantum_vulnerable,
            "weak_crypto_assets": weak_crypto,
            "recommendation": self._get_readiness_recommendation(status)
        }
    
    def _generate_migration_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate specific migration recommendations"""
        recommendations = []
        
        # Group findings by crypto type
        crypto_groups = {}
        for finding in scan_results.get("crypto_findings", []):
            crypto_type = finding['crypto_type']
            if crypto_type not in crypto_groups:
                crypto_groups[crypto_type] = []
            crypto_groups[crypto_type].append(finding)
        
        # Generate recommendations for each crypto type
        for crypto_type, findings in crypto_groups.items():
            if crypto_type in ['RSA', 'ECC', 'DH']:
                recommendations.append({
                    "crypto_type": crypto_type,
                    "priority": "HIGH",
                    "affected_files": len(set(f.get('file', '') for f in findings)),
                    "affected_instances": len(findings),
                    "nist_recommendation": self._get_nist_recommendation(crypto_type),
                    "migration_timeline": "Before 2030",
                    "estimated_effort": self._estimate_migration_effort(findings),
                    "specific_actions": self._get_specific_actions(crypto_type, findings)
                })
        
        return recommendations
    
    def _create_component_key(self, finding: Dict[str, Any]) -> str:
        """Create a unique key for a crypto component"""
        key_parts = [
            finding['crypto_type'],
            finding.get('pattern', 'unknown'),
            finding.get('language', 'unknown')
        ]
        return hashlib.md5("-".join(key_parts).encode()).hexdigest()[:12]
    
    def _extract_project_info(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract project information from scan results"""
        # Try to derive project name from target path
        target_path = scan_results.get("target_path", "unknown-project")
        project_name = Path(target_path).name if target_path != "unknown-project" else "unknown-project"
        
        return {
            "name": project_name,
            "version": "1.0.0",
            "description": f"Cryptographic inventory for {project_name}"
        }
    
    def _calculate_tool_hash(self) -> str:
        """Calculate hash of the scanning tool for integrity"""
        # In a real implementation, this would hash the actual tool binary/code
        return hashlib.sha256(b"quantum-crypto-scanner-v0.2.0").hexdigest()
    
    def _get_quantum_recommendation(self, crypto_type: str) -> str:
        """Get quantum-specific recommendation for a crypto type"""
        recommendations = {
            "RSA": "Migrate to ML-DSA (Dilithium) for digital signatures or ML-KEM (Kyber) for key encapsulation",
            "ECC": "Replace with ML-DSA (Dilithium) for signatures or consider hybrid classical+PQC approach",
            "DH": "Migrate to ML-KEM (Kyber) for key agreement or use hybrid approach with X25519+Kyber"
        }
        return recommendations.get(crypto_type, "Evaluate quantum resistance and consider NIST PQC alternatives")
    
    def _get_nist_recommendation(self, crypto_type: str) -> Dict[str, Any]:
        """Get NIST PQC recommendations for crypto type"""
        nist_recommendations = {
            "RSA": {
                "signatures": ["ML-DSA (FIPS 204)", "SLH-DSA (FIPS 205)"],
                "key_encapsulation": ["ML-KEM (FIPS 203)"],
                "priority": "HIGH"
            },
            "ECC": {
                "signatures": ["ML-DSA (FIPS 204)", "SLH-DSA (FIPS 205)"],
                "key_agreement": ["ML-KEM (FIPS 203)"],
                "priority": "HIGH"
            },
            "DH": {
                "key_agreement": ["ML-KEM (FIPS 203)"],
                "priority": "MEDIUM"
            }
        }
        return nist_recommendations.get(crypto_type, {"priority": "LOW"})
    
    def _estimate_migration_effort(self, findings: List[Dict[str, Any]]) -> str:
        """Estimate migration effort based on findings"""
        instance_count = len(findings)
        file_count = len(set(f.get('file', '') for f in findings))
        
        if instance_count <= 5 and file_count <= 2:
            return "LOW"
        elif instance_count <= 20 and file_count <= 10:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _get_specific_actions(self, crypto_type: str, findings: List[Dict[str, Any]]) -> List[str]:
        """Get specific actionable recommendations"""
        actions = []
        file_count = len(set(f.get('file', '') for f in findings))
        
        if crypto_type == "RSA":
            actions.extend([
                f"Replace RSA key generation in {file_count} file(s)",
                "Implement ML-KEM for key encapsulation",
                "Use ML-DSA for digital signatures",
                "Consider hybrid RSA+PQC during transition"
            ])
        elif crypto_type == "ECC":
            actions.extend([
                f"Replace ECC usage in {file_count} file(s)",
                "Migrate ECDSA to ML-DSA",
                "Replace ECDH with ML-KEM",
                "Update certificate generation processes"
            ])
        
        return actions
    
    def _get_readiness_recommendation(self, status: str) -> str:
        """Get recommendation based on quantum readiness status"""
        recommendations = {
            "quantum-ready": "Excellent! Continue monitoring for new crypto usage",
            "mostly-ready": "Good position. Address remaining quantum-vulnerable crypto",
            "needs-attention": "Priority migration needed. Focus on high-impact crypto first", 
            "high-risk": "Urgent action required. Develop comprehensive migration plan"
        }
        return recommendations.get(status, "Assess quantum cryptography usage")


class QuantumRiskAssessor:
    """Assess quantum risk for individual crypto components"""
    
    def assess_crypto_component(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Assess quantum risk for a single crypto finding"""
        crypto_type = finding['crypto_type']
        
        # Quantum vulnerability assessment
        if crypto_type in ['RSA', 'ECC']:
            return {
                "is_quantum_vulnerable": True,
                "risk_level": "CRITICAL",
                "estimated_break_timeline": "2030-2035",
                "attack_method": "Shor's Algorithm",
                "confidence": 0.95
            }
        elif crypto_type == 'DH':
            return {
                "is_quantum_vulnerable": True,
                "risk_level": "HIGH",
                "estimated_break_timeline": "2030-2035", 
                "attack_method": "Shor's Algorithm",
                "confidence": 0.90
            }
        elif crypto_type == 'HASH':
            # Check for weak hashes
            pattern = finding.get('pattern', '').upper()
            if any(weak in pattern for weak in ['MD5', 'SHA1']):
                return {
                    "is_quantum_vulnerable": True,
                    "risk_level": "MEDIUM",
                    "estimated_break_timeline": "2035-2040",
                    "attack_method": "Grover's Algorithm", 
                    "confidence": 0.80
                }
        
        # Default for quantum-resistant crypto
        return {
            "is_quantum_vulnerable": False,
            "risk_level": "LOW",
            "estimated_break_timeline": "Post-2050",
            "attack_method": "None known",
            "confidence": 0.70
        }