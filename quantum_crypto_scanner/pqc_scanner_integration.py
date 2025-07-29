# quantum_crypto_scanner/pqc_scanner_integration.py
"""
Step 3: PQC Scanner Integration
Integrates semantic analysis capabilities inspired by epap011/Crypto-Scanner-PQC
Enhanced pattern matching and cryptographic context analysis
"""

import os
import json
import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import subprocess

class PQCSemanticAnalyzer:
    """
    Advanced semantic analyzer for cryptographic code patterns
    Inspired by epap011/Crypto-Scanner-PQC methodology
    """
    
    def __init__(self):
        self.semantic_rules = self._load_semantic_rules()
        self.crypto_context_patterns = self._load_context_patterns()
        self.pqc_knowledge_base = self._load_pqc_knowledge()
        
    def analyze_project_semantics(self, project_path: Path) -> Dict[str, Any]:
        """
        Perform semantic analysis on the entire project
        
        Args:
            project_path: Path to the project directory
            
        Returns:
            Comprehensive semantic analysis results
        """
        print("🧠 Running PQC semantic analysis...")
        
        results = {
            "analysis_method": "pqc_semantic",
            "semantic_findings": [],
            "context_analysis": {},
            "crypto_dependencies": [],
            "pqc_recommendations": [],
            "semantic_confidence": {},
            "files_analyzed": 0,
            "languages_detected": set()
        }
        
        # Analyze each supported file
        for file_path in project_path.rglob('*'):
            if self._is_supported_file(file_path):
                file_results = self._analyze_file_semantics(file_path)
                if file_results:
                    results["semantic_findings"].extend(file_results.get("findings", []))
                    results["files_analyzed"] += 1
                    
                    # Merge language detection
                    if "language" in file_results:
                        results["languages_detected"].add(file_results["language"])
        
        # Perform cross-file analysis
        results["context_analysis"] = self._perform_context_analysis(results["semantic_findings"])
        results["crypto_dependencies"] = self._analyze_crypto_dependencies(results["semantic_findings"])
        results["pqc_recommendations"] = self._generate_pqc_recommendations(results["semantic_findings"])
        
        # Convert set to list for JSON serialization
        results["languages_detected"] = list(results["languages_detected"])
        
        print(f"✅ PQC semantic analysis complete: {len(results['semantic_findings'])} semantic findings")
        return results
    
    def _analyze_file_semantics(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Perform semantic analysis on a single file
        """
        try:
            language = self._detect_file_language(file_path)
            if not language:
                return None
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            if language == 'python':
                return self._analyze_python_semantics(file_path, content)
            elif language == 'java':
                return self._analyze_java_semantics(file_path, content)
            elif language == 'javascript':
                return self._analyze_javascript_semantics(file_path, content)
            else:
                return self._analyze_generic_semantics(file_path, content, language)
                
        except Exception as e:
            print(f"⚠️ Error in semantic analysis of {file_path}: {e}")
            return None
    
    def _analyze_python_semantics(self, file_path: Path, content: str) -> Dict[str, Any]:
        """
        Advanced semantic analysis for Python files using AST
        """
        findings = []
        
        try:
            # Parse AST for deep semantic analysis
            tree = ast.parse(content)
            
            # Analyze imports for crypto libraries
            crypto_imports = self._analyze_python_imports(tree)
            findings.extend(crypto_imports)
            
            # Analyze function calls with context
            function_calls = self._analyze_python_functions(tree, content)
            findings.extend(function_calls)
            
            # Analyze variable assignments
            crypto_assignments = self._analyze_python_assignments(tree, content)
            findings.extend(crypto_assignments)
            
            # Analyze class definitions for crypto patterns
            crypto_classes = self._analyze_python_classes(tree, content)
            findings.extend(crypto_classes)
            
        except SyntaxError:
            # Fallback to regex-based analysis for problematic files
            findings = self._analyze_generic_semantics(file_path, content, 'python')["findings"]
        
        return {
            "language": "python",
            "findings": findings,
            "file_path": str(file_path)
        }
    
    def _analyze_python_imports(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Analyze Python imports for cryptographic libraries"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if self._is_crypto_import(alias.name):
                        findings.append({
                            "type": "crypto_import",
                            "line": node.lineno,
                            "import_name": alias.name,
                            "crypto_type": self._classify_crypto_import(alias.name),
                            "semantic_context": "import_statement",
                            "confidence": 0.95,
                            "pqc_impact": self._assess_pqc_impact(alias.name)
                        })
            
            elif isinstance(node, ast.ImportFrom):
                if node.module and self._is_crypto_import(node.module):
                    for alias in node.names:
                        findings.append({
                            "type": "crypto_from_import",
                            "line": node.lineno,
                            "module": node.module,
                            "import_name": alias.name,
                            "crypto_type": self._classify_crypto_import(f"{node.module}.{alias.name}"),
                            "semantic_context": "from_import_statement",
                            "confidence": 0.9,
                            "pqc_impact": self._assess_pqc_impact(f"{node.module}.{alias.name}")
                        })
        
        return findings
    
    def _analyze_python_functions(self, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Analyze Python function calls for crypto operations"""
        findings = []
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Analyze function calls
                func_name = self._get_function_name(node)
                if func_name and self._is_crypto_function(func_name):
                    context = self._extract_function_context(node, lines)
                    
                    findings.append({
                        "type": "crypto_function_call",
                        "line": node.lineno,
                        "function_name": func_name,
                        "crypto_type": self._classify_crypto_function(func_name),
                        "semantic_context": context,
                        "arguments": self._extract_function_args(node),
                        "confidence": 0.85,
                        "pqc_impact": self._assess_function_pqc_impact(func_name, context)
                    })
        
        return findings
    
    def _analyze_python_assignments(self, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Analyze variable assignments for crypto operations"""
        findings = []
        lines = content.split('\n')
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    func_name = self._get_function_name(node.value)
                    if func_name and self._is_crypto_function(func_name):
                        var_names = [target.id for target in node.targets if isinstance(target, ast.Name)]
                        
                        findings.append({
                            "type": "crypto_assignment",
                            "line": node.lineno,
                            "variable_names": var_names,
                            "function_name": func_name,
                            "crypto_type": self._classify_crypto_function(func_name),
                            "semantic_context": "variable_assignment",
                            "confidence": 0.8,
                            "pqc_impact": self._assess_function_pqc_impact(func_name, "assignment")
                        })
        
        return findings
    
    def _analyze_python_classes(self, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Analyze class definitions for crypto patterns"""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if self._is_crypto_class(node.name):
                    findings.append({
                        "type": "crypto_class",
                        "line": node.lineno,
                        "class_name": node.name,
                        "crypto_type": self._classify_crypto_class(node.name),
                        "semantic_context": "class_definition",
                        "confidence": 0.75,
                        "pqc_impact": self._assess_class_pqc_impact(node.name)
                    })
        
        return findings
    
    def _analyze_java_semantics(self, file_path: Path, content: str) -> Dict[str, Any]:
        """
        Advanced semantic analysis for Java files
        """
        findings = []
        lines = content.split('\n')
        
        # Analyze imports
        import_patterns = [
            r'import\s+java\.security\.([^;]+);',
            r'import\s+javax\.crypto\.([^;]+);',
            r'import\s+org\.bouncycastle\.([^;]+);'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in import_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append({
                        "type": "crypto_import",
                        "line": line_num,
                        "import_name": match.group(1),
                        "crypto_type": self._classify_java_crypto_import(match.group(1)),
                        "semantic_context": "java_import",
                        "confidence": 0.9,
                        "pqc_impact": self._assess_java_pqc_impact(match.group(1))
                    })
        
        # Analyze method calls
        method_patterns = [
            r'KeyPairGenerator\.getInstance\("([^"]+)"\)',
            r'Cipher\.getInstance\("([^"]+)"\)',
            r'MessageDigest\.getInstance\("([^"]+)"\)',
            r'Signature\.getInstance\("([^"]+)"\)'
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in method_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    findings.append({
                        "type": "crypto_method_call",
                        "line": line_num,
                        "method_call": match.group(0),
                        "algorithm": match.group(1),
                        "crypto_type": self._classify_java_algorithm(match.group(1)),
                        "semantic_context": "java_method_call",
                        "confidence": 0.85,
                        "pqc_impact": self._assess_algorithm_pqc_impact(match.group(1))
                    })
        
        return {
            "language": "java",
            "findings": findings,
            "file_path": str(file_path)
        }
    
    def _analyze_javascript_semantics(self, file_path: Path, content: str) -> Dict[str, Any]:
        """
        Semantic analysis for JavaScript/Node.js crypto patterns
        """
        findings = []
        lines = content.split('\n')
        
        # JavaScript crypto patterns
        js_patterns = [
            (r'require\([\'"]crypto[\'"]\)', "crypto_require"),
            (r'require\([\'"]node-forge[\'"]\)', "forge_require"),
            (r'crypto\.createHash\([\'"]([^\'"]+)[\'"]\)', "hash_creation"),
            (r'crypto\.generateKeyPairSync\([\'"]([^\'"]+)[\'"]\)', "keypair_generation"),
            (r'forge\.pki\.rsa\.generateKeyPair\(', "rsa_generation"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, finding_type in js_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    algorithm = match.group(1) if match.groups() else "unknown"
                    
                    findings.append({
                        "type": finding_type,
                        "line": line_num,
                        "pattern": match.group(0),
                        "algorithm": algorithm,
                        "crypto_type": self._classify_js_crypto(finding_type, algorithm),
                        "semantic_context": "javascript_crypto",
                        "confidence": 0.8,
                        "pqc_impact": self._assess_js_pqc_impact(finding_type, algorithm)
                    })
        
        return {
            "language": "javascript",
            "findings": findings,
            "file_path": str(file_path)
        }
    
    def _analyze_generic_semantics(self, file_path: Path, content: str, language: str) -> Dict[str, Any]:
        """
        Generic semantic analysis for other languages
        """
        findings = []
        lines = content.split('\n')
        
        # Generic crypto patterns
        generic_patterns = self.semantic_rules.get("generic_patterns", [])
        
        for line_num, line in enumerate(lines, 1):
            for pattern_info in generic_patterns:
                pattern = pattern_info["pattern"]
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "type": "generic_crypto_pattern",
                        "line": line_num,
                        "pattern": match.group(0),
                        "crypto_type": pattern_info["crypto_type"],
                        "semantic_context": f"{language}_generic",
                        "confidence": pattern_info.get("confidence", 0.6),
                        "pqc_impact": self._assess_generic_pqc_impact(pattern_info["crypto_type"])
                    })
        
        return {
            "language": language,
            "findings": findings,
            "file_path": str(file_path)
        }
    
    def _perform_context_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform cross-file context analysis to understand crypto usage patterns
        """
        context_analysis = {
            "crypto_usage_patterns": {},
            "dependency_chains": [],
            "security_contexts": [],
            "architectural_insights": []
        }
        
        # Group findings by crypto type
        crypto_groups = {}
        for finding in findings:
            crypto_type = finding.get("crypto_type", "unknown")
            if crypto_type not in crypto_groups:
                crypto_groups[crypto_type] = []
            crypto_groups[crypto_type].append(finding)
        
        # Analyze usage patterns
        for crypto_type, group_findings in crypto_groups.items():
            context_analysis["crypto_usage_patterns"][crypto_type] = {
                "usage_count": len(group_findings),
                "files_affected": len(set(f.get("file_path", "") for f in group_findings)),
                "confidence_average": sum(f.get("confidence", 0) for f in group_findings) / len(group_findings),
                "semantic_contexts": list(set(f.get("semantic_context", "") for f in group_findings))
            }
        
        return context_analysis
    
    def _analyze_crypto_dependencies(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze cryptographic dependencies and their relationships
        """
        dependencies = []
        
        # Extract imports and their usage
        imports = [f for f in findings if f.get("type", "").endswith("import")]
        usages = [f for f in findings if f.get("type", "") in ["crypto_function_call", "crypto_method_call"]]
        
        for import_finding in imports:
            related_usages = [
                u for u in usages 
                if self._are_related(import_finding, u)
            ]
            
            if related_usages:
                dependencies.append({
                    "import": import_finding,
                    "usages": related_usages,
                    "dependency_strength": len(related_usages),
                    "pqc_migration_complexity": self._assess_migration_complexity(import_finding, related_usages)
                })
        
        return dependencies
    
    def _generate_pqc_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate specific PQC migration recommendations based on semantic analysis
        """
        recommendations = []
        
        # Group findings by PQC impact
        high_impact = [f for f in findings if f.get("pqc_impact", {}).get("level") == "HIGH"]
        medium_impact = [f for f in findings if f.get("pqc_impact", {}).get("level") == "MEDIUM"]
        
        # Generate high priority recommendations
        for finding in high_impact:
            recommendations.append({
                "priority": "HIGH",
                "finding": finding,
                "recommendation": self._get_specific_pqc_recommendation(finding),
                "estimated_effort": self._estimate_migration_effort(finding),
                "nist_standard": self._get_nist_standard_recommendation(finding),
                "timeline": "Before 2030"
            })
        
        # Generate medium priority recommendations
        for finding in medium_impact:
            recommendations.append({
                "priority": "MEDIUM", 
                "finding": finding,
                "recommendation": self._get_specific_pqc_recommendation(finding),
                "estimated_effort": self._estimate_migration_effort(finding),
                "nist_standard": self._get_nist_standard_recommendation(finding),
                "timeline": "2030-2035"
            })
        
        return recommendations
    
    # Utility methods
    def _load_semantic_rules(self) -> Dict[str, Any]:
        """Load semantic analysis rules"""
        return {
            "crypto_imports": {
                "python": ["Crypto", "cryptography", "hashlib", "secrets"],
                "java": ["java.security", "javax.crypto", "org.bouncycastle"],
                "javascript": ["crypto", "node-forge", "bcrypt"]
            },
            "crypto_functions": {
                "python": ["generate", "encrypt", "decrypt", "sign", "verify", "hash"],
                "java": ["getInstance", "generateKeyPair", "init", "doFinal"],
                "javascript": ["createHash", "createCipher", "generateKeyPair"]
            },
            "generic_patterns": [
                {"pattern": r"RSA\.generate", "crypto_type": "RSA", "confidence": 0.9},
                {"pattern": r"ECDSA", "crypto_type": "ECC", "confidence": 0.85},
                {"pattern": r"md5|MD5", "crypto_type": "HASH", "confidence": 0.8},
                {"pattern": r"sha1|SHA1", "crypto_type": "HASH", "confidence": 0.8},
                {"pattern": r"AES\.new", "crypto_type": "AES", "confidence": 0.85}
            ]
        }
    
    def _load_context_patterns(self) -> Dict[str, Any]:
        """Load context analysis patterns"""
        return {
            "security_contexts": ["authentication", "encryption", "signing", "hashing"],
            "usage_patterns": ["key_generation", "data_encryption", "digital_signature", "hash_computation"]
        }
    
    def _load_pqc_knowledge(self) -> Dict[str, Any]:
        """Load PQC knowledge base"""
        return {
            "vulnerable_algorithms": {
                "RSA": {"threat": "Shor's Algorithm", "timeline": "2030-2035", "replacement": "ML-DSA"},
                "ECC": {"threat": "Shor's Algorithm", "timeline": "2030-2035", "replacement": "ML-DSA"},
                "DH": {"threat": "Shor's Algorithm", "timeline": "2030-2035", "replacement": "ML-KEM"}
            },
            "pqc_standards": {
                "ML-DSA": "FIPS 204 - Digital Signatures",
                "ML-KEM": "FIPS 203 - Key Encapsulation",
                "SLH-DSA": "FIPS 205 - Stateless Hash-Based Signatures"
            }
        }
    
    def _is_supported_file(self, file_path: Path) -> bool:
        """Check if file is supported for semantic analysis"""
        supported_extensions = {'.py', '.java', '.js', '.ts', '.go', '.cpp', '.c', '.cs'}
        return file_path.suffix in supported_extensions
    
    def _detect_file_language(self, file_path: Path) -> Optional[str]:
        """Detect programming language from file extension"""
        extension_map = {
            '.py': 'python',
            '.java': 'java',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.go': 'go',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp'
        }
        return extension_map.get(file_path.suffix)
    
    def _is_crypto_import(self, import_name: str) -> bool:
        """Check if import is crypto-related"""
        crypto_keywords = ["crypto", "security", "cipher", "hash", "rsa", "ecc", "aes"]
        return any(keyword in import_name.lower() for keyword in crypto_keywords)
    
    def _classify_crypto_import(self, import_name: str) -> str:
        """Classify the type of crypto import"""
        if "rsa" in import_name.lower():
            return "RSA"
        elif any(ecc in import_name.lower() for ecc in ["ecc", "ecdsa", "elliptic"]):
            return "ECC"
        elif "aes" in import_name.lower():
            return "AES"
        elif any(hash_type in import_name.lower() for hash_type in ["hash", "md5", "sha"]):
            return "HASH"
        else:
            return "CRYPTO_GENERIC"
    
    def _assess_pqc_impact(self, import_name: str) -> Dict[str, Any]:
        """Assess PQC impact of an import"""
        crypto_type = self._classify_crypto_import(import_name)
        if crypto_type in ["RSA", "ECC", "DH"]:
            return {"level": "HIGH", "reason": "Quantum vulnerable algorithm"}
        elif crypto_type == "HASH":
            return {"level": "MEDIUM", "reason": "Partially quantum vulnerable"}
        else:
            return {"level": "LOW", "reason": "Quantum resistant or unknown"}
    
    def _get_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract function name from AST Call node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        return None
    
    def _is_crypto_function(self, func_name: str) -> bool:
        """Check if function name is crypto-related"""
        crypto_functions = ["generate", "encrypt", "decrypt", "sign", "verify", "hash", "digest"]
        return any(cf in func_name.lower() for cf in crypto_functions)
    
    def _classify_crypto_function(self, func_name: str) -> str:
        """Classify crypto function type"""
        if "generate" in func_name.lower() and "rsa" in func_name.lower():
            return "RSA"
        elif "generate" in func_name.lower() and any(ecc in func_name.lower() for ecc in ["ecc", "ecdsa"]):
            return "ECC"
        elif any(hash_type in func_name.lower() for hash_type in ["hash", "md5", "sha"]):
            return "HASH"
        elif "aes" in func_name.lower():
            return "AES"
        else:
            return "CRYPTO_FUNCTION"
    
    def _extract_function_context(self, node: ast.Call, lines: List[str]) -> str:
        """Extract context around function call"""
        if hasattr(node, 'lineno') and node.lineno <= len(lines):
            return lines[node.lineno - 1].strip()
        return "unknown_context"
    
    def _extract_function_args(self, node: ast.Call) -> List[str]:
        """Extract function arguments"""
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Constant):
                args.append(str(arg.value))
            elif isinstance(arg, ast.Name):
                args.append(arg.id)
        return args
    
    def _assess_function_pqc_impact(self, func_name: str, context: str) -> Dict[str, Any]:
        """Assess PQC impact of function call"""
        crypto_type = self._classify_crypto_function(func_name)
        return self._assess_pqc_impact(crypto_type)
    
    def _is_crypto_class(self, class_name: str) -> bool:
        """Check if class name is crypto-related"""
        crypto_classes = ["cipher", "hash", "crypto", "rsa", "ecc", "aes"]
        return any(cc in class_name.lower() for cc in crypto_classes)
    
    def _classify_crypto_class(self, class_name: str) -> str:
        """Classify crypto class type"""
        return self._classify_crypto_import(class_name)
    
    def _assess_class_pqc_impact(self, class_name: str) -> Dict[str, Any]:
        """Assess PQC impact of class"""
        return self._assess_pqc_impact(class_name)
    
    def _classify_java_crypto_import(self, import_name: str) -> str:
        """Classify Java crypto import"""
        return self._classify_crypto_import(import_name)
    
    def _assess_java_pqc_impact(self, import_name: str) -> Dict[str, Any]:
        """Assess PQC impact of Java import"""
        return self._assess_pqc_impact(import_name)
    
    def _classify_java_algorithm(self, algorithm: str) -> str:
        """Classify Java crypto algorithm"""
        if algorithm.upper() in ["RSA"]:
            return "RSA"
        elif algorithm.upper() in ["EC", "ECDSA"]:
            return "ECC"
        elif algorithm.upper() in ["MD5", "SHA-1", "SHA1"]:
            return "HASH"
        elif algorithm.upper() in ["AES"]:
            return "AES"
        else:
            return "CRYPTO_ALGORITHM"
    
    def _assess_algorithm_pqc_impact(self, algorithm: str) -> Dict[str, Any]:
        """Assess PQC impact of algorithm"""
        crypto_type = self._classify_java_algorithm(algorithm)
        return self._assess_pqc_impact(crypto_type)
    
    def _classify_js_crypto(self, finding_type: str, algorithm: str) -> str:
        """Classify JavaScript crypto finding"""
        if "rsa" in finding_type.lower() or "rsa" in algorithm.lower():
            return "RSA"
        elif "hash" in finding_type.lower():
            return "HASH"
        elif "keypair" in finding_type.lower():
            if "rsa" in algorithm.lower():
                return "RSA"
            elif "ec" in algorithm.lower():
                return "ECC"
        return "CRYPTO_JS"
    
    def _assess_js_pqc_impact(self, finding_type: str, algorithm: str) -> Dict[str, Any]:
        """Assess PQC impact of JavaScript crypto"""
        crypto_type = self._classify_js_crypto(finding_type, algorithm)
        return self._assess_pqc_impact(crypto_type)
    
    def _assess_generic_pqc_impact(self, crypto_type: str) -> Dict[str, Any]:
        """Assess PQC impact of generic crypto"""
        return self._assess_pqc_impact(crypto_type)
    
    def _are_related(self, import_finding: Dict[str, Any], usage_finding: Dict[str, Any]) -> bool:
        """Check if import and usage are related"""
        import_name = import_finding.get("import_name", "").lower()
        usage_context = usage_finding.get("semantic_context", "").lower()
        return import_name in usage_context or any(
            part in usage_context for part in import_name.split(".")
        )
    
    def _assess_migration_complexity(self, import_finding: Dict[str, Any], usages: List[Dict[str, Any]]) -> str:
        """Assess migration complexity based on usage patterns"""
        usage_count = len(usages)
        if usage_count > 10:
            return "HIGH"
        elif usage_count > 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_specific_pqc_recommendation(self, finding: Dict[str, Any]) -> str:
        """Get specific PQC recommendation for finding"""
        crypto_type = finding.get("crypto_type", "")
        pqc_knowledge = self.pqc_knowledge_base.get("vulnerable_algorithms", {})
        
        if crypto_type in pqc_knowledge:
            replacement = pqc_knowledge[crypto_type]["replacement"]
            return f"Replace {crypto_type} with {replacement}"
        else:
            return "Evaluate quantum resistance and consider NIST PQC alternatives"
    
    def _estimate_migration_effort(self, finding: Dict[str, Any]) -> str:
        """Estimate migration effort for finding"""
        confidence = finding.get("confidence", 0.5)
        if confidence > 0.8:
            return "LOW"
        elif confidence > 0.6:
            return "MEDIUM"
        else:
            return "HIGH"
    
    def _get_nist_standard_recommendation(self, finding: Dict[str, Any]) -> str:
        """Get NIST standard recommendation"""
        crypto_type = finding.get("crypto_type", "")
        standards = self.pqc_knowledge_base.get("pqc_standards", {})
        
        if crypto_type in ["RSA", "ECC"]:
            return standards.get("ML-DSA", "ML-DSA for digital signatures")
        elif crypto_type in ["DH"]:
            return standards.get("ML-KEM", "ML-KEM for key encapsulation")
        else:
            return "Consult NIST PQC standards"