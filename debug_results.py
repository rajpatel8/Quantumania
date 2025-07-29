#!/usr/bin/env python3
# debug_results.py - Debug the results structure

import tempfile
import json
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
        print("🔍 Running scan...")
        results = scanner.scan_codebase(str(temp_dir))
        
        print(f"📊 Results top-level keys: {list(results.keys())}")
        
        # Check specific fields
        if 'target_path' in results:
            print(f"✅ target_path found: {results['target_path']}")
        else:
            print(f"❌ target_path missing")
            
        if 'scan_metadata' in results:
            print(f"✅ scan_metadata found")
            if 'target_path' in results['scan_metadata']:
                print(f"   - target_path in scan_metadata: {results['scan_metadata']['target_path']}")
        
        if 'sonar_cryptography_results' in results:
            sonar_results = results['sonar_cryptography_results']
            print(f"✅ sonar_cryptography_results found")
            print(f"   - Keys: {list(sonar_results.keys())}")
            
            required_fields = ['crypto_findings', 'files_analyzed', 'files_scanned']
            for field in required_fields:
                if field in sonar_results:
                    value = sonar_results[field]
                    if field == 'crypto_findings':
                        print(f"   - {field}: {len(value)} findings")
                    else:
                        print(f"   - {field}: {value}")
                else:
                    print(f"   - ❌ {field}: MISSING")
        
        print(f"\n📄 Full results structure (first level only):")
        for key, value in results.items():
            if isinstance(value, dict):
                print(f"   {key}: dict with {len(value)} keys")
            elif isinstance(value, list):
                print(f"   {key}: list with {len(value)} items")
            else:
                print(f"   {key}: {type(value).__name__} = {value}")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        scanner.cleanup()