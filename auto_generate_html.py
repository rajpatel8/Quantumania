#!/usr/bin/env python3
"""
Auto HTML Report Generator
Automatically generates HTML reports from JSON files in the results folder
Can also be used standalone with any JSON file

Usage:
    python auto_generate_html.py                    # Process all JSON files in results/
    python auto_generate_html.py <specific_file>    # Process specific JSON file
"""

import sys
import os
import json
from pathlib import Path
from typing import List, Dict, Any


def find_json_files(directory: str = "results") -> List[Path]:
    """Find all JSON files in the specified directory"""
    results_dir = Path(directory)
    if not results_dir.exists():
        return []
    
    json_files = []
    for file_path in results_dir.glob("*.json"):
        if file_path.is_file():
            json_files.append(file_path)
    
    return json_files


def is_valid_scan_json(json_data: Dict[str, Any]) -> bool:
    """Check if JSON data appears to be from a crypto scan"""
    # Check for CBOM format
    if 'bomFormat' in json_data and json_data.get('bomFormat') == 'CycloneDX':
        return True
    
    # Check for scan results format
    if 'cbom' in json_data:
        return True
    
    # Check for crypto-related content
    if 'components' in json_data or 'vulnerabilities' in json_data:
        return True
    
    # Check for quantum-related content
    if any(key in json_data for key in ['quantum_assessment', 'quantumReadiness', 'migration_plan']):
        return True
    
    return False


def generate_html_reports_auto(json_file_path: Path) -> bool:
    """Generate HTML reports from a JSON file"""
    try:
        # Import the HTML generator functions
        sys.path.insert(0, str(json_file_path.parent))
        from create_html_reports import generate_html_from_json, create_results_folder_structure
        
        # Load and validate JSON
        with open(json_file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        if not is_valid_scan_json(json_data):
            print(f"⚠️  Warning: {json_file_path.name} doesn't appear to be a crypto scan result")
            return False
        
        # Create HTML output directory
        base_name = json_file_path.stem
        html_output_dir = json_file_path.parent / f"html_reports_{base_name}"
        html_output_dir.mkdir(exist_ok=True)
        
        print(f"📄 Processing: {json_file_path.name}")
        print(f"📁 Output: {html_output_dir}")
        
        # Generate HTML reports
        generated_files = generate_html_from_json(json_data, html_output_dir)
        
        if generated_files:
            print(f"✅ Generated {len(generated_files)} HTML files for {json_file_path.name}")
            return True
        else:
            print(f"❌ Failed to generate HTML reports for {json_file_path.name}")
            return False
            
    except Exception as e:
        print(f"❌ Error processing {json_file_path.name}: {e}")
        return False


def main():
    """Main function"""
    print("🛡️  Auto HTML Report Generator for Quantum Crypto Scanner")
    print("=" * 60)
    
    if len(sys.argv) == 1:
        # Auto-process all JSON files in results directory
        print("🔍 Looking for JSON files in results/ directory...")
        
        json_files = find_json_files("results")
        
        if not json_files:
            print("❌ No JSON files found in results/ directory")
            print("💡 Tip: Run the quantum crypto scanner first, or specify a JSON file:")
            print("   python auto_generate_html.py <json_file>")
            return 1
        
        print(f"📄 Found {len(json_files)} JSON files:")
        for json_file in json_files:
            print(f"  • {json_file.name}")
        
        print("\n🔄 Processing files...")
        
        success_count = 0
        for json_file in json_files:
            if generate_html_reports_auto(json_file):
                success_count += 1
            print()  # Add spacing between files
        
        print(f"🎉 Successfully processed {success_count}/{len(json_files)} files")
        
        if success_count > 0:
            print(f"\n🌐 HTML reports generated in results/html_reports_* directories")
            print(f"🌐 Open index.html files in your browser to view the reports")
        
        return 0 if success_count > 0 else 1
    
    elif len(sys.argv) == 2:
        # Process specific file
        json_file_path = Path(sys.argv[1])
        
        if not json_file_path.exists():
            print(f"❌ Error: File not found: {json_file_path}")
            return 1
        
        print(f"🔄 Processing specific file: {json_file_path}")
        
        success = generate_html_reports_auto(json_file_path)
        
        if success:
            html_dir = json_file_path.parent / f"html_reports_{json_file_path.stem}"
            print(f"\n🎉 HTML reports generated successfully!")
            print(f"🌐 Main dashboard: {html_dir}/index.html")
            print(f"🌐 URL: file://{html_dir.absolute()}/index.html")
        
        return 0 if success else 1
    
    else:
        print(f"""
Usage:
    python {sys.argv[0]}                    # Auto-process all JSON files in results/
    python {sys.argv[0]} <json_file>        # Process specific JSON file

Examples:
    python {sys.argv[0]}
    python {sys.argv[0]} results/cbom_report.json
    python {sys.argv[0]} test_samples__cbom.json
        """)
        return 1


if __name__ == "__main__":
    sys.exit(main())
