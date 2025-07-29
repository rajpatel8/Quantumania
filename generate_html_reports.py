#!/usr/bin/env python3
"""
Dynamic HTML Report Generator for Quantum Crypto Scanner
Standalone script to generate HTML reports from JSON scan results

Usage:
    python generate_html_reports.py <json_file> [--output-dir <directory>]
    python generate_html_reports.py test_samples__cbom.json --output-dir results/html_reports
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add the quantum_crypto_scanner module to the path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from quantum_crypto_scanner.html_reporter import HTMLReportGenerator, create_html_reports_from_json
except ImportError:
    try:
        # If running as standalone script, try local import
        html_reporter_path = os.path.join(current_dir, 'quantum_crypto_scanner', 'html_reporter.py')
        if os.path.exists(html_reporter_path):
            sys.path.insert(0, os.path.join(current_dir, 'quantum_crypto_scanner'))
            from html_reporter import HTMLReportGenerator, create_html_reports_from_json
        else:
            # Create minimal implementation if module not found
            print("⚠️  Warning: html_reporter module not found. Using minimal implementation.")
            from datetime import datetime
            import uuid
            
            class HTMLReportGenerator:
                def __init__(self):
                    pass
                    
                def generate_html_reports(self, json_data, output_dir):
                    print("❌ Error: Full HTML reporter module not available.")
                    print("Please ensure quantum_crypto_scanner/html_reporter.py exists.")
                    return {}
            
            def create_html_reports_from_json(json_file, output_dir):
                return {}
    except ImportError as e:
        print(f"❌ Error importing HTML reporter: {e}")
        sys.exit(1)


def main():
    """Main function for the standalone HTML report generator"""
    parser = argparse.ArgumentParser(
        description='Generate dynamic HTML reports from Quantum Crypto Scanner JSON results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_html_reports.py scan_results.json
  python generate_html_reports.py test_samples__cbom.json --output-dir reports
  python generate_html_reports.py results/cbom_report.json --output-dir html_output
        """
    )
    
    parser.add_argument('json_file', 
                       help='Path to the JSON file containing scan results or CBOM data')
    parser.add_argument('--output-dir', '-o', 
                       default='results/html_reports',
                       help='Output directory for HTML reports (default: results/html_reports)')
    parser.add_argument('--verbose', '-v', 
                       action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate input file
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"❌ Error: JSON file not found: {json_path}")
        return 1
    
    if not json_path.suffix.lower() == '.json':
        print(f"⚠️  Warning: File doesn't have .json extension: {json_path}")
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.verbose:
        print(f"📁 Input file: {json_path}")
        print(f"📁 Output directory: {output_dir}")
        print(f"🔄 Generating HTML reports...")
    
    try:
        # Load and validate JSON
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        if args.verbose:
            print(f"✅ Successfully loaded JSON data")
            print(f"📊 Data keys: {list(json_data.keys()) if isinstance(json_data, dict) else 'List data'}")
        
        # Generate HTML reports
        generator = HTMLReportGenerator()
        reports = generator.generate_html_reports(json_data, str(output_dir))
        
        if reports:
            print(f"🎉 Successfully generated {len(reports)} HTML reports in {output_dir}/")
            print("\n📄 Generated files:")
            
            for report_name, file_path in reports.items():
                if args.verbose:
                    file_size = os.path.getsize(file_path)
                    print(f"  {report_name:<20} → {file_path} ({file_size:,} bytes)")
                else:
                    print(f"  📄 {report_name}")
            
            # Show main dashboard link
            main_dashboard = output_dir / "index.html"
            print(f"\n🌐 Main Dashboard: {main_dashboard}")
            print(f"🌐 Open in browser: file://{main_dashboard.absolute()}")
            
            # Quick access links
            print(f"\n🔗 Quick Access:")
            print(f"  📊 Summary:        {output_dir}/summary.html")
            print(f"  🔐 Crypto Assets:  {output_dir}/crypto_assets.html")
            print(f"  ⚠️  Vulnerabilities: {output_dir}/vulnerabilities.html")
            print(f"  🚀 Migration Plan: {output_dir}/migration_plan.html")
            print(f"  📋 CBOM:          {output_dir}/cbom.html")
            
        else:
            print("❌ Failed to generate HTML reports")
            return 1
            
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON format in {json_path}")
        print(f"   Details: {e}")
        return 1
    except Exception as e:
        print(f"❌ Error generating HTML reports: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


def demo_usage():
    """Demonstrate usage with example commands"""
    print("""
🛡️  HTML Report Generator for Quantum Crypto Scanner

This script generates comprehensive HTML reports from JSON scan results.

📋 Usage Examples:

1. Basic usage with current directory JSON file:
   python generate_html_reports.py test_samples__cbom.json

2. Specify custom output directory:
   python generate_html_reports.py scan_results.json --output-dir my_reports

3. Generate from existing CBOM file:
   python generate_html_reports.py results/cbom_report.json -o html_output

4. Verbose output for debugging:
   python generate_html_reports.py data.json --verbose

📁 Expected JSON structure:
   The script can handle:
   - Full scan results with 'cbom' key
   - Direct CBOM JSON files
   - CycloneDX format cryptographic BOMs

🌐 Output:
   - index.html (Main Dashboard)
   - crypto_assets.html (Cryptographic Components)
   - vulnerabilities.html (Security Vulnerabilities)
   - migration_plan.html (Post-Quantum Migration Plan)
   - summary.html (Statistical Overview with Charts)
   - cbom.html (Raw CBOM Data)
   - styles.css (Styling)

🎯 Features:
   ✅ Interactive dashboard with metrics
   ✅ Detailed crypto asset analysis
   ✅ Vulnerability tracking and assessment
   ✅ Migration planning with NIST recommendations
   ✅ Statistical charts and visualizations
   ✅ Responsive design for mobile/desktop
   ✅ Downloadable CBOM in JSON format
    """)


if __name__ == "__main__":
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ['--help', '-h', 'help']):
        demo_usage()
        sys.exit(0)
    
    sys.exit(main())
