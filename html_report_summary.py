#!/usr/bin/env python3
"""
HTML Report Generation Summary
Overview of all HTML report generation capabilities for Quantum Crypto Scanner

This script demonstrates the different ways to generate HTML reports from JSON scan results.
"""

import os
import sys
from pathlib import Path


def show_usage_examples():
    """Show usage examples for HTML report generation"""
    print("""
🛡️  Quantum Crypto Scanner - HTML Report Generation
====================================================

The Quantum Crypto Scanner provides multiple ways to generate comprehensive HTML reports
from JSON scan results. Here are all the available methods:

📋 AVAILABLE SCRIPTS:
═══════════════════════

1. 🎯 create_html_reports.py (Full-featured)
   ├── Comprehensive HTML report generator with all features
   ├── Supports both CBOM and full scan result JSON formats
   ├── Generates 6 HTML pages + CSS styling
   └── Usage: python create_html_reports.py <json_file> [--output-dir <dir>]

2. 🚀 generate_html.py (Simple)
   ├── Quick and easy HTML report generation
   ├── Automatically creates results folder structure
   ├── Single command execution
   └── Usage: python generate_html.py <json_file>

3. 🤖 auto_generate_html.py (Automatic)
   ├── Automatically processes all JSON files in results/ folder
   ├── Can process specific files or batch process
   ├── Smart detection of crypto scan JSON files
   └── Usage: python auto_generate_html.py [json_file]

4. 📊 quantum_crypto_scanner/html_reporter.py (Module)
   ├── Python module for integration with other scripts
   ├── Can be imported and used programmatically
   └── Usage: from quantum_crypto_scanner.html_reporter import HTMLReportGenerator

📄 GENERATED HTML REPORTS:
════════════════════════════

Each generation creates 6 comprehensive HTML pages:

├── 🏠 index.html (Main Dashboard)
│   ├── Overview metrics and statistics
│   ├── Quick action buttons
│   └── Navigation to all other reports
│
├── 🔐 crypto_assets.html (Cryptographic Assets)
│   ├── Detailed table of all crypto components
│   ├── Vulnerability status for each asset
│   └── Searchable and sortable data
│
├── ⚠️  vulnerabilities.html (Security Vulnerabilities)
│   ├── Complete vulnerability assessment
│   ├── CVSS scores and severity ratings
│   └── Detailed remediation recommendations
│
├── 🚀 migration_plan.html (Post-Quantum Migration Plan)
│   ├── NIST post-quantum cryptography recommendations
│   ├── Prioritized migration tasks
│   └── Timeline and effort estimates
│
├── 📊 summary.html (Statistical Overview)
│   ├── Interactive charts and visualizations
│   ├── Crypto type distribution
│   └── Quantum readiness scoring
│
└── 📋 cbom.html (Cryptographic Bill of Materials)
    ├── Complete CBOM in CycloneDX format
    ├── Downloadable JSON export
    └── Copy-to-clipboard functionality

🎨 FEATURES:
═══════════

✅ Responsive design (mobile/desktop compatible)
✅ Interactive charts and visualizations
✅ Modern CSS styling with gradient themes
✅ Downloadable CBOM in JSON format
✅ Copy-to-clipboard functionality
✅ Navigation between all report sections
✅ Quantum vulnerability highlighting
✅ NIST PQC compliance recommendations
✅ Statistical analysis and metrics
✅ Print-friendly layouts

🚀 QUICK START EXAMPLES:
═══════════════════════

# Generate from existing test data
python generate_html.py test_samples__cbom.json

# Generate from scan results
python create_html_reports.py results/cbom_report.json

# Auto-process all results
python auto_generate_html.py

# Custom output directory
python create_html_reports.py scan.json --output-dir my_reports

📁 OUTPUT STRUCTURE:
══════════════════

results/
├── html_reports/           # Default HTML output
│   ├── index.html         # Main dashboard
│   ├── crypto_assets.html # Asset analysis
│   ├── vulnerabilities.html # Vulnerability report
│   ├── migration_plan.html # Migration guidance
│   ├── summary.html       # Statistical charts
│   ├── cbom.html          # CBOM viewer
│   └── styles.css         # Styling
│
└── html_reports_<name>/   # Named outputs (auto-generator)
    └── [same structure]

🌐 VIEWING REPORTS:
═════════════════

After generation, open any of these files in your web browser:
• file:///path/to/results/html_reports/index.html

The reports are completely self-contained and work offline.
No server or internet connection required.

🔧 INTEGRATION:
═════════════

To integrate HTML generation into your workflow:

```python
from quantum_crypto_scanner.html_reporter import HTMLReportGenerator

generator = HTMLReportGenerator()
reports = generator.generate_html_reports(json_data, "output_dir")
```

📞 SUPPORT:
═════════

If you encounter any issues:
1. Ensure JSON files are valid crypto scan results
2. Check file permissions for output directories
3. Verify Python version compatibility (3.7+)
4. Review error messages for specific guidance

Happy scanning! 🛡️
    """)


def check_file_status():
    """Check the status of HTML generator files"""
    print("\n📁 CURRENT FILE STATUS:")
    print("=" * 30)
    
    files_to_check = [
        "create_html_reports.py",
        "generate_html.py", 
        "auto_generate_html.py",
        "quantum_crypto_scanner/html_reporter.py",
        "test_samples__cbom.json"
    ]
    
    for file_path in files_to_check:
        path = Path(file_path)
        if path.exists():
            size = path.stat().st_size
            print(f"✅ {file_path:<35} ({size:,} bytes)")
        else:
            print(f"❌ {file_path:<35} (Not found)")
    
    # Check results directory
    results_dir = Path("results")
    if results_dir.exists():
        json_files = list(results_dir.glob("*.json"))
        html_dirs = list(results_dir.glob("html_reports*"))
        
        print(f"\n📊 RESULTS DIRECTORY:")
        print(f"   JSON files: {len(json_files)}")
        print(f"   HTML report directories: {len(html_dirs)}")
        
        if html_dirs:
            print(f"\n🌐 AVAILABLE HTML REPORTS:")
            for html_dir in html_dirs:
                index_file = html_dir / "index.html"
                if index_file.exists():
                    print(f"   📄 {html_dir.name}/index.html")
    else:
        print(f"\n📊 RESULTS DIRECTORY: Not found")


def main():
    """Main function"""
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        show_usage_examples()
    else:
        show_usage_examples()
        check_file_status()
        
        print(f"\n🎯 RECOMMENDED NEXT STEPS:")
        print(f"=" * 30)
        print(f"1. Test with sample data:    python generate_html.py test_samples__cbom.json")
        print(f"2. Process all results:      python auto_generate_html.py")
        print(f"3. View generated reports:   Open results/html_reports/index.html in browser")
        print(f"4. Run a new scan:          python -m quantum_crypto_scanner.main <target>")


if __name__ == "__main__":
    main()
