# HTML Report Generation for Quantum Crypto Scanner

This directory contains comprehensive HTML report generation capabilities for the Quantum Crypto Scanner. The system automatically creates beautiful, interactive HTML reports from JSON scan results.

## 🚀 Quick Start

```bash
# Generate HTML reports from existing scan data
python generate_html.py test_samples__cbom.json

# Auto-process all JSON files in results/
python auto_generate_html.py

# View the generated reports in your browser
open results/html_reports/index.html
```

## 📋 Available Scripts

### 1. `generate_html.py` (Recommended for most users)
Simple, one-command HTML report generation.
```bash
python generate_html.py <json_file>
```

### 2. `create_html_reports.py` (Full-featured)
Comprehensive HTML generator with advanced options.
```bash
python create_html_reports.py <json_file> [--output-dir <directory>]
```

### 3. `auto_generate_html.py` (Batch processing)
Automatically processes all JSON files in the results directory.
```bash
python auto_generate_html.py                # Process all JSON files
python auto_generate_html.py <json_file>    # Process specific file
```

### 4. `html_report_summary.py` (Documentation)
Shows usage examples and current status.
```bash
python html_report_summary.py
```

## 📄 Generated HTML Reports

Each generation creates **6 comprehensive HTML pages**:

| Page | Description |
|------|-------------|
| 🏠 **index.html** | Main dashboard with overview metrics |
| 🔐 **crypto_assets.html** | Detailed crypto component analysis |
| ⚠️ **vulnerabilities.html** | Security vulnerabilities and quantum threats |
| 🚀 **migration_plan.html** | Post-quantum migration roadmap |
| 📊 **summary.html** | Statistical charts and visualizations |
| 📋 **cbom.html** | Complete CBOM in CycloneDX format |

Plus `styles.css` for modern, responsive styling.

## 🎨 Features

- ✅ **Responsive design** - Works on mobile and desktop
- ✅ **Interactive charts** - Using Chart.js for visualizations
- ✅ **Modern styling** - Professional gradient themes
- ✅ **Navigation** - Easy movement between report sections
- ✅ **Downloadable CBOM** - Export JSON data
- ✅ **Copy to clipboard** - Quick data sharing
- ✅ **Quantum highlighting** - Visual vulnerability indicators
- ✅ **NIST compliance** - Post-quantum cryptography recommendations
- ✅ **Print-friendly** - Optimized for PDF generation
- ✅ **Offline ready** - No internet connection required

## 📁 Output Structure

```
results/
├── html_reports/                 # Default output directory
│   ├── index.html               # Main dashboard
│   ├── crypto_assets.html       # Asset analysis
│   ├── vulnerabilities.html     # Vulnerability report  
│   ├── migration_plan.html      # Migration guidance
│   ├── summary.html             # Statistical overview
│   ├── cbom.html                # CBOM viewer
│   └── styles.css               # CSS styling
│
├── html_reports_<name>/         # Named outputs (for batch processing)
│   └── [same structure as above]
│
└── *.json                       # Source JSON files
```

## 🔧 Integration with Main Scanner

The HTML report generation can be integrated into the main scanning workflow:

```python
from quantum_crypto_scanner.html_reporter import HTMLReportGenerator

# After running a scan
generator = HTMLReportGenerator()
reports = generator.generate_html_reports(scan_results, "output_directory")
```

## 📊 Supported JSON Formats

The HTML generator supports multiple JSON formats:

1. **Full scan results** - Complete output from quantum_crypto_scanner
2. **CBOM files** - CycloneDX format cryptographic bill of materials
3. **Legacy scan results** - Previous versions of scan output

## 🌐 Viewing Reports

After generation, open the main dashboard in any web browser:

```bash
# macOS
open results/html_reports/index.html

# Linux
xdg-open results/html_reports/index.html

# Windows
start results/html_reports/index.html

# Or manually navigate to:
file:///path/to/your/project/results/html_reports/index.html
```

## 🎯 Usage Examples

### Basic Usage
```bash
# Generate from test data
python generate_html.py test_samples__cbom.json

# Generate from scan results
python generate_html.py results/cbom_report.json
```

### Advanced Usage
```bash
# Custom output directory
python create_html_reports.py scan.json --output-dir my_reports

# Batch process all results
python auto_generate_html.py

# Verbose output
python create_html_reports.py scan.json --verbose
```

### Programmatic Usage
```python
import json
from quantum_crypto_scanner.html_reporter import HTMLReportGenerator

# Load scan data
with open('results/cbom_report.json', 'r') as f:
    data = json.load(f)

# Generate reports
generator = HTMLReportGenerator()
reports = generator.generate_html_reports(data, 'html_output')

print(f"Generated {len(reports)} HTML files")
```

## 🐛 Troubleshooting

### Common Issues

1. **JSON file not found**
   ```bash
   # Ensure the file path is correct
   ls -la results/*.json
   ```

2. **Permission denied**
   ```bash
   # Check directory permissions
   chmod 755 results/
   ```

3. **Invalid JSON format**
   ```bash
   # Validate JSON syntax
   python -m json.tool results/scan.json
   ```

4. **Missing modules**
   ```bash
   # Ensure all dependencies are available
   python -c "import json, os, pathlib"
   ```

### Getting Help

Run the summary script for current status and examples:
```bash
python html_report_summary.py
```

## 📝 Requirements

- Python 3.7+
- Standard library modules (json, os, pathlib, datetime)
- Web browser for viewing reports
- No external dependencies required

## 🔄 Workflow Integration

The HTML report generation integrates seamlessly with the Quantum Crypto Scanner workflow:

1. **Scan** → Run quantum crypto scanner on your codebase
2. **Generate** → Create HTML reports from JSON results  
3. **Review** → Analyze results in browser-based dashboard
4. **Share** → Distribute comprehensive HTML reports
5. **Act** → Follow migration plan recommendations

## 🎉 Success!

Once generated, you'll have a complete set of professional HTML reports ready for:
- Security team reviews
- Management presentations  
- Compliance documentation
- Migration planning
- Developer guidance

Happy scanning! 🛡️
