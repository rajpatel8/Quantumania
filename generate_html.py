#!/usr/bin/env python3
"""
Simple HTML Report Generator
Quick script to generate HTML reports from any JSON file

Usage:
    python generate_html.py <json_file>
    python generate_html.py test_samples__cbom.json
"""

import sys
import os
from pathlib import Path

# Import the main HTML report generator
try:
    from create_html_reports import generate_html_from_json, create_results_folder_structure
except ImportError:
    print("❌ Error: create_html_reports.py not found in the same directory")
    sys.exit(1)

import json


def quick_generate_html(json_file_path: str) -> bool:
    """
    Quick function to generate HTML reports from a JSON file
    
    Args:
        json_file_path: Path to the JSON file
        
    Returns:
        True if successful, False otherwise
    """
    json_path = Path(json_file_path)
    
    if not json_path.exists():
        print(f"❌ Error: JSON file not found: {json_path}")
        return False
    
    try:
        # Load JSON data
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        print(f"📄 Loaded JSON data from: {json_path}")
        
        # Create results folder in the same directory as the JSON file
        base_dir = json_path.parent / "results"
        html_output_dir = create_results_folder_structure(str(base_dir))
        
        print(f"📁 Output directory: {html_output_dir}")
        
        # Generate HTML reports
        print(f"🔄 Generating HTML reports...")
        generated_files = generate_html_from_json(json_data, html_output_dir)
        
        if generated_files:
            print(f"✅ Successfully generated {len(generated_files)} HTML files!")
            
            # Show main dashboard link
            main_dashboard = html_output_dir / "index.html"
            print(f"\n🌐 Main Dashboard: {main_dashboard}")
            print(f"🌐 URL: file://{main_dashboard.absolute()}")
            
            # Quick access URLs
            print(f"\n🔗 Quick Access:")
            for page in ['index.html', 'crypto_assets.html', 'vulnerabilities.html', 'migration_plan.html', 'summary.html']:
                print(f"  📄 {page.replace('.html', '').replace('_', ' ').title()}: {html_output_dir}/{page}")
            
            return True
        else:
            print("❌ Failed to generate HTML reports")
            return False
            
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON format in {json_path}")
        print(f"   Details: {e}")
        return False
    except Exception as e:
        print(f"❌ Error generating HTML reports: {e}")
        return False


def main():
    """Main function"""
    if len(sys.argv) != 2:
        print(f"""
🛡️  Simple HTML Report Generator

Usage:
    python {sys.argv[0]} <json_file>

Examples:
    python {sys.argv[0]} test_samples__cbom.json
    python {sys.argv[0]} results/cbom_report.json
    python {sys.argv[0]} scan_results.json

This script will:
✅ Read the JSON file
✅ Create a results/html_reports folder
✅ Generate 6 HTML report pages + CSS
✅ Open-ready browser links
        """)
        return 1
    
    json_file = sys.argv[1]
    
    print(f"🚀 Starting HTML report generation for: {json_file}")
    
    success = quick_generate_html(json_file)
    
    if success:
        print(f"\n🎉 HTML reports generated successfully!")
        return 0
    else:
        print(f"\n❌ Failed to generate HTML reports")
        return 1


if __name__ == "__main__":
    sys.exit(main())
