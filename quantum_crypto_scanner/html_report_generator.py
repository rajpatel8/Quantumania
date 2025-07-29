# quantum_crypto_scanner/html_report_generator.py
"""
Step 3: HTML Report Generator with Interactive Dashboard
Creates comprehensive HTML results with charts, tables, and interactive elements
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import base64
import shutil

class HTMLReportGenerator:
    """
    Generate comprehensive HTML reports with interactive dashboard
    Step 3: Enhanced with PQC analysis and semantic insights
    """
    
    def __init__(self):
        self.report_version = "3.0"
        self.template_dir = Path(__file__).parent / "templates"
        self.assets_dir = Path(__file__).parent / "assets"
        
    def generate_html_report(self, scan_results: Dict[str, Any], output_dir: str = "quantum_scan_results") -> str:
        """
        Generate comprehensive HTML report with dashboard
        
        Args:
            scan_results: Complete scan results from Step 2
            output_dir: Directory to create for HTML results
            
        Returns:
            Path to the main HTML file
        """
        print(f"📊 Generating HTML dashboard report...")
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        # Create directory structure
        self._create_directory_structure(output_path)
        
        # Generate main dashboard
        main_html = self._generate_main_dashboard(scan_results, output_path)
        
        # Generate detailed pages
        self._generate_findings_page(scan_results, output_path)
        self._generate_cbom_page(scan_results, output_path)
        self._generate_migration_page(scan_results, output_path)
        self._generate_risk_analysis_page(scan_results, output_path)
        
        # Copy assets and generate data files
        self._copy_assets(output_path)
        self._generate_data_files(scan_results, output_path)
        
        print(f"✅ HTML report generated: {output_path / 'index.html'}")
        return str(output_path / 'index.html')
    
    def _create_directory_structure(self, output_path: Path):
        """Create the directory structure for HTML report"""
        directories = [
            'css',
            'js', 
            'data',
            'pages',
            'assets'
        ]
        
        for dir_name in directories:
            (output_path / dir_name).mkdir(exist_ok=True)
    
    def _generate_main_dashboard(self, scan_results: Dict[str, Any], output_path: Path) -> str:
        """Generate the main dashboard HTML"""
        
        # Extract key metrics
        summary = scan_results.get('summary', {})
        quantum_assessment = scan_results.get('quantum_assessment', {})
        cbom = scan_results.get('cbom', {})
        scan_metadata = scan_results.get('scan_metadata', {})
        
        # Calculate dashboard metrics
        total_files = summary.get('total_files_scanned', 0)
        total_findings = summary.get('total_crypto_findings', 0)
        quantum_vulnerable = summary.get('quantum_vulnerable_count', 0)
        readiness_score = summary.get('quantum_readiness_score', 0)
        
        risk_breakdown = summary.get('risk_breakdown', {})
        
        html_content = self._generate_dashboard_html(
            scan_metadata=scan_metadata,
            total_files=total_files,
            total_findings=total_findings,
            quantum_vulnerable=quantum_vulnerable,
            readiness_score=readiness_score,
            risk_breakdown=risk_breakdown,
            cbom=cbom,
            quantum_assessment=quantum_assessment
        )
        
        # Write main HTML file
        main_file = output_path / 'index.html'
        main_file.write_text(html_content, encoding='utf-8')
        
        return str(main_file)
    
    def _generate_dashboard_html(self, **kwargs) -> str:
        """Generate the main dashboard HTML content"""
        
        scan_metadata = kwargs.get('scan_metadata', {})
        total_files = kwargs.get('total_files', 0)
        total_findings = kwargs.get('total_findings', 0)
        quantum_vulnerable = kwargs.get('quantum_vulnerable', 0)
        readiness_score = kwargs.get('readiness_score', 0)
        risk_breakdown = kwargs.get('risk_breakdown', {})
        cbom = kwargs.get('cbom', {})
        
        # Determine readiness status and color
        if readiness_score >= 80:
            readiness_status = "Quantum Ready"
            readiness_color = "#22c55e"
        elif readiness_score >= 60:
            readiness_status = "Mostly Ready"
            readiness_color = "#f59e0b"
        elif readiness_score >= 40:
            readiness_status = "Needs Attention"
            readiness_color = "#f97316"
        else:
            readiness_status = "High Risk"
            readiness_color = "#ef4444"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Crypto Scanner Results - Enhanced Dashboard</title>
    <link rel="stylesheet" href="css/dashboard.css">
    <link rel="stylesheet" href="css/charts.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <div class="dashboard-container">
        <!-- Header -->
        <header class="dashboard-header">
            <div class="header-content">
                <div class="logo-section">
                    <i class="fas fa-shield-alt quantum-icon"></i>
                    <h1>Quantum Crypto Scanner</h1>
                    <span class="version-badge">v{self.report_version}</span>
                </div>
                <div class="scan-info">
                    <div class="scan-meta">
                        <span class="scan-target">📁 {scan_metadata.get('target_path', 'Unknown')}</span>
                        <span class="scan-time">🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                    </div>
                </div>
            </div>
        </header>

        <!-- Navigation -->
        <nav class="dashboard-nav">
            <div class="nav-content">
                <ul class="nav-links">
                    <li><a href="#overview" class="nav-link active">📊 Overview</a></li>
                    <li><a href="pages/findings.html" class="nav-link">🔍 Findings</a></li>
                    <li><a href="pages/cbom.html" class="nav-link">📋 CBOM</a></li>
                    <li><a href="pages/migration.html" class="nav-link">🔄 Migration Plan</a></li>
                    <li><a href="pages/risk-analysis.html" class="nav-link">⚠️ Risk Analysis</a></li>
                </ul>
                <div class="nav-actions">
                    <button class="btn-export" onclick="exportReport()">
                        <i class="fas fa-download"></i> Export Report
                    </button>
                </div>
            </div>
        </nav>

        <!-- Main Content -->
        <main class="dashboard-main">
            <!-- Key Metrics Section -->
            <section class="metrics-section">
                <div class="metrics-grid">
                    <div class="metric-card files-scanned">
                        <div class="metric-icon">📁</div>
                        <div class="metric-content">
                            <div class="metric-value">{total_files}</div>
                            <div class="metric-label">Files Scanned</div>
                        </div>
                    </div>
                    
                    <div class="metric-card crypto-findings">
                        <div class="metric-icon">🔐</div>
                        <div class="metric-content">
                            <div class="metric-value">{total_findings}</div>
                            <div class="metric-label">Crypto Findings</div>
                        </div>
                    </div>
                    
                    <div class="metric-card quantum-vulnerable">
                        <div class="metric-icon">⚡</div>
                        <div class="metric-content">
                            <div class="metric-value quantum-risk">{quantum_vulnerable}</div>
                            <div class="metric-label">Quantum Vulnerable</div>
                        </div>
                    </div>
                    
                    <div class="metric-card readiness-score">
                        <div class="metric-icon">🛡️</div>
                        <div class="metric-content">
                            <div class="metric-value" style="color: {readiness_color}">{readiness_score:.1f}%</div>
                            <div class="metric-label">Quantum Readiness</div>
                            <div class="metric-status" style="color: {readiness_color}">{readiness_status}</div>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Charts Section -->
            <section class="charts-section">
                <div class="charts-grid">
                    <!-- Risk Distribution Chart -->
                    <div class="chart-card">
                        <div class="chart-header">
                            <h3>Risk Distribution</h3>
                            <div class="chart-actions">
                                <button class="btn-chart-fullscreen" onclick="toggleFullscreen('riskChart')">
                                    <i class="fas fa-expand"></i>
                                </button>
                            </div>
                        </div>
                        <div class="chart-container">
                            <canvas id="riskChart" width="400" height="200"></canvas>
                        </div>
                    </div>
                    
                    <!-- Quantum Readiness Gauge -->
                    <div class="chart-card">
                        <div class="chart-header">
                            <h3>Quantum Readiness Score</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="readinessGauge" width="400" height="200"></canvas>
                        </div>
                    </div>
                    
                    <!-- Crypto Types Distribution -->
                    <div class="chart-card">
                        <div class="chart-header">
                            <h3>Cryptographic Algorithms</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="cryptoTypesChart" width="400" height="200"></canvas>
                        </div>
                    </div>
                    
                    <!-- Timeline Chart -->
                    <div class="chart-card">
                        <div class="chart-header">
                            <h3>Quantum Threat Timeline</h3>
                        </div>
                        <div class="chart-container">
                            <canvas id="timelineChart" width="400" height="200"></canvas>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Quick Insights Section -->
            <section class="insights-section">
                <div class="insights-header">
                    <h2>🔍 Quick Insights</h2>
                </div>
                <div class="insights-grid">
                    <div class="insight-card critical">
                        <div class="insight-icon">🚨</div>
                        <div class="insight-content">
                            <h4>Critical Vulnerabilities</h4>
                            <p>{risk_breakdown.get('CRITICAL', 0)} critical quantum-vulnerable algorithms found</p>
                            <a href="pages/findings.html#critical" class="insight-link">View Details →</a>
                        </div>
                    </div>
                    
                    <div class="insight-card migration">
                        <div class="insight-icon">🔄</div>
                        <div class="insight-content">
                            <h4>Migration Priority</h4>
                            <p>Start with RSA and ECC replacements by 2030</p>
                            <a href="pages/migration.html" class="insight-link">View Plan →</a>
                        </div>
                    </div>
                    
                    <div class="insight-card cbom">
                        <div class="insight-icon">📋</div>
                        <div class="insight-content">
                            <h4>CBOM Generated</h4>
                            <p>{len(cbom.get('components', []))} crypto components catalogued</p>
                            <a href="pages/cbom.html" class="insight-link">View CBOM →</a>
                        </div>
                    </div>
                </div>
            </section>

            <!-- Action Items Section -->
            <section class="actions-section">
                <div class="actions-header">
                    <h2>📝 Recommended Actions</h2>
                </div>
                <div class="actions-list">
                    <div class="action-item priority-high">
                        <div class="action-priority">HIGH</div>
                        <div class="action-content">
                            <h4>Replace Quantum-Vulnerable Algorithms</h4>
                            <p>Migrate {quantum_vulnerable} quantum-vulnerable crypto instances to NIST PQC standards</p>
                            <div class="action-timeline">Timeline: Before 2030</div>
                        </div>
                    </div>
                    
                    <div class="action-item priority-medium">
                        <div class="action-priority">MEDIUM</div>
                        <div class="action-content">
                            <h4>Implement Hybrid Approach</h4>
                            <p>Consider hybrid classical+PQC solutions during transition period</p>
                            <div class="action-timeline">Timeline: 2025-2030</div>
                        </div>
                    </div>
                    
                    <div class="action-item priority-low">
                        <div class="action-priority">LOW</div>
                        <div class="action-content">
                            <h4>Monitor Developments</h4>
                            <p>Stay updated on NIST PQC standards and quantum computing progress</p>
                            <div class="action-timeline">Timeline: Ongoing</div>
                        </div>
                    </div>
                </div>
            </section>
        </main>

        <!-- Footer -->
        <footer class="dashboard-footer">
            <div class="footer-content">
                <div class="footer-info">
                    <span>Generated by Quantum Crypto Scanner v{self.report_version}</span>
                    <span>Analysis Method: {scan_metadata.get('analysis_method', 'Enhanced').replace('_', ' ').title()}</span>
                </div>
                <div class="footer-links">
                    <a href="data/scan_results.json" target="_blank">📄 Raw Data</a>
                    <a href="data/cbom.json" target="_blank">📋 CBOM JSON</a>
                    <a href="#" onclick="showHelp()">❓ Help</a>
                </div>
            </div>
        </footer>
    </div>

    <!-- Scripts -->
    <script src="js/dashboard.js"></script>
    <script src="js/charts.js"></script>
    <script>
        // Initialize dashboard with data
        const scanData = {{
            riskBreakdown: {json.dumps(risk_breakdown)},
            readinessScore: {readiness_score},
            totalFindings: {total_findings},
            quantumVulnerable: {quantum_vulnerable}
        }};
        
        // Initialize charts when page loads
        document.addEventListener('DOMContentLoaded', function() {{
            initializeCharts(scanData);
        }});
    </script>
</body>
</html>"""
    
    def _generate_findings_page(self, scan_results: Dict[str, Any], output_path: Path):
        """Generate detailed findings page"""
        findings = scan_results.get('sonar_cryptography_results', {}).get('crypto_findings', [])
        quantum_findings = scan_results.get('quantum_assessment', {}).get('quantum_vulnerable_findings', [])
        
        findings_html = self._create_findings_html(findings, quantum_findings)
        
        findings_file = output_path / 'pages' / 'findings.html'
        findings_file.write_text(findings_html, encoding='utf-8')
    
    def _generate_cbom_page(self, scan_results: Dict[str, Any], output_path: Path):
        """Generate CBOM visualization page"""
        cbom = scan_results.get('cbom', {})
        
        cbom_html = self._create_cbom_html(cbom)
        
        cbom_file = output_path / 'pages' / 'cbom.html'
        cbom_file.write_text(cbom_html, encoding='utf-8')
    
    def _generate_migration_page(self, scan_results: Dict[str, Any], output_path: Path):
        """Generate migration plan page"""
        migration_plan = scan_results.get('migration_plan', {})
        migration_recs = scan_results.get('cbom', {}).get('migrationRecommendations', [])
        
        migration_html = self._create_migration_html(migration_plan, migration_recs)
        
        migration_file = output_path / 'pages' / 'migration.html'
        migration_file.write_text(migration_html, encoding='utf-8')
    
    def _generate_risk_analysis_page(self, scan_results: Dict[str, Any], output_path: Path):
        """Generate risk analysis page"""
        quantum_assessment = scan_results.get('quantum_assessment', {})
        
        risk_html = self._create_risk_analysis_html(quantum_assessment)
        
        risk_file = output_path / 'pages' / 'risk-analysis.html'
        risk_file.write_text(risk_html, encoding='utf-8')
    
    def _copy_assets(self, output_path: Path):
        """Copy CSS, JS, and other assets"""
        # Generate CSS files
        self._generate_css_files(output_path)
        
        # Generate JavaScript files
        self._generate_js_files(output_path)
    
    def _generate_data_files(self, scan_results: Dict[str, Any], output_path: Path):
        """Generate JSON data files for the report"""
        data_dir = output_path / 'data'
        
        # Main scan results
        with open(data_dir / 'scan_results.json', 'w') as f:
            json.dump(scan_results, f, indent=2, default=str)
        
        # CBOM data
        if 'cbom' in scan_results:
            with open(data_dir / 'cbom.json', 'w') as f:
                json.dump(scan_results['cbom'], f, indent=2, default=str)
        
        # Findings data for interactive tables
        findings_data = {
            'crypto_findings': scan_results.get('sonar_cryptography_results', {}).get('crypto_findings', []),
            'quantum_vulnerable': scan_results.get('quantum_assessment', {}).get('quantum_vulnerable_findings', [])
        }
        
        with open(data_dir / 'findings.json', 'w') as f:
            json.dump(findings_data, f, indent=2, default=str)
    
    def _create_findings_html(self, findings: List[Dict], quantum_findings: List[Dict]) -> str:
        """Create the findings detail page HTML"""
        return """<!-- Findings page will be implemented with detailed tables and filters -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Crypto Findings - Quantum Scanner</title>
    <link rel="stylesheet" href="../css/dashboard.css">
    <link rel="stylesheet" href="../css/findings.css">
</head>
<body>
    <div class="page-container">
        <h1>🔍 Cryptographic Findings</h1>
        <div id="findings-content">
            <p>Detailed findings will be loaded here...</p>
        </div>
    </div>
    <script src="../js/findings.js"></script>
</body>
</html>"""
    
    def _create_cbom_html(self, cbom: Dict[str, Any]) -> str:
        """Create the CBOM visualization page HTML"""
        return """<!-- CBOM page will be implemented with component visualization -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CBOM - Quantum Scanner</title>
    <link rel="stylesheet" href="../css/dashboard.css">
    <link rel="stylesheet" href="../css/cbom.css">
</head>
<body>
    <div class="page-container">
        <h1>📋 Cryptography Bill of Materials</h1>
        <div id="cbom-content">
            <p>CBOM visualization will be loaded here...</p>
        </div>
    </div>
    <script src="../js/cbom.js"></script>
</body>
</html>"""
    
    def _create_migration_html(self, migration_plan: Dict[str, Any], migration_recs: List[Dict]) -> str:
        """Create the migration plan page HTML"""
        return """<!-- Migration page will be implemented with timeline and recommendations -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Migration Plan - Quantum Scanner</title>
    <link rel="stylesheet" href="../css/dashboard.css">
    <link rel="stylesheet" href="../css/migration.css">
</head>
<body>
    <div class="page-container">
        <h1>🔄 Post-Quantum Migration Plan</h1>
        <div id="migration-content">
            <p>Migration plan and timeline will be loaded here...</p>
        </div>
    </div>
    <script src="../js/migration.js"></script>
</body>
</html>"""
    
    def _create_risk_analysis_html(self, quantum_assessment: Dict[str, Any]) -> str:
        """Create the risk analysis page HTML"""
        return """<!-- Risk analysis page will be implemented with detailed risk metrics -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Risk Analysis - Quantum Scanner</title>
    <link rel="stylesheet" href="../css/dashboard.css">
    <link rel="stylesheet" href="../css/risk.css">
</head>
<body>
    <div class="page-container">
        <h1>⚠️ Quantum Risk Analysis</h1>
        <div id="risk-content">
            <p>Risk analysis and projections will be loaded here...</p>
        </div>
    </div>
    <script src="../js/risk.js"></script>
</body>
</html>"""
    
    def _generate_css_files(self, output_path: Path):
        """Generate CSS files for the HTML report"""
        css_dir = output_path / 'css'
        
        # Main dashboard CSS
        dashboard_css = """
/* Quantum Crypto Scanner - Dashboard CSS */
:root {
    --primary-color: #2563eb;
    --secondary-color: #7c3aed;
    --success-color: #22c55e;
    --warning-color: #f59e0b;
    --danger-color: #ef4444;
    --dark-bg: #1f2937;
    --light-bg: #f8fafc;
    --card-bg: #ffffff;
    --border-color: #e5e7eb;
    --text-primary: #111827;
    --text-secondary: #6b7280;
    --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, var(--light-bg) 0%, #e0e7ff 100%);
    color: var(--text-primary);
    line-height: 1.6;
}

.dashboard-container {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.dashboard-header {
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
    color: white;
    padding: 1.5rem 0;
    box-shadow: var(--shadow);
}

.header-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo-section {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.quantum-icon {
    font-size: 2rem;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.7; }
}

.dashboard-header h1 {
    font-size: 2rem;
    font-weight: 700;
}

.version-badge {
    background: rgba(255, 255, 255, 0.2);
    padding: 0.25rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.875rem;
    font-weight: 500;
}

.scan-info {
    text-align: right;
}

.scan-meta {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.875rem;
    opacity: 0.9;
}

/* Navigation */
.dashboard-nav {
    background: var(--card-bg);
    border-bottom: 1px solid var(--border-color);
    box-shadow: var(--shadow);
    position: sticky;
    top: 0;
    z-index: 100;
}

.nav-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-links {
    display: flex;
    list-style: none;
    gap: 2rem;
}

.nav-link {
    display: block;
    padding: 1rem 0;
    text-decoration: none;
    color: var(--text-secondary);
    font-weight: 500;
    border-bottom: 2px solid transparent;
    transition: all 0.3s ease;
}

.nav-link:hover,
.nav-link.active {
    color: var(--primary-color);
    border-bottom-color: var(--primary-color);
}

.btn-export {
    background: var(--primary-color);
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.3s ease;
}

.btn-export:hover {
    background: var(--secondary-color);
    transform: translateY(-1px);
}

/* Main Content */
.dashboard-main {
    flex: 1;
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
    width: 100%;
}

/* Metrics Section */
.metrics-section {
    margin-bottom: 3rem;
}

.metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
}

.metric-card {
    background: var(--card-bg);
    padding: 2rem;
    border-radius: 1rem;
    box-shadow: var(--shadow);
    display: flex;
    align-items: center;
    gap: 1.5rem;
    transition: all 0.3s ease;
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

.metric-icon {
    font-size: 3rem;
    opacity: 0.8;
}

.metric-value {
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1;
}

.metric-label {
    font-size: 0.875rem;
    color: var(--text-secondary);
    font-weight: 500;
}

.metric-status {
    font-size: 0.75rem;
    font-weight: 600;
    margin-top: 0.25rem;
}

.quantum-risk {
    color: var(--danger-color);
}

/* Charts Section */
.charts-section {
    margin-bottom: 3rem;
}

.charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 1.5rem;
}

.chart-card {
    background: var(--card-bg);
    border-radius: 1rem;
    box-shadow: var(--shadow);
    overflow: hidden;
}

.chart-header {
    padding: 1.5rem;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.chart-header h3 {
    font-size: 1.125rem;
    font-weight: 600;
}

.chart-container {
    padding: 1.5rem;
    height: 300px;
    position: relative;
}

/* Insights Section */
.insights-section {
    margin-bottom: 3rem;
}

.insights-header h2 {
    margin-bottom: 1.5rem;
    font-size: 1.5rem;
    font-weight: 600;
}

.insights-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
}

.insight-card {
    background: var(--card-bg);
    padding: 1.5rem;
    border-radius: 1rem;
    box-shadow: var(--shadow);
    display: flex;
    gap: 1rem;
    transition: all 0.3s ease;
}

.insight-card:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

.insight-icon {
    font-size: 2rem;
    width: 3rem;
    text-align: center;
}

.insight-content h4 {
    margin-bottom: 0.5rem;
    font-weight: 600;
}

.insight-content p {
    color: var(--text-secondary);
    margin-bottom: 1rem;
}

.insight-link {
    color: var(--primary-color);
    text-decoration: none;
    font-weight: 500;
    font-size: 0.875rem;
}

.insight-link:hover {
    text-decoration: underline;
}

/* Actions Section */
.actions-section {
    margin-bottom: 3rem;
}

.actions-header h2 {
    margin-bottom: 1.5rem;
    font-size: 1.5rem;
    font-weight: 600;
}

.actions-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.action-item {
    background: var(--card-bg);
    padding: 1.5rem;
    border-radius: 1rem;
    box-shadow: var(--shadow);
    display: flex;
    gap: 1rem;
    align-items: flex-start;
}

.action-priority {
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    font-size: 0.75rem;
    font-weight: 700;
    white-space: nowrap;
}

.priority-high .action-priority {
    background: var(--danger-color);
    color: white;
}

.priority-medium .action-priority {
    background: var(--warning-color);
    color: white;
}

.priority-low .action-priority {
    background: var(--success-color);
    color: white;
}

.action-content h4 {
    margin-bottom: 0.5rem;
    font-weight: 600;
}

.action-content p {
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
}

.action-timeline {
    font-size: 0.875rem;
    color: var(--text-secondary);
    font-style: italic;
}

/* Footer */
.dashboard-footer {
    background: var(--dark-bg);
    color: white;
    padding: 2rem 0;
    margin-top: auto;
}

.footer-content {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.footer-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.875rem;
    opacity: 0.8;
}

.footer-links {
    display: flex;
    gap: 1.5rem;
}

.footer-links a {
    color: white;
    text-decoration: none;
    font-size: 0.875rem;
    opacity: 0.8;
    transition: opacity 0.3s ease;
}

.footer-links a:hover {
    opacity: 1;
}

/* Responsive Design */
@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }
    
    .nav-content {
        flex-direction: column;
        gap: 1rem;
        padding: 1rem 2rem;
    }
    
    .nav-links {
        flex-wrap: wrap;
        justify-content: center;
    }
    
    .dashboard-main {
        padding: 1rem;
    }
    
    .charts-grid {
        grid-template-columns: 1fr;
    }
    
    .footer-content {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }
}
"""
        
        with open(css_dir / 'dashboard.css', 'w') as f:
            f.write(dashboard_css)
    
    def _generate_js_files(self, output_path: Path):
        """Generate JavaScript files for the HTML report"""
        js_dir = output_path / 'js'
        
        # Main dashboard JavaScript
        dashboard_js = """
// Quantum Crypto Scanner - Dashboard JavaScript

// Global variables
let charts = {};

// Initialize charts
function initializeCharts(data) {
    initRiskChart(data.riskBreakdown);
    initReadinessGauge(data.readinessScore);
    initCryptoTypesChart(data);
    initTimelineChart();
}

// Risk Distribution Chart
function initRiskChart(riskData) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    charts.riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    riskData.CRITICAL || 0,
                    riskData.HIGH || 0,
                    riskData.MEDIUM || 0,
                    riskData.LOW || 0
                ],
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#f59e0b',
                    '#22c55e'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                }
            }
        }
    });
}

// Quantum Readiness Gauge
function initReadinessGauge(score) {
    const ctx = document.getElementById('readinessGauge').getContext('2d');
    
    charts.readinessGauge = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [
                    getReadinessColor(score),
                    '#e5e7eb'
                ],
                borderWidth: 0,
                cutout: '75%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            }
        },
        plugins: [{
            beforeDraw: function(chart) {
                const ctx = chart.ctx;
                const centerX = (chart.chartArea.left + chart.chartArea.right) / 2;
                const centerY = (chart.chartArea.top + chart.chartArea.bottom) / 2;
                
                ctx.save();
                ctx.font = 'bold 24px Inter';
                ctx.fillStyle = getReadinessColor(score);
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(score.toFixed(1) + '%', centerX, centerY);
                ctx.restore();
            }
        }]
    });
}

// Crypto Types Distribution Chart
function initCryptoTypesChart(data) {
    const ctx = document.getElementById('cryptoTypesChart').getContext('2d');
    
    // Sample data - in real implementation, this would come from scan results
    charts.cryptoTypesChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['RSA', 'ECC', 'AES', 'Hash Functions', 'Other'],
            datasets: [{
                label: 'Count',
                data: [5, 3, 2, 4, 1],
                backgroundColor: [
                    '#ef4444',
                    '#f97316',
                    '#22c55e',
                    '#f59e0b',
                    '#6b7280'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Quantum Threat Timeline Chart
function initTimelineChart() {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    charts.timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['2025', '2030', '2035', '2040', '2045', '2050'],
            datasets: [{
                label: 'Quantum Threat Level',
                data: [10, 40, 70, 85, 95, 100],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4
            }, {
                label: 'PQC Adoption',
                data: [5, 25, 60, 80, 95, 100],
                borderColor: '#22c55e',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });
}

// Utility functions
function getReadinessColor(score) {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#f59e0b';
    if (score >= 40) return '#f97316';
    return '#ef4444';
}

function toggleFullscreen(chartId) {
    // Implement fullscreen toggle for charts
    console.log('Toggle fullscreen for:', chartId);
}

function exportReport() {
    // Implement report export functionality
    alert('Export functionality coming soon!');
}

function showHelp() {
    // Implement help modal
    alert('Help documentation coming soon!');
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    console.log('Quantum Crypto Scanner Dashboard loaded');
});
"""
        
        with open(js_dir / 'dashboard.js', 'w') as f:
            f.write(dashboard_js)
        
        # Charts JavaScript
        charts_js = """
// Additional chart utilities and configurations
// This file can be extended with more chart types and configurations
"""
        
        with open(js_dir / 'charts.js', 'w') as f:
            f.write(charts_js)