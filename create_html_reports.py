#!/usr/bin/env python3
"""
Integrated HTML Report Generator
Creates HTML reports from JSON scan results and automatically creates results folder structure
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import uuid


def create_results_folder_structure(base_dir: str = "results") -> Path:
    """Create the results folder structure"""
    results_path = Path(base_dir)
    html_path = results_path / "html_reports"
    
    # Create directories
    results_path.mkdir(exist_ok=True)
    html_path.mkdir(exist_ok=True)
    
    return html_path


def generate_html_from_json(json_data: Dict[str, Any], output_dir: Path) -> Dict[str, str]:
    """Generate HTML reports from JSON data"""
    
    # Prepare context data
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data
    
    # Handle different JSON structures
    if 'cbom' in data:
        cbom = data['cbom']
        scan_metadata = data.get('scan_metadata', {})
    else:
        cbom = data
        scan_metadata = {}
    
    components = cbom.get('components', [])
    vulnerabilities = cbom.get('vulnerabilities', [])
    quantum_readiness = cbom.get('quantumReadiness', {})
    migration_recommendations = cbom.get('migrationRecommendations', [])
    
    # Calculate statistics
    stats = calculate_statistics(components, vulnerabilities, quantum_readiness)
    
    # Common context for all templates
    context = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'project_name': scan_metadata.get('target_path', cbom.get('metadata', {}).get('component', {}).get('name', 'Unknown Project')),
        'stats': stats,
        'components': components,
        'vulnerabilities': vulnerabilities,
        'quantum_readiness': quantum_readiness,
        'migration_recommendations': migration_recommendations,
        'cbom': cbom
    }
    
    generated_files = {}
    
    # Generate main dashboard
    main_html = generate_main_dashboard(context)
    main_file = output_dir / "index.html"
    with open(main_file, 'w', encoding='utf-8') as f:
        f.write(main_html)
    generated_files['dashboard'] = str(main_file)
    
    # Generate crypto assets page
    assets_html = generate_crypto_assets_page(context)
    assets_file = output_dir / "crypto_assets.html"
    with open(assets_file, 'w', encoding='utf-8') as f:
        f.write(assets_html)
    generated_files['crypto_assets'] = str(assets_file)
    
    # Generate vulnerabilities page
    vulns_html = generate_vulnerabilities_page(context)
    vulns_file = output_dir / "vulnerabilities.html"
    with open(vulns_file, 'w', encoding='utf-8') as f:
        f.write(vulns_html)
    generated_files['vulnerabilities'] = str(vulns_file)
    
    # Generate migration plan page
    migration_html = generate_migration_page(context)
    migration_file = output_dir / "migration_plan.html"
    with open(migration_file, 'w', encoding='utf-8') as f:
        f.write(migration_html)
    generated_files['migration_plan'] = str(migration_file)
    
    # Generate summary page
    summary_html = generate_summary_page(context)
    summary_file = output_dir / "summary.html"
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write(summary_html)
    generated_files['summary'] = str(summary_file)
    
    # Generate CBOM page
    cbom_html = generate_cbom_page(context)
    cbom_file = output_dir / "cbom.html"
    with open(cbom_file, 'w', encoding='utf-8') as f:
        f.write(cbom_html)
    generated_files['cbom'] = str(cbom_file)
    
    # Generate CSS file
    css_content = get_css_styles()
    css_file = output_dir / "styles.css"
    with open(css_file, 'w', encoding='utf-8') as f:
        f.write(css_content)
    generated_files['styles'] = str(css_file)
    
    return generated_files


def calculate_statistics(components: List[Dict], vulnerabilities: List[Dict], quantum_readiness: Dict) -> Dict[str, Any]:
    """Calculate statistics for the reports"""
    crypto_types = {}
    severity_levels = {}
    languages = {}
    quantum_vulnerable_count = 0
    
    for component in components:
        # Get crypto type
        crypto_type = None
        for prop in component.get('properties', []):
            if prop.get('name') == 'crypto:algorithm-type':
                crypto_type = prop.get('value', 'Unknown')
                break
        
        if crypto_type:
            crypto_types[crypto_type] = crypto_types.get(crypto_type, 0) + 1
        
        # Get severity
        severity = None
        for prop in component.get('properties', []):
            if prop.get('name') == 'crypto:severity':
                severity = prop.get('value', 'Unknown')
                break
        
        if severity:
            severity_levels[severity] = severity_levels.get(severity, 0) + 1
        
        # Get language
        language = None
        for prop in component.get('properties', []):
            if prop.get('name') == 'crypto:language':
                language = prop.get('value', 'Unknown')
                break
        
        if language:
            languages[language] = languages.get(language, 0) + 1
        
        # Check if quantum vulnerable
        is_vulnerable = False
        for prop in component.get('properties', []):
            if prop.get('name') == 'quantum:vulnerable' and prop.get('value') == 'True':
                is_vulnerable = True
                break
        
        if is_vulnerable:
            quantum_vulnerable_count += 1
    
    return {
        'total_components': len(components),
        'total_vulnerabilities': len(vulnerabilities),
        'quantum_vulnerable_count': quantum_vulnerable_count,
        'quantum_safe_count': len(components) - quantum_vulnerable_count,
        'crypto_types': crypto_types,
        'severity_levels': severity_levels,
        'languages': languages,
        'quantum_readiness_score': quantum_readiness.get('score', 0),
        'quantum_status': quantum_readiness.get('status', 'unknown').replace('-', ' ').title()
    }


def generate_main_dashboard(context: Dict[str, Any]) -> str:
    """Generate the main dashboard HTML"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum Crypto Scanner - Dashboard</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🛡️ Quantum Crypto Scanner Dashboard</h1>
            <p class="subtitle">Comprehensive Cryptographic Vulnerability Analysis</p>
            <div class="metadata">
                <span>Project: {context['project_name']}</span> | 
                <span>Generated: {context['timestamp']}</span>
            </div>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html" class="active">Dashboard</a></li>
                <li><a href="crypto_assets.html">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html">Vulnerabilities</a></li>
                <li><a href="migration_plan.html">Migration Plan</a></li>
                <li><a href="summary.html">Summary</a></li>
                <li><a href="cbom.html">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="dashboard-grid">
                <div class="metric-card critical">
                    <h3>Quantum Risk Status</h3>
                    <div class="metric-value">{context['stats']['quantum_status']}</div>
                    <div class="metric-label">Overall Status</div>
                </div>

                <div class="metric-card">
                    <h3>Crypto Assets</h3>
                    <div class="metric-value">{context['stats']['total_components']}</div>
                    <div class="metric-label">Total Components</div>
                </div>

                <div class="metric-card vulnerable">
                    <h3>Quantum Vulnerable</h3>
                    <div class="metric-value">{context['stats']['quantum_vulnerable_count']}</div>
                    <div class="metric-label">Critical Items</div>
                </div>

                <div class="metric-card safe">
                    <h3>Quantum Safe</h3>
                    <div class="metric-value">{context['stats']['quantum_safe_count']}</div>
                    <div class="metric-label">Safe Items</div>
                </div>

                <div class="metric-card">
                    <h3>Readiness Score</h3>
                    <div class="metric-value">{context['stats']['quantum_readiness_score']}%</div>
                    <div class="metric-label">Quantum Readiness</div>
                </div>

                <div class="metric-card warning">
                    <h3>Vulnerabilities</h3>
                    <div class="metric-value">{context['stats']['total_vulnerabilities']}</div>
                    <div class="metric-label">Security Issues</div>
                </div>
            </div>

            <div class="quick-actions">
                <h2>Quick Actions</h2>
                <div class="action-buttons">
                    <a href="crypto_assets.html" class="btn btn-primary">View Crypto Assets</a>
                    <a href="vulnerabilities.html" class="btn btn-danger">Review Vulnerabilities</a>
                    <a href="migration_plan.html" class="btn btn-warning">Migration Plan</a>
                    <a href="cbom.html" class="btn btn-info">Download CBOM</a>
                </div>
            </div>

            <div class="recent-findings">
                <h2>Scan Overview</h2>
                <p>This dashboard provides an overview of cryptographic assets and quantum vulnerabilities found in your codebase.</p>
                <ul>
                    <li><strong>Total Components:</strong> {context['stats']['total_components']} cryptographic assets identified</li>
                    <li><strong>Quantum Vulnerable:</strong> {context['stats']['quantum_vulnerable_count']} components at risk</li>
                    <li><strong>Readiness Score:</strong> {context['stats']['quantum_readiness_score']}% quantum-safe</li>
                    <li><strong>Crypto Types:</strong> {', '.join(context['stats']['crypto_types'].keys()) or 'None detected'}</li>
                </ul>
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>
</body>
</html>"""


def generate_crypto_assets_page(context: Dict[str, Any]) -> str:
    """Generate crypto assets page"""
    # Build component rows
    component_rows = ""
    for i, component in enumerate(context['components'], 1):
        props = {prop['name']: prop['value'] for prop in component.get('properties', [])}
        
        crypto_type = props.get('crypto:algorithm-type', 'Unknown')
        pattern = props.get('crypto:pattern', 'N/A')
        language = props.get('crypto:language', 'Unknown')
        confidence = props.get('crypto:confidence', 'N/A')
        severity = props.get('crypto:severity', 'Unknown')
        quantum_vulnerable = props.get('quantum:vulnerable', 'False')
        risk_level = props.get('quantum:risk-level', 'Unknown')
        
        row_class = "vulnerable" if quantum_vulnerable == 'True' else "safe"
        
        component_rows += f"""
            <tr class="{row_class}">
                <td>{i}</td>
                <td>{component['name']}</td>
                <td><span class="crypto-type">{crypto_type}</span></td>
                <td><code>{pattern}</code></td>
                <td>{language}</td>
                <td>{confidence}</td>
                <td><span class="severity severity-{severity.lower()}">{severity}</span></td>
                <td><span class="quantum-status {'vulnerable' if quantum_vulnerable == 'True' else 'safe'}">{quantum_vulnerable}</span></td>
                <td><span class="risk-level risk-{risk_level.lower()}">{risk_level}</span></td>
            </tr>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crypto Assets - Quantum Crypto Scanner</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🔐 Cryptographic Assets</h1>
            <p class="subtitle">Detailed analysis of cryptographic components</p>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html">Dashboard</a></li>
                <li><a href="crypto_assets.html" class="active">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html">Vulnerabilities</a></li>
                <li><a href="migration_plan.html">Migration Plan</a></li>
                <li><a href="summary.html">Summary</a></li>
                <li><a href="cbom.html">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="assets-overview">
                <h2>Assets Overview</h2>
                <div class="overview-stats">
                    <div class="stat-item">
                        <span class="stat-number">{context['stats']['total_components']}</span>
                        <span class="stat-label">Total Assets</span>
                    </div>
                    <div class="stat-item vulnerable">
                        <span class="stat-number">{context['stats']['quantum_vulnerable_count']}</span>
                        <span class="stat-label">Quantum Vulnerable</span>
                    </div>
                    <div class="stat-item safe">
                        <span class="stat-number">{context['stats']['quantum_safe_count']}</span>
                        <span class="stat-label">Quantum Safe</span>
                    </div>
                </div>
            </div>

            <div class="assets-table-container">
                <h2>Cryptographic Components</h2>
                <table class="assets-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Component Name</th>
                            <th>Crypto Type</th>
                            <th>Pattern</th>
                            <th>Language</th>
                            <th>Confidence</th>
                            <th>Severity</th>
                            <th>Quantum Vulnerable</th>
                            <th>Risk Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        {component_rows}
                    </tbody>
                </table>
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>
</body>
</html>"""


def generate_vulnerabilities_page(context: Dict[str, Any]) -> str:
    """Generate vulnerabilities page"""
    vuln_rows = ""
    for i, vuln in enumerate(context['vulnerabilities'], 1):
        vuln_id = vuln.get('id', f'VULN-{i}')
        description = vuln.get('description', 'No description available')
        detail = vuln.get('detail', 'No details available')
        recommendation = vuln.get('recommendation', 'See migration plan')
        
        severity = 'Unknown'
        score = 'N/A'
        for rating in vuln.get('ratings', []):
            severity = rating.get('severity', 'Unknown').title()
            score = rating.get('score', 'N/A')
            break
        
        vuln_rows += f"""
            <tr>
                <td>{i}</td>
                <td><strong>{vuln_id}</strong></td>
                <td><span class="severity severity-{severity.lower()}">{severity}</span></td>
                <td>{score}</td>
                <td>{description}</td>
                <td class="detail-cell">{detail}</td>
                <td class="recommendation-cell">{recommendation}</td>
            </tr>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerabilities - Quantum Crypto Scanner</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>⚠️ Quantum Vulnerabilities</h1>
            <p class="subtitle">Security vulnerabilities and quantum threats</p>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html">Dashboard</a></li>
                <li><a href="crypto_assets.html">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html" class="active">Vulnerabilities</a></li>
                <li><a href="migration_plan.html">Migration Plan</a></li>
                <li><a href="summary.html">Summary</a></li>
                <li><a href="cbom.html">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="vulnerabilities-overview">
                <h2>Vulnerability Overview</h2>
                <div class="overview-stats">
                    <div class="stat-item critical">
                        <span class="stat-number">{context['stats']['total_vulnerabilities']}</span>
                        <span class="stat-label">Total Vulnerabilities</span>
                    </div>
                </div>
            </div>

            <div class="vulnerabilities-table-container">
                <h2>Detected Vulnerabilities</h2>
                <table class="vulnerabilities-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Vulnerability ID</th>
                            <th>Severity</th>
                            <th>Score</th>
                            <th>Description</th>
                            <th>Details</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows}
                    </tbody>
                </table>
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>
</body>
</html>"""


def generate_migration_page(context: Dict[str, Any]) -> str:
    """Generate migration plan page"""
    migration_cards = ""
    for i, recommendation in enumerate(context['migration_recommendations'], 1):
        crypto_type = recommendation.get('crypto_type', 'Unknown')
        priority = recommendation.get('priority', 'MEDIUM')
        affected_files = recommendation.get('affected_files', 0)
        affected_instances = recommendation.get('affected_instances', 0)
        timeline = recommendation.get('migration_timeline', 'TBD')
        effort = recommendation.get('estimated_effort', 'TBD')
        
        nist_rec = recommendation.get('nist_recommendation', {})
        signatures = ', '.join(nist_rec.get('signatures', ['Not specified']))
        key_encapsulation = ', '.join(nist_rec.get('key_encapsulation', ['Not specified']))
        
        actions = recommendation.get('specific_actions', [])
        action_list = ''.join([f'<li>{action}</li>' for action in actions])
        
        priority_class = priority.lower()
        
        migration_cards += f"""
            <div class="migration-card priority-{priority_class}">
                <div class="migration-header">
                    <h3>{crypto_type} Migration</h3>
                    <span class="priority-badge priority-{priority_class}">{priority} Priority</span>
                </div>
                <div class="migration-content">
                    <div class="migration-stats">
                        <div class="stat">
                            <span class="stat-label">Affected Files:</span>
                            <span class="stat-value">{affected_files}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Instances:</span>
                            <span class="stat-value">{affected_instances}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Timeline:</span>
                            <span class="stat-value">{timeline}</span>
                        </div>
                        <div class="stat">
                            <span class="stat-label">Effort:</span>
                            <span class="stat-value">{effort}</span>
                        </div>
                    </div>
                    
                    <div class="nist-recommendations">
                        <h4>NIST Recommendations</h4>
                        <p><strong>Signatures:</strong> {signatures}</p>
                        <p><strong>Key Encapsulation:</strong> {key_encapsulation}</p>
                    </div>
                    
                    <div class="action-items">
                        <h4>Specific Actions</h4>
                        <ul>{action_list}</ul>
                    </div>
                </div>
            </div>
        """
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Migration Plan - Quantum Crypto Scanner</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>🚀 Post-Quantum Migration Plan</h1>
            <p class="subtitle">Roadmap to quantum-safe cryptography</p>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html">Dashboard</a></li>
                <li><a href="crypto_assets.html">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html">Vulnerabilities</a></li>
                <li><a href="migration_plan.html" class="active">Migration Plan</a></li>
                <li><a href="summary.html">Summary</a></li>
                <li><a href="cbom.html">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="migration-overview">
                <h2>Migration Overview</h2>
                <p>This section provides a comprehensive plan for migrating from quantum-vulnerable cryptographic algorithms to post-quantum cryptography (PQC) standards.</p>
                
                <div class="overview-stats">
                    <div class="stat-item">
                        <span class="stat-number">{len(context['migration_recommendations'])}</span>
                        <span class="stat-label">Migration Tasks</span>
                    </div>
                </div>
            </div>

            <div class="migration-recommendations">
                <h2>Migration Recommendations</h2>
                {migration_cards if migration_cards else '<p>No specific migration recommendations available in the current data.</p>'}
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>
</body>
</html>"""


def generate_summary_page(context: Dict[str, Any]) -> str:
    """Generate summary page with charts"""
    crypto_types_json = json.dumps(context['stats']['crypto_types'])
    severity_levels_json = json.dumps(context['stats']['severity_levels'])
    languages_json = json.dumps(context['stats']['languages'])
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Summary - Quantum Crypto Scanner</title>
    <link rel="stylesheet" href="styles.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>📊 Scan Summary</h1>
            <p class="subtitle">Statistical overview and analysis</p>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html">Dashboard</a></li>
                <li><a href="crypto_assets.html">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html">Vulnerabilities</a></li>
                <li><a href="migration_plan.html">Migration Plan</a></li>
                <li><a href="summary.html" class="active">Summary</a></li>
                <li><a href="cbom.html">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="charts-grid">
                <div class="chart-container">
                    <h3>Crypto Types Distribution</h3>
                    <canvas id="cryptoTypesChart"></canvas>
                </div>

                <div class="chart-container">
                    <h3>Severity Levels</h3>
                    <canvas id="severityChart"></canvas>
                </div>

                <div class="chart-container">
                    <h3>Languages Analyzed</h3>
                    <canvas id="languagesChart"></canvas>
                </div>

                <div class="chart-container">
                    <h3>Quantum Readiness</h3>
                    <canvas id="readinessChart"></canvas>
                </div>
            </div>

            <div class="summary-stats">
                <h2>Summary Statistics</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <h4>Total Crypto Assets</h4>
                        <div class="stat-value">{context['stats']['total_components']}</div>
                    </div>
                    <div class="stat-card vulnerable">
                        <h4>Quantum Vulnerable</h4>
                        <div class="stat-value">{context['stats']['quantum_vulnerable_count']}</div>
                    </div>
                    <div class="stat-card safe">
                        <h4>Quantum Safe</h4>
                        <div class="stat-value">{context['stats']['quantum_safe_count']}</div>
                    </div>
                    <div class="stat-card">
                        <h4>Readiness Score</h4>
                        <div class="stat-value">{context['stats']['quantum_readiness_score']}%</div>
                    </div>
                </div>
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>

    <script>
        // Chart data
        const cryptoTypesData = {crypto_types_json};
        const severityData = {severity_levels_json};
        const languagesData = {languages_json};
        const readinessScore = {context['stats']['quantum_readiness_score']};

        // Only create charts if data exists
        if (Object.keys(cryptoTypesData).length > 0) {{
            new Chart(document.getElementById('cryptoTypesChart'), {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(cryptoTypesData),
                    datasets: [{{
                        data: Object.values(cryptoTypesData),
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false
                }}
            }});
        }}

        if (Object.keys(severityData).length > 0) {{
            new Chart(document.getElementById('severityChart'), {{
                type: 'bar',
                data: {{
                    labels: Object.keys(severityData),
                    datasets: [{{
                        label: 'Count',
                        data: Object.values(severityData),
                        backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        }}

        if (Object.keys(languagesData).length > 0) {{
            new Chart(document.getElementById('languagesChart'), {{
                type: 'pie',
                data: {{
                    labels: Object.keys(languagesData),
                    datasets: [{{
                        data: Object.values(languagesData),
                        backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false
                }}
            }});
        }}

        // Readiness Chart
        new Chart(document.getElementById('readinessChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Quantum Ready', 'Needs Migration'],
                datasets: [{{
                    data: [readinessScore, 100 - readinessScore],
                    backgroundColor: ['#28a745', '#dc3545']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""


def generate_cbom_page(context: Dict[str, Any]) -> str:
    """Generate CBOM page"""
    cbom_json = json.dumps(context['cbom'], indent=2)
    
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBOM - Quantum Crypto Scanner</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>📋 Cryptographic Bill of Materials (CBOM)</h1>
            <p class="subtitle">Complete CBOM in CycloneDX format</p>
        </header>

        <nav class="nav-menu">
            <ul>
                <li><a href="index.html">Dashboard</a></li>
                <li><a href="crypto_assets.html">Crypto Assets</a></li>
                <li><a href="vulnerabilities.html">Vulnerabilities</a></li>
                <li><a href="migration_plan.html">Migration Plan</a></li>
                <li><a href="summary.html">Summary</a></li>
                <li><a href="cbom.html" class="active">CBOM</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <div class="cbom-info">
                <h2>About CBOM</h2>
                <p>A Cryptographic Bill of Materials (CBOM) provides a comprehensive inventory of cryptographic assets and their quantum vulnerability status. This CBOM follows the CycloneDX standard for software bill of materials.</p>
                
                <div class="cbom-actions">
                    <button onclick="downloadCBOM()" class="btn btn-primary">Download CBOM JSON</button>
                    <button onclick="copyCBOM()" class="btn btn-secondary">Copy to Clipboard</button>
                </div>
            </div>

            <div class="cbom-content">
                <h2>CBOM Content</h2>
                <pre id="cbom-json" class="cbom-json">{cbom_json}</pre>
            </div>
        </main>

        <footer class="footer">
            <p>&copy; 2025 Quantum Crypto Scanner | Generated on {context['timestamp']}</p>
        </footer>
    </div>

    <script>
        function downloadCBOM() {{
            const cbomContent = document.getElementById('cbom-json').textContent;
            const blob = new Blob([cbomContent], {{ type: 'application/json' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cbom.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }}

        function copyCBOM() {{
            const cbomContent = document.getElementById('cbom-json').textContent;
            navigator.clipboard.writeText(cbomContent).then(() => {{
                alert('CBOM copied to clipboard!');
            }});
        }}
    </script>
</body>
</html>"""


def get_css_styles() -> str:
    """Get CSS styles for all HTML reports"""
    return """/* Quantum Crypto Scanner - HTML Report Styles */

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f5f5f5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Header Styles */
.header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px 20px;
    border-radius: 10px;
    margin-bottom: 20px;
    text-align: center;
}

.header h1 {
    font-size: 2.5em;
    margin-bottom: 10px;
}

.subtitle {
    font-size: 1.2em;
    opacity: 0.9;
    margin-bottom: 15px;
}

.metadata {
    font-size: 0.9em;
    opacity: 0.8;
}

/* Navigation Styles */
.nav-menu {
    background: white;
    border-radius: 10px;
    padding: 15px 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.nav-menu ul {
    list-style: none;
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.nav-menu a {
    text-decoration: none;
    color: #666;
    padding: 10px 15px;
    border-radius: 5px;
    transition: all 0.3s ease;
}

.nav-menu a:hover,
.nav-menu a.active {
    background: #667eea;
    color: white;
}

/* Main Content */
.main-content {
    background: white;
    border-radius: 10px;
    padding: 30px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    margin-bottom: 20px;
}

/* Dashboard Grid */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.metric-card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    border-left: 5px solid #667eea;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.metric-card.critical {
    border-left-color: #dc3545;
}

.metric-card.vulnerable {
    border-left-color: #fd7e14;
}

.metric-card.safe {
    border-left-color: #28a745;
}

.metric-card.warning {
    border-left-color: #ffc107;
}

.metric-card h3 {
    font-size: 1em;
    color: #666;
    margin-bottom: 10px;
}

.metric-value {
    font-size: 2.5em;
    font-weight: bold;
    color: #333;
    margin-bottom: 5px;
}

.metric-label {
    font-size: 0.9em;
    color: #888;
}

/* Tables */
.assets-table,
.vulnerabilities-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

.assets-table th,
.assets-table td,
.vulnerabilities-table th,
.vulnerabilities-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

.assets-table th,
.vulnerabilities-table th {
    background-color: #f8f9fa;
    font-weight: bold;
    color: #333;
}

.assets-table tr.vulnerable {
    background-color: #fff5f5;
}

.assets-table tr.safe {
    background-color: #f0fff4;
}

/* Status Badges */
.crypto-type {
    background: #e9ecef;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.9em;
}

.severity {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    text-transform: uppercase;
}

.severity.severity-critical {
    background: #f8d7da;
    color: #721c24;
}

.severity.severity-high {
    background: #ffeaa7;
    color: #856404;
}

.severity.severity-medium {
    background: #fff3cd;
    color: #856404;
}

.severity.severity-low {
    background: #d1ecf1;
    color: #0c5460;
}

.quantum-status.vulnerable {
    color: #dc3545;
    font-weight: bold;
}

.quantum-status.safe {
    color: #28a745;
    font-weight: bold;
}

.risk-level {
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
}

.risk-level.risk-critical {
    background: #f8d7da;
    color: #721c24;
}

.risk-level.risk-high {
    background: #ffeaa7;
    color: #856404;
}

.risk-level.risk-medium {
    background: #fff3cd;
    color: #856404;
}

.risk-level.risk-low {
    background: #d1ecf1;
    color: #0c5460;
}

/* Migration Cards */
.migration-card {
    background: white;
    border: 1px solid #ddd;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}

.migration-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}

.priority-badge {
    padding: 5px 10px;
    border-radius: 5px;
    font-size: 0.8em;
    font-weight: bold;
    text-transform: uppercase;
}

.priority-badge.priority-high {
    background: #f8d7da;
    color: #721c24;
}

.priority-badge.priority-medium {
    background: #fff3cd;
    color: #856404;
}

.priority-badge.priority-low {
    background: #d1ecf1;
    color: #0c5460;
}

.migration-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}

.stat {
    display: flex;
    justify-content: space-between;
    padding: 10px;
    background: #f8f9fa;
    border-radius: 5px;
}

.stat-label {
    font-weight: bold;
}

.nist-recommendations,
.action-items {
    margin-top: 15px;
}

.action-items ul {
    list-style-position: inside;
    margin-left: 10px;
}

.action-items li {
    margin-bottom: 5px;
}

/* Charts */
.charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}

.chart-container {
    background: white;
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    height: 300px;
}

.chart-container h3 {
    margin-bottom: 15px;
    text-align: center;
}

/* Stats Grid */
.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
}

.stat-card {
    background: white;
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    border-left: 5px solid #667eea;
}

.stat-card.vulnerable {
    border-left-color: #dc3545;
}

.stat-card.safe {
    border-left-color: #28a745;
}

.stat-card h4 {
    color: #666;
    margin-bottom: 10px;
}

.stat-card .stat-value {
    font-size: 2em;
    font-weight: bold;
    color: #333;
}

/* CBOM Styles */
.cbom-json {
    background: #f8f9fa;
    border: 1px solid #ddd;
    border-radius: 5px;
    padding: 20px;
    font-family: 'Courier New', monospace;
    font-size: 0.9em;
    overflow-x: auto;
    white-space: pre-wrap;
    max-height: 600px;
    overflow-y: auto;
}

.cbom-actions {
    margin: 20px 0;
}

/* Buttons */
.btn {
    display: inline-block;
    padding: 10px 20px;
    background: #667eea;
    color: white;
    text-decoration: none;
    border-radius: 5px;
    border: none;
    cursor: pointer;
    font-size: 1em;
    transition: background 0.3s ease;
    margin-right: 10px;
    margin-bottom: 10px;
}

.btn:hover {
    background: #5a67d8;
}

.btn.btn-primary {
    background: #667eea;
}

.btn.btn-danger {
    background: #dc3545;
}

.btn.btn-warning {
    background: #ffc107;
    color: #333;
}

.btn.btn-info {
    background: #17a2b8;
}

.btn.btn-secondary {
    background: #6c757d;
}

.action-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}

/* Quick Actions */
.quick-actions {
    margin: 30px 0;
}

.quick-actions h2 {
    margin-bottom: 20px;
}

/* Overview Stats */
.overview-stats {
    display: flex;
    gap: 30px;
    margin: 20px 0;
}

.stat-item {
    text-align: center;
    padding: 15px;
    background: #f8f9fa;
    border-radius: 10px;
    min-width: 120px;
}

.stat-item.vulnerable {
    background: #fff5f5;
    color: #dc3545;
}

.stat-item.safe {
    background: #f0fff4;
    color: #28a745;
}

.stat-number {
    display: block;
    font-size: 2em;
    font-weight: bold;
    margin-bottom: 5px;
}

.stat-label {
    font-size: 0.9em;
    opacity: 0.8;
}

/* Table Containers */
.assets-table-container,
.vulnerabilities-table-container {
    margin-top: 30px;
    overflow-x: auto;
}

.detail-cell,
.recommendation-cell {
    max-width: 200px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* Footer */
.footer {
    text-align: center;
    padding: 20px;
    color: #666;
    border-top: 1px solid #ddd;
    margin-top: 30px;
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .header h1 {
        font-size: 2em;
    }
    
    .nav-menu ul {
        flex-direction: column;
        gap: 10px;
    }
    
    .dashboard-grid,
    .charts-grid,
    .stats-grid {
        grid-template-columns: 1fr;
    }
    
    .migration-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 10px;
    }
    
    .overview-stats {
        flex-direction: column;
        gap: 15px;
    }
    
    .action-buttons {
        flex-direction: column;
    }
    
    .btn {
        width: 100%;
        margin-right: 0;
    }
}"""


def main():
    """Main function for the integrated HTML report generator"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate HTML reports from Quantum Crypto Scanner JSON results',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python create_html_reports.py test_samples__cbom.json
  python create_html_reports.py scan_results.json --output-dir custom_reports
        """
    )
    
    parser.add_argument('json_file', 
                       help='Path to the JSON file containing scan results or CBOM data')
    parser.add_argument('--output-dir', '-o', 
                       default='results',
                       help='Base output directory (HTML reports will be in results/html_reports)')
    parser.add_argument('--verbose', '-v', 
                       action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Validate input file
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"❌ Error: JSON file not found: {json_path}")
        return 1
    
    try:
        # Load JSON data
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        if args.verbose:
            print(f"✅ Successfully loaded JSON data from {json_path}")
        
        # Create results folder structure
        html_output_dir = create_results_folder_structure(args.output_dir)
        
        if args.verbose:
            print(f"📁 Created output directory: {html_output_dir}")
        
        # Generate HTML reports
        print(f"🔄 Generating HTML reports...")
        generated_files = generate_html_from_json(json_data, html_output_dir)
        
        if generated_files:
            print(f"🎉 Successfully generated {len(generated_files)} HTML files!")
            print(f"\n📄 Generated files in {html_output_dir}/:")
            
            for report_name, file_path in generated_files.items():
                file_size = os.path.getsize(file_path)
                print(f"  📄 {report_name:<15} → {Path(file_path).name} ({file_size:,} bytes)")
            
            # Show main dashboard link
            main_dashboard = html_output_dir / "index.html"
            print(f"\n🌐 Main Dashboard: {main_dashboard}")
            print(f"🌐 Open in browser: file://{main_dashboard.absolute()}")
            
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


if __name__ == "__main__":
    sys.exit(main())
