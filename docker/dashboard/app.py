#!/usr/bin/env python3
"""
QuantumGuard: Cyberpunk Dashboard
Flask backend for the cyberpunk-style security dashboard.
Serves real-time security metrics, heatmaps, and remediation logs.
"""

import json
import os
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')

REPORTS_DIR = Path('reports')
DATA_DIR = Path('data')

class DashboardData:
    def __init__(self):
        self.reports_dir = REPORTS_DIR
        self.data_dir = DATA_DIR
        self.data_dir.mkdir(exist_ok=True)

    def get_latest_scan_data(self):
        """Get the latest security scan data."""
        scan_types = ['sast', 'sca', 'container', 'iac']
        latest_data = {}

        for scan_type in scan_types:
            report_file = self.reports_dir / f"{scan_type}-processed.json"
            if report_file.exists():
                try:
                    with open(report_file, 'r') as f:
                        data = json.load(f)
                        latest_data[scan_type] = {
                            'risk_score': data.get('overall_risk_score', 0),
                            'findings': len(data.get('findings', [])),
                            'last_scan': data.get('timestamp', ''),
                            'severity_breakdown': data.get('severity_breakdown', {})
                        }
                except json.JSONDecodeError:
                    continue

        return latest_data

    def get_attack_simulation_data(self):
        """Get attack simulation results."""
        sim_file = self.reports_dir / "attack-simulation-report.json"
        if sim_file.exists():
            try:
                with open(sim_file, 'r') as f:
                    data = json.load(f)
                    return {
                        'overall_risk': data.get('simulation_summary', {}).get('overall_risk_score', 0),
                        'simulations': data.get('attack_results', {}),
                        'timestamp': data.get('simulation_summary', {}).get('timestamp', '')
                    }
            except json.JSONDecodeError:
                pass
        return {}

    def get_remediation_status(self):
        """Get auto-remediation status."""
        rem_file = self.reports_dir / "remediation-report.json"
        if rem_file.exists():
            try:
                with open(rem_file, 'r') as f:
                    data = json.load(f)
                    return {
                        'phases': data.get('phases', {}),
                        'timestamp': data.get('timestamp', '')
                    }
            except json.JSONDecodeError:
                pass
        return {}

    def get_system_health(self):
        """Get overall system health metrics."""
        scan_data = self.get_latest_scan_data()
        sim_data = self.get_attack_simulation_data()

        total_risk = 0
        scan_count = 0

        for scan_type, data in scan_data.items():
            total_risk += data.get('risk_score', 0)
            scan_count += 1

        if sim_data:
            total_risk += sim_data.get('overall_risk', 0)
            scan_count += 1

        avg_risk = total_risk / max(scan_count, 1)

        health_status = "CRITICAL" if avg_risk >= 7 else "HIGH" if avg_risk >= 5 else "MEDIUM" if avg_risk >= 3 else "LOW"

        return {
            'overall_health': health_status,
            'average_risk_score': round(avg_risk, 2),
            'active_scans': scan_count,
            'last_update': time.time()
        }

dashboard_data = DashboardData()

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/api/health')
def get_health():
    """API endpoint for system health."""
    return jsonify(dashboard_data.get_system_health())

@app.route('/api/scans')
def get_scans():
    """API endpoint for scan data."""
    return jsonify(dashboard_data.get_latest_scan_data())

@app.route('/api/simulations')
def get_simulations():
    """API endpoint for attack simulations."""
    return jsonify(dashboard_data.get_attack_simulation_data())

@app.route('/api/remediation')
def get_remediation():
    """API endpoint for remediation status."""
    return jsonify(dashboard_data.get_remediation_status())

@app.route('/api/logs')
def get_logs():
    """API endpoint for recent logs."""
    log_file = DATA_DIR / 'dashboard.log'
    logs = []

    if log_file.exists():
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()[-50:]  # Last 50 lines
                for line in lines:
                    if ' - ' in line:
                        timestamp, level, message = line.split(' - ', 2)
                        logs.append({
                            'timestamp': timestamp,
                            'level': level,
                            'message': message.strip()
                        })
        except Exception as e:
            logger.error(f"Error reading logs: {e}")

    return jsonify({'logs': logs})

@app.route('/api/trigger-scan/<scan_type>')
def trigger_scan(scan_type):
    """API endpoint to trigger a specific scan."""
    import subprocess

    scan_commands = {
        'sast': ['python', 'scanner/sast_scan.py'],
        'sca': ['python', 'scanner/sca_scan.py'],
        'container': ['python', 'scanner/container_scan.py'],
        'iac': ['python', 'scanner/iac_scan.py'],
        'simulation': ['python', 'simulator/attack_simulator.py'],
        'remediation': ['python', 'hardening/auto_remediate.py']
    }

    if scan_type not in scan_commands:
        return jsonify({'error': 'Invalid scan type'}), 400

    try:
        # Run scan in background
        subprocess.Popen(scan_commands[scan_type])
        return jsonify({'status': 'started', 'scan_type': scan_type})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/heatmap-data')
def get_heatmap_data():
    """API endpoint for risk heatmap data."""
    scan_data = dashboard_data.get_latest_scan_data()

    # Create mock heatmap data for visualization
    heatmap_data = {
        'containers': [],
        'services': [],
        'infrastructure': []
    }

    # Generate sample data based on scan results
    for scan_type, data in scan_data.items():
        risk_score = data.get('risk_score', 0)
        heatmap_data['services'].append({
            'name': scan_type.upper(),
            'risk': risk_score,
            'x': len(heatmap_data['services']),
            'y': risk_score
        })

    return jsonify(heatmap_data)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    templates_dir = Path('dashboard/templates')
    templates_dir.mkdir(parents=True, exist_ok=True)

    # Create static directory
    static_dir = Path('dashboard/static')
    static_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting QuantumGuard Dashboard...")
    app.run(host='0.0.0.0', port=5000, debug=True)
