#!/usr/bin/env python3
"""
QuantumGuard: Main Orchestrator
Complete offline cyber-defense simulator with modular functions.
Integrates all components: scanning, simulation, hardening, learning, dashboard.
"""

import sys
import time
import argparse
from pathlib import Path
from typing import Dict, Any, Optional

# Import all modules
from utils import QuantumGuardUtils
from self_learning import SelfLearningModule
from scanner.sast_scan import SASTScanner
from scanner.sca_scan import SCAScanner
from scanner.container_scan import ContainerScanner
from scanner.iac_scan import IACScanner
from simulator.attack_simulator import AttackSimulator
from hardening.auto_remediate import AutoRemediator
from dashboard.app import app as dashboard_app

class QuantumGuard:
    """Main QuantumGuard orchestrator class."""

    def __init__(self):
        self.utils = QuantumGuardUtils()
        self.self_learning = SelfLearningModule()
        self.scanners = {}
        self.simulator = None
        self.remediator = None
        self.dashboard_process = None

    # App Setup Functions
    def check_prerequisites(self) -> Dict[str, bool]:
        """Validate system dependencies."""
        return self.utils.check_prerequisites()

    def prepare_environment(self) -> bool:
        """Create folders, clean old logs, initialize local databases or storage."""
        return self.utils.prepare_environment()

    def deploy_vulnerable_app(self) -> bool:
        """Clone OWASP Juice Shop, apply theme, run Docker container."""
        return self.utils.deploy_vulnerable_app()

    def apply_theme(self) -> bool:
        """Apply cyberpunk purple hacker-style frontend."""
        return self.utils.apply_theme()

    # Scanner Functions
    def run_sast_scan(self) -> Dict[str, Any]:
        """Run Semgrep or custom static code analysis."""
        scanner = SASTScanner()
        return scanner.run_scan()

    def run_dependency_scan(self) -> Dict[str, Any]:
        """Check for vulnerable dependencies using OWASP Dependency-Check."""
        scanner = SCAScanner()
        return scanner.run_scan()

    def run_container_scan(self) -> Dict[str, Any]:
        """Scan Docker image for vulnerabilities using Trivy."""
        scanner = ContainerScanner()
        return scanner.run_scan()

    def run_secret_scan(self) -> Dict[str, Any]:
        """Detect secrets or credentials in the code using Gitleaks."""
        return self.utils.run_secret_scan()

    def run_iac_scan(self) -> Dict[str, Any]:
        """Scan Terraform manifests using tfsec."""
        scanner = IACScanner()
        return scanner.run_scan()

    def generate_scan_reports(self) -> bool:
        """Aggregate results into JSON/CSV/SARIF for dashboard & CI/CD."""
        # Run all scans
        scan_results = {
            'sast': self.run_sast_scan(),
            'sca': self.run_dependency_scan(),
            'container': self.run_container_scan(),
            'iac': self.run_iac_scan(),
            'secrets': self.run_secret_scan()
        }

        return self.utils.generate_scan_reports(scan_results)

    # Attack Simulation Functions
    def simulate_sql_injection(self) -> Dict[str, Any]:
        """Offline safe SQLi simulation against Juice Shop."""
        if not self.simulator:
            self.simulator = AttackSimulator()
        return self.simulator.simulate_sql_injection()

    def simulate_xss(self) -> Dict[str, Any]:
        """Cross-site scripting attacks for testing."""
        if not self.simulator:
            self.simulator = AttackSimulator()
        return self.simulator.simulate_xss()

    def simulate_misconfigurations(self) -> Dict[str, Any]:
        """Test weak Docker/Kubernetes/IaC setups."""
        if not self.simulator:
            self.simulator = AttackSimulator()
        return self.simulator.simulate_misconfigured_permissions()

    def log_attack_results(self, results: Dict[str, Any]):
        """Save simulated attack results for reporting."""
        # Results are already logged in the simulator
        pass

    def risk_score_calculator(self, attack_results: Dict[str, Any]) -> float:
        """Assign risk levels to each simulated attack."""
        total_risk = 0
        count = 0
        for attack_type, result in attack_results.items():
            if 'risk_score' in result:
                total_risk += result['risk_score']
                count += 1
        return total_risk / max(count, 1)

    # Auto-Hardening Functions
    def update_dependencies(self) -> Dict[str, Any]:
        """Automatically upgrade vulnerable packages."""
        if not self.remediator:
            self.remediator = AutoRemediator()
        reports = self.remediator.load_scan_reports()
        return self.remediator.remediate_dependencies(reports.get('sca', {}))

    def harden_dockerfile(self) -> Dict[str, Any]:
        """Apply best practices: non-root, read-only FS, minimal image."""
        if not self.remediator:
            self.remediator = AutoRemediator()
        reports = self.remediator.load_scan_reports()
        return self.remediator.remediate_dockerfile(reports.get('container', {}))

    def harden_k8s_manifests(self) -> Dict[str, Any]:
        """Enforce security contexts, RBAC, network policies."""
        if not self.remediator:
            self.remediator = AutoRemediator()
        reports = self.remediator.load_scan_reports()
        return self.remediator.remediate_kubernetes(reports.get('iac', {}))

    def remediate_iac_issues(self) -> Dict[str, Any]:
        """Fix insecure Terraform configs."""
        # This is handled in harden_k8s_manifests for now
        return self.harden_k8s_manifests()

    def verify_remediation(self) -> Dict[str, Any]:
        """Re-run scans to confirm vulnerabilities are gone."""
        if not self.remediator:
            self.remediator = AutoRemediator()
        return self.remediator.test_remediation_sandbox()

    # Self-Learning / Predictive Functions
    def train_risk_model(self) -> bool:
        """Learn from past scan & attack results offline."""
        return self.self_learning.train_risk_model()

    def predict_new_threats(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify potential risk patterns in unseen code/configs."""
        return self.self_learning.predict_new_threats(scan_data)

    def update_model(self, new_scan_data: Dict[str, Any]):
        """Incrementally update ML model with new results."""
        self.self_learning.update_model(new_scan_data)

    def anomaly_detection(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect abnormal patterns in system behavior."""
        return self.self_learning.anomaly_detection(scan_data)

    # Dashboard / Visualization Functions
    def start_dashboard_server(self):
        """Start Flask/FastAPI backend."""
        import subprocess
        self.dashboard_process = subprocess.Popen([sys.executable, 'dashboard/app.py'])
        self.utils.log_event('INFO', 'Dashboard server started')

    def load_scan_data(self):
        """Load JSON/CSV/SARIF scan results."""
        # This is handled in the dashboard app
        pass

    def render_attack_map(self):
        """Visualize attacks on a heatmap."""
        # This is handled in the dashboard frontend
        pass

    def display_risk_overview(self):
        """Show vulnerability levels & trends."""
        # This is handled in the dashboard
        pass

    def update_dashboard(self):
        """Refresh frontend dynamically."""
        # This is handled automatically in the dashboard
        pass

    # CI/CD & Automation Functions
    def build_container(self) -> bool:
        """Build Docker image from hardened Dockerfile."""
        try:
            import subprocess
            result = subprocess.run(['docker', 'build', '-t', 'quantumguard-app:latest', './docker'],
                                  capture_output=True, text=True, timeout=600)
            return result.returncode == 0
        except Exception as e:
            self.utils.handle_errors('build_container', e)
            return False

    def deploy_k8s_cluster(self) -> bool:
        """Deploy manifests to local minikube or kind."""
        try:
            import subprocess
            result = subprocess.run(['kubectl', 'apply', '-f', 'k8s/'],
                                  capture_output=True, text=True, timeout=300)
            return result.returncode == 0
        except Exception as e:
            self.utils.handle_errors('deploy_k8s_cluster', e)
            return False

    def run_ci_pipeline(self) -> bool:
        """Automate scanning, simulation, and remediation."""
        try:
            # Run scans
            scan_success = self.generate_scan_reports()

            # Run simulations
            simulations = {
                'sql_injection': self.simulate_sql_injection(),
                'xss': self.simulate_xss(),
                'misconfigurations': self.simulate_misconfigurations()
            }

            # Calculate overall risk
            overall_risk = self.risk_score_calculator(simulations)

            # Auto-remediate if risk is high
            if overall_risk > 7.0:
                self.update_dependencies()
                self.harden_dockerfile()
                self.harden_k8s_manifests()

            # Update learning model
            combined_data = {
                'scan_results': scan_success,
                'attack_simulations': simulations,
                'overall_risk_score': overall_risk
            }
            self.update_model(combined_data)

            return True

        except Exception as e:
            self.utils.handle_errors('run_ci_pipeline', e)
            return False

    def fail_on_critical_vuln(self, scan_results: Dict[str, Any]) -> bool:
        """Stop pipeline if HIGH/CRITICAL issues found."""
        for scan_type, result in scan_results.items():
            if isinstance(result, dict) and result.get('overall_risk_score', 0) >= 7.0:
                self.utils.log_event('ERROR', f'Critical vulnerability found in {scan_type}')
                return True
        return False

    def archive_reports(self) -> bool:
        """Save reports as artifacts for review."""
        try:
            import shutil
            archive_dir = Path('artifacts')
            archive_dir.mkdir(exist_ok=True)

            # Copy reports
            if Path('reports').exists():
                shutil.copytree('reports', archive_dir / 'reports', dirs_exist_ok=True)

            # Create timestamped archive
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            archive_name = f'quantumguard_report_{timestamp}'
            shutil.make_archive(archive_name, 'zip', archive_dir)

            self.utils.log_event('INFO', f'Reports archived as {archive_name}.zip')
            return True

        except Exception as e:
            self.utils.handle_errors('archive_reports', e)
            return False

    # Utility / Helper Functions
    def check_internet(self) -> bool:
        """Optional — ensure network available for updates."""
        return self.utils.check_internet()

    def log_event(self, level: str, message: str, extra_data: Optional[Dict] = None):
        """Centralized logging of actions, errors, results."""
        self.utils.log_event(level, message, extra_data)

    def handle_errors(self, func_name: str, error: Exception, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Robust error handling for all scripts."""
        return self.utils.handle_errors(func_name, error, context)

    def cleanup_temp_files(self) -> bool:
        """Remove temporary files after execution."""
        return self.utils.cleanup_temp_files()

    def system_status(self) -> Dict[str, Any]:
        """Print RAM, CPU, disk usage for monitoring."""
        return self.utils.system_status()

    # Main orchestration methods
    def initialize_system(self) -> bool:
        """Complete system initialization."""
        self.log_event('INFO', 'Initializing QuantumGuard system...')

        # Check prerequisites
        prereqs = self.check_prerequisites()
        if not all(prereqs.values()):
            missing = [tool for tool, available in prereqs.items() if not available]
            self.log_event('ERROR', f'Missing prerequisites: {missing}')
            return False

        # Prepare environment
        if not self.prepare_environment():
            return False

        # Train initial model
        if not self.train_risk_model():
            self.log_event('WARNING', 'Could not train initial risk model')

        self.log_event('INFO', 'QuantumGuard system initialized successfully')
        return True

    def run_full_security_assessment(self) -> Dict[str, Any]:
        """Run complete security assessment pipeline."""
        self.log_event('INFO', 'Starting full security assessment...')

        results = {}

        # Run all scans
        results['scans'] = {
            'sast': self.run_sast_scan(),
            'sca': self.run_dependency_scan(),
            'container': self.run_container_scan(),
            'iac': self.run_iac_scan(),
            'secrets': self.run_secret_scan()
        }

        # Run attack simulations
        results['simulations'] = {
            'sql_injection': self.simulate_sql_injection(),
            'xss': self.simulate_xss(),
            'misconfigurations': self.simulate_misconfigurations()
        }

        # Calculate overall risk
        results['overall_risk'] = self.risk_score_calculator(results['simulations'])

        # Check for critical vulnerabilities
        results['critical_found'] = self.fail_on_critical_vuln(results['scans'])

        # Generate reports
        self.generate_scan_reports()

        # Update learning model
        self.update_model(results)

        self.log_event('INFO', f'Security assessment completed. Overall risk: {results["overall_risk"]:.2f}')
        return results

    def run_automated_hardening(self) -> Dict[str, Any]:
        """Run complete automated hardening process."""
        self.log_event('INFO', 'Starting automated hardening...')

        results = {}

        # Load current scan reports
        if not self.remediator:
            self.remediator = AutoRemediator()

        # Apply remediations
        results['dependency_updates'] = self.update_dependencies()
        results['docker_hardening'] = self.harden_dockerfile()
        results['k8s_hardening'] = self.harden_k8s_manifests()

        # Verify remediations
        results['verification'] = self.verify_remediation()

        # Archive results
        self.archive_reports()

        self.log_event('INFO', 'Automated hardening completed')
        return results

    def start_interactive_mode(self):
        """Start interactive dashboard mode."""
        self.log_event('INFO', 'Starting interactive dashboard mode...')

        # Start dashboard
        self.start_dashboard_server()

        # Deploy vulnerable app if not already deployed
        if not self.deploy_vulnerable_app():
            self.log_event('WARNING', 'Could not deploy vulnerable app')

        print("\n" + "="*60)
        print("QUANTUMGUARD CYBER DEFENSE SIMULATOR")
        print("="*60)
        print("Dashboard available at: http://localhost:5000")
        print("Vulnerable app at: http://localhost:3000")
        print("\nAvailable commands:")
        print("  scan        - Run security scans")
        print("  simulate    - Run attack simulations")
        print("  harden      - Run auto-hardening")
        print("  assess      - Run full assessment")
        print("  status      - Show system status")
        print("  exit        - Exit interactive mode")
        print("="*60)

        while True:
            try:
                cmd = input("\nquantumguard> ").strip().lower()

                if cmd == 'scan':
                    results = self.generate_scan_reports()
                    print(f"Scans completed: {results}")

                elif cmd == 'simulate':
                    results = self.run_full_security_assessment()
                    print(f"Simulations completed. Risk: {results.get('overall_risk', 0):.2f}")

                elif cmd == 'harden':
                    results = self.run_automated_hardening()
                    print(f"Hardening completed: {len(results)} phases")

                elif cmd == 'assess':
                    results = self.run_full_security_assessment()
                    print(f"Assessment completed. Risk: {results.get('overall_risk', 0):.2f}")

                elif cmd == 'status':
                    status = self.system_status()
                    print(f"CPU: {status.get('cpu_percent', 0)}%")
                    print(f"Memory: {status.get('memory', {}).get('percent', 0)}%")
                    print(f"Disk: {status.get('disk', {}).get('percent', 0)}%")

                elif cmd == 'exit':
                    break

                else:
                    print("Unknown command. Type 'help' for available commands.")

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")

        self.log_event('INFO', 'Interactive mode exited')

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='QuantumGuard Cyber Defense Simulator')
    parser.add_argument('command', nargs='?', default='interactive',
                       choices=['init', 'scan', 'simulate', 'harden', 'assess', 'dashboard', 'interactive'],
                       help='Command to run')
    parser.add_argument('--config', help='Configuration file path')

    args = parser.parse_args()

    qg = QuantumGuard()

    if args.command == 'init':
        success = qg.initialize_system()
        sys.exit(0 if success else 1)

    elif args.command == 'scan':
        results = qg.generate_scan_reports()
        print("Scan reports generated:", results)

    elif args.command == 'simulate':
        results = qg.run_full_security_assessment()
        print(f"Assessment completed. Risk: {results.get('overall_risk', 0):.2f}")

    elif args.command == 'harden':
        results = qg.run_automated_hardening()
        print("Hardening completed:", results)

    elif args.command == 'assess':
        results = qg.run_full_security_assessment()
        print(f"Full assessment completed. Risk: {results.get('overall_risk', 0):.2f}")

    elif args.command == 'dashboard':
        qg.start_dashboard_server()
        print("Dashboard started at http://localhost:5000")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    elif args.command == 'interactive':
        if not qg.initialize_system():
            sys.exit(1)
        qg.start_interactive_mode()

if __name__ == "__main__":
    main()
