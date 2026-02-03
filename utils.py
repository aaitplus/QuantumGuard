#!/usr/bin/env python3
"""
QuantumGuard: Utility Functions
Helper functions for system operations, logging, error handling, and monitoring.
"""

import os
import sys
import logging
import shutil
import psutil
import socket
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import json
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class QuantumGuardUtils:
    def __init__(self):
        self.start_time = time.time()

    def check_prerequisites(self) -> Dict[str, bool]:
        """Validate system dependencies."""
        prerequisites = {
            'python': self._check_python(),
            'nodejs': self._check_nodejs(),
            'docker': self._check_docker(),
            'terraform': self._check_terraform(),
            'kubectl': self._check_kubectl(),
            'semgrep': self._check_semgrep(),
            'trivy': self._check_trivy(),
            'tfsec': self._check_tfsec(),
            'dependency_check': self._check_dependency_check()
        }

        logger.info("Prerequisites check completed:")
        for tool, available in prerequisites.items():
            status = "✓" if available else "✗"
            logger.info(f"  {status} {tool}")

        return prerequisites

    def _check_python(self) -> bool:
        """Check Python version."""
        try:
            import sys
            version = sys.version_info
            return version >= (3, 9)
        except:
            return False

    def _check_nodejs(self) -> bool:
        """Check Node.js installation."""
        try:
            import subprocess
            result = subprocess.run(['node', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0 and 'v18' in result.stdout
        except:
            return False

    def _check_docker(self) -> bool:
        """Check Docker installation and daemon."""
        try:
            import subprocess
            result = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except:
            return False

    def _check_terraform(self) -> bool:
        """Check Terraform installation."""
        try:
            import subprocess
            result = subprocess.run(['terraform', 'version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_kubectl(self) -> bool:
        """Check kubectl installation."""
        try:
            import subprocess
            result = subprocess.run(['kubectl', 'version', '--client'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_semgrep(self) -> bool:
        """Check Semgrep installation."""
        try:
            import subprocess
            result = subprocess.run(['semgrep', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_trivy(self) -> bool:
        """Check Trivy installation."""
        try:
            import subprocess
            result = subprocess.run(['trivy', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_tfsec(self) -> bool:
        """Check tfsec installation."""
        try:
            import subprocess
            result = subprocess.run(['tfsec', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _check_dependency_check(self) -> bool:
        """Check OWASP Dependency-Check installation."""
        try:
            import subprocess
            result = subprocess.run(['dependency-check', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def prepare_environment(self) -> bool:
        """Create folders and clean old logs."""
        try:
            directories = [
                'data',
                'reports',
                'data/models',
                'data/backups',
                'dashboard/static/css',
                'dashboard/static/js',
                'dashboard/templates'
            ]

            for dir_path in directories:
                Path(dir_path).mkdir(parents=True, exist_ok=True)
                logger.info(f"Created directory: {dir_path}")

            # Clean old log files (>30 days)
            self._cleanup_old_logs()

            # Initialize local storage
            self._initialize_storage()

            logger.info("Environment preparation completed")
            return True

        except Exception as e:
            logger.error(f"Error preparing environment: {e}")
            return False

    def _cleanup_old_logs(self):
        """Remove log files older than 30 days."""
        try:
            log_files = Path('data').glob('*.log')
            cutoff_time = time.time() - (30 * 24 * 60 * 60)  # 30 days

            for log_file in log_files:
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logger.info(f"Removed old log file: {log_file}")

        except Exception as e:
            logger.warning(f"Error cleaning old logs: {e}")

    def _initialize_storage(self):
        """Initialize local databases or storage."""
        try:
            # Create empty historical data file if it doesn't exist
            historical_file = Path('data/historical_scans.json')
            if not historical_file.exists():
                with open(historical_file, 'w') as f:
                    json.dump([], f)
                logger.info("Initialized historical data storage")

            # Create empty config file
            config_file = Path('data/config.json')
            if not config_file.exists():
                default_config = {
                    'app_name': 'QuantumGuard',
                    'version': '1.0.0',
                    'scan_interval': 3600,
                    'risk_threshold': 7.0,
                    'auto_remediation': True,
                    'theme': 'cyberpunk'
                }
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logger.info("Initialized configuration file")

        except Exception as e:
            logger.error(f"Error initializing storage: {e}")

    def check_internet(self) -> bool:
        """Check internet connectivity."""
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except OSError:
            return False

    def log_event(self, level: str, message: str, extra_data: Optional[Dict] = None):
        """Centralized logging of actions, errors, results."""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'level': level.upper(),
            'message': message,
            'extra': extra_data or {}
        }

        # Log to console
        if level.upper() == 'ERROR':
            logger.error(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        else:
            logger.info(message)

        # Save to structured log file
        try:
            log_file = Path('data/events.log')
            with open(log_file, 'a') as f:
                json.dump(log_data, f)
                f.write('\n')
        except Exception as e:
            logger.error(f"Error writing to event log: {e}")

    def handle_errors(self, func_name: str, error: Exception, context: Optional[Dict] = None) -> Dict[str, Any]:
        """Robust error handling for all scripts."""
        error_info = {
            'function': func_name,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now().isoformat(),
            'context': context or {}
        }

        self.log_event('ERROR', f"Error in {func_name}: {error}", error_info)

        # Attempt recovery based on error type
        if isinstance(error, FileNotFoundError):
            return {'status': 'retry', 'message': 'File not found, check paths'}
        elif isinstance(error, PermissionError):
            return {'status': 'retry', 'message': 'Permission denied, check access rights'}
        elif isinstance(error, ConnectionError):
            return {'status': 'retry', 'message': 'Connection failed, check network'}
        else:
            return {'status': 'failed', 'message': str(error)}

    def cleanup_temp_files(self) -> bool:
        """Remove temporary files after execution."""
        try:
            temp_patterns = ['*.tmp', '*.temp', 'temp_*', '*.bak']
            cleaned_count = 0

            for pattern in temp_patterns:
                for temp_file in Path('.').glob(pattern):
                    if temp_file.is_file():
                        temp_file.unlink()
                        cleaned_count += 1

            # Clean temp directories
            temp_dirs = ['.tmp', 'temp', '__pycache__']
            for temp_dir in temp_dirs:
                temp_path = Path(temp_dir)
                if temp_path.exists() and temp_path.is_dir():
                    shutil.rmtree(temp_path)
                    cleaned_count += 1

            logger.info(f"Cleaned up {cleaned_count} temporary files/directories")
            return True

        except Exception as e:
            logger.error(f"Error cleaning temporary files: {e}")
            return False

    def system_status(self) -> Dict[str, Any]:
        """Print RAM, CPU, disk usage for monitoring."""
        try:
            status = {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                },
                'uptime': time.time() - psutil.boot_time(),
                'quantumguard_runtime': time.time() - self.start_time
            }

            logger.info("System Status:")
            logger.info(f"  CPU: {status['cpu_percent']}%")
            logger.info(f"  Memory: {status['memory']['percent']}% used")
            logger.info(f"  Disk: {status['disk']['percent']}% used")
            logger.info(f"  Uptime: {status['uptime']:.0f} seconds")

            return status

        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'error': str(e)}

    def deploy_vulnerable_app(self) -> bool:
        """Deploy OWASP Juice Shop with theme."""
        try:
            import subprocess

            # Clone repository
            if not Path('juice-shop').exists():
                self.log_event('INFO', 'Cloning OWASP Juice Shop')
                result = subprocess.run(['git', 'clone', 'https://github.com/juice-shop/juice-shop.git'],
                                      capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    raise Exception(f"Git clone failed: {result.stderr}")

            # Apply theme
            self.apply_theme()

            # Build and run Docker container
            self.log_event('INFO', 'Building Docker container')
            result = subprocess.run(['docker', 'build', '-t', 'quantumguard-app', './docker'],
                                  capture_output=True, text=True, timeout=600)
            if result.returncode != 0:
                raise Exception(f"Docker build failed: {result.stderr}")

            self.log_event('INFO', 'Starting application container')
            result = subprocess.run(['docker', 'run', '-d', '--name', 'quantumguard-app',
                                   '-p', '3000:3000', 'quantumguard-app'],
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                raise Exception(f"Docker run failed: {result.stderr}")

            self.log_event('INFO', 'Vulnerable application deployed successfully')
            return True

        except Exception as e:
            self.handle_errors('deploy_vulnerable_app', e)
            return False

    def apply_theme(self) -> bool:
        """Apply cyberpunk purple hacker-style frontend."""
        try:
            juice_shop_path = Path('juice-shop')
            theme_file = Path('app/custom-theme.css')

            if not juice_shop_path.exists():
                raise FileNotFoundError("Juice Shop directory not found")

            if not theme_file.exists():
                raise FileNotFoundError("Theme file not found")

            # Copy theme to Juice Shop
            dest_theme = juice_shop_path / 'public' / 'custom-theme.css'
            dest_theme.parent.mkdir(exist_ok=True)
            shutil.copy2(theme_file, dest_theme)

            # Inject theme into HTML
            index_file = juice_shop_path / 'src' / 'index.html'
            if index_file.exists():
                with open(index_file, 'r') as f:
                    content = f.read()

                if 'custom-theme.css' not in content:
                    # Insert theme link before closing head
                    theme_link = '<link rel="stylesheet" href="custom-theme.css">'
                    content = content.replace('</head>', f'{theme_link}\n</head>')

                    with open(index_file, 'w') as f:
                        f.write(content)

            self.log_event('INFO', 'Cyberpunk theme applied successfully')
            return True

        except Exception as e:
            self.handle_errors('apply_theme', e)
            return False

    def run_secret_scan(self) -> Dict[str, Any]:
        """Detect secrets or credentials in the code using Gitleaks."""
        try:
            import subprocess

            if not self._check_gitleaks():
                return {'error': 'Gitleaks not installed'}

            result = subprocess.run(['gitleaks', 'detect', '--verbose', '--redact'],
                                  capture_output=True, text=True, timeout=300)

            findings = []
            if result.returncode == 1:  # Gitleaks returns 1 when secrets found
                # Parse output (simplified)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'secret=' in line:
                        findings.append({'line': line.strip()})

            return {
                'secrets_found': len(findings),
                'findings': findings,
                'scan_completed': True
            }

        except Exception as e:
            return self.handle_errors('run_secret_scan', e)

    def _check_gitleaks(self) -> bool:
        """Check Gitleaks installation."""
        try:
            import subprocess
            result = subprocess.run(['gitleaks', 'version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def generate_scan_reports(self, scan_results: Dict[str, Any]) -> bool:
        """Aggregate results into JSON/CSV/SARIF for dashboard & CI/CD."""
        try:
            # Generate JSON report
            json_report = Path('reports/combined-report.json')
            with open(json_report, 'w') as f:
                json.dump(scan_results, f, indent=2)

            # Generate CSV summary
            csv_report = Path('reports/scan-summary.csv')
            with open(csv_report, 'w') as f:
                f.write("Scan Type,Risk Score,Findings,Vulnerabilities\n")
                for scan_type, data in scan_results.items():
                    if isinstance(data, dict):
                        risk = data.get('overall_risk_score', 0)
                        findings = data.get('total_findings', 0)
                        vulns = data.get('total_vulnerabilities', 0)
                        f.write(f"{scan_type},{risk},{findings},{vulns}\n")

            # Generate SARIF report (simplified)
            sarif_report = Path('reports/scan-results.sarif')
            sarif_data = self._generate_sarif(scan_results)
            with open(sarif_report, 'w') as f:
                json.dump(sarif_data, f, indent=2)

            self.log_event('INFO', 'Scan reports generated successfully')
            return True

        except Exception as e:
            self.handle_errors('generate_scan_reports', e)
            return False

    def _generate_sarif(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SARIF format report."""
        runs = []

        for scan_type, data in scan_results.items():
            if isinstance(data, dict) and 'findings' in data:
                results = []
                for finding in data['findings'][:100]:  # Limit for performance
                    result = {
                        "ruleId": finding.get('rule_id', 'unknown'),
                        "level": finding.get('severity', 'warning').lower(),
                        "message": {
                            "text": finding.get('message', '')
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": finding.get('file', '')
                                },
                                "region": {
                                    "startLine": finding.get('line', 1)
                                }
                            }
                        }]
                    }
                    results.append(result)

                run = {
                    "tool": {
                        "driver": {
                            "name": f"QuantumGuard {scan_type.upper()}",
                            "version": "1.0.0"
                        }
                    },
                    "results": results
                }
                runs.append(run)

        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": runs
        }

def main():
    """Main entry point for testing utilities."""
    utils = QuantumGuardUtils()

    print("=== QuantumGuard System Utilities ===\n")

    # Check prerequisites
    print("Checking prerequisites...")
    prereqs = utils.check_prerequisites()
    print(f"Prerequisites met: {sum(prereqs.values())}/{len(prereqs)}\n")

    # Prepare environment
    print("Preparing environment...")
    env_ready = utils.prepare_environment()
    print(f"Environment ready: {env_ready}\n")

    # System status
    print("System status:")
    status = utils.system_status()
    if 'cpu_percent' in status:
        print(f"CPU: {status['cpu_percent']}%")
        print(f"Memory: {status['memory']['percent']}% used")
        print(f"Disk: {status['disk']['percent']}% used\n")

    # Cleanup
    print("Cleaning up temporary files...")
    cleaned = utils.cleanup_temp_files()
    print(f"Cleanup successful: {cleaned}")

if __name__ == "__main__":
    main()
