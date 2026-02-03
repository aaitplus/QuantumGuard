#!/usr/bin/env python3
"""
QuantumGuard: Auto-Hardening & Remediation Engine
Automatically fixes detected vulnerabilities based on scan reports.
Supports rollback and sandbox testing.
"""

import subprocess
import json
import os
import sys
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
import docker
from docker.errors import DockerException

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/auto_remediation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AutoRemediator:
    def __init__(self, reports_dir: str = "reports", backup_dir: str = "data/backups"):
        self.reports_dir = Path(reports_dir)
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.docker_client = None
        self.rollback_stack = []

    def initialize_docker(self) -> bool:
        """Initialize Docker client for sandbox testing."""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            logger.info("Docker client initialized for remediation")
            return True
        except DockerException as e:
            logger.error(f"Failed to initialize Docker: {e}")
            return False

    def load_scan_reports(self) -> Dict[str, Any]:
        """Load and aggregate all scan reports."""
        reports = {}

        # Load processed reports
        report_files = {
            "sast": "sast-processed.json",
            "sca": "sca-processed.json",
            "container": "container-processed.json",
            "iac": "iac-processed.json"
        }

        for scan_type, filename in report_files.items():
            report_path = self.reports_dir / filename
            if report_path.exists():
                try:
                    with open(report_path, 'r') as f:
                        reports[scan_type] = json.load(f)
                    logger.info(f"Loaded {scan_type} report")
                except json.JSONDecodeError as e:
                    logger.error(f"Error loading {scan_type} report: {e}")
            else:
                logger.warning(f"{scan_type} report not found")

        return reports

    def create_backup(self, file_path: str) -> Optional[str]:
        """Create backup of file before modification."""
        if not Path(file_path).exists():
            return None

        timestamp = str(int(time.time()))
        backup_name = f"{Path(file_path).name}.{timestamp}.bak"
        backup_path = self.backup_dir / backup_name

        try:
            shutil.copy2(file_path, backup_path)
            self.rollback_stack.append({
                "original_path": file_path,
                "backup_path": str(backup_path),
                "timestamp": timestamp
            })
            logger.info(f"Backup created: {backup_path}")
            return str(backup_path)
        except Exception as e:
            logger.error(f"Failed to create backup for {file_path}: {e}")
            return None

    def remediate_dependencies(self, sca_report: Dict[str, Any]) -> Dict[str, Any]:
        """Remediate vulnerable dependencies."""
        logger.info("Starting dependency remediation...")

        if not sca_report:
            return {"status": "skipped", "reason": "No SCA report available"}

        # Find requirements.txt or similar
        dep_files = ["requirements.txt", "package.json", "pom.xml", "build.gradle"]

        updates_made = []
        for dep_file in dep_files:
            if Path(dep_file).exists():
                self.create_backup(dep_file)

                if dep_file == "requirements.txt":
                    updates = self.update_requirements_txt(sca_report)
                    updates_made.extend(updates)
                elif dep_file == "package.json":
                    updates = self.update_package_json(sca_report)
                    updates_made.extend(updates)

        return {
            "status": "completed",
            "updates_made": updates_made,
            "files_modified": len(updates_made)
        }

    def update_requirements_txt(self, sca_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Update requirements.txt with secure versions."""
        updates = []

        try:
            with open("requirements.txt", 'r') as f:
                lines = f.readlines()

            updated_lines = []
            for line in lines:
                original_line = line.strip()
                if "==" in original_line:
                    package, version = original_line.split("==", 1)
                    # Check if this package has vulnerabilities
                    for vuln in sca_report.get("vulnerabilities", []):
                        if vuln["pkg_name"].lower() == package.lower():
                            if vuln.get("fixed_version"):
                                new_line = f"{package}=={vuln['fixed_version']}\n"
                                updated_lines.append(new_line)
                                updates.append({
                                    "file": "requirements.txt",
                                    "package": package,
                                    "old_version": version,
                                    "new_version": vuln["fixed_version"]
                                })
                                logger.info(f"Updated {package} from {version} to {vuln['fixed_version']}")
                                break
                    else:
                        updated_lines.append(line)
                else:
                    updated_lines.append(line)

            with open("requirements.txt", 'w') as f:
                f.writelines(updated_lines)

        except Exception as e:
            logger.error(f"Error updating requirements.txt: {e}")

        return updates

    def update_package_json(self, sca_report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Update package.json with secure versions."""
        updates = []

        try:
            with open("package.json", 'r') as f:
                data = json.load(f)

            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        # Check for vulnerabilities (simplified check)
                        for vuln in sca_report.get("vulnerabilities", []):
                            if vuln["pkg_name"].lower() in package.lower():
                                if vuln.get("fixed_version"):
                                    data[dep_type][package] = f"^{vuln['fixed_version']}"
                                    updates.append({
                                        "file": "package.json",
                                        "package": package,
                                        "old_version": version,
                                        "new_version": f"^{vuln['fixed_version']}"
                                    })
                                    logger.info(f"Updated {package} to {vuln['fixed_version']}")

            with open("package.json", 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.error(f"Error updating package.json: {e}")

        return updates

    def remediate_dockerfile(self, container_report: Dict[str, Any]) -> Dict[str, Any]:
        """Remediate Dockerfile security issues."""
        logger.info("Starting Dockerfile remediation...")

        dockerfile_path = "docker/Dockerfile"
        if not Path(dockerfile_path).exists():
            return {"status": "skipped", "reason": "Dockerfile not found"}

        self.create_backup(dockerfile_path)

        try:
            with open(dockerfile_path, 'r') as f:
                lines = f.readlines()

            updated_lines = []
            changes_made = []

            for line in lines:
                # Remove USER root if present
                if line.strip().startswith("USER root"):
                    updated_lines.append("USER appuser\n")
                    changes_made.append("Changed USER from root to appuser")
                    continue

                # Add security headers
                if line.strip().startswith("FROM"):
                    updated_lines.append(line)
                    updated_lines.append("RUN apt-get update && apt-get install -y --no-install-recommends \\\n")
                    updated_lines.append("    && rm -rf /var/lib/apt/lists/*\n")
                    changes_made.append("Added package cleanup")
                    continue

                # Add non-root user
                if line.strip().startswith("COPY") and "appuser" not in "".join(updated_lines[-5:]):
                    updated_lines.append("RUN useradd --create-home --shell /bin/bash appuser\n")
                    changes_made.append("Added non-root user creation")

                updated_lines.append(line)

            with open(dockerfile_path, 'w') as f:
                f.writelines(updated_lines)

            return {
                "status": "completed",
                "changes_made": changes_made,
                "file_modified": dockerfile_path
            }

        except Exception as e:
            logger.error(f"Error remediating Dockerfile: {e}")
            return {"status": "failed", "error": str(e)}

    def remediate_kubernetes(self, iac_report: Dict[str, Any]) -> Dict[str, Any]:
        """Remediate Kubernetes manifests."""
        logger.info("Starting Kubernetes remediation...")

        k8s_dir = Path("k8s")
        if not k8s_dir.exists():
            return {"status": "skipped", "reason": "Kubernetes manifests not found"}

        changes_made = []

        for yaml_file in k8s_dir.glob("*.yaml"):
            self.create_backup(str(yaml_file))

            try:
                with open(yaml_file, 'r') as f:
                    content = f.read()

                # Add security contexts
                if "spec:" in content and "securityContext:" not in content:
                    # Insert security context after spec
                    content = content.replace(
                        "spec:",
                        "spec:\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 1000",
                        1
                    )
                    changes_made.append(f"Added security context to {yaml_file}")

                # Add network policies
                if "kind: Deployment" in content and not (k8s_dir / "network-policy.yaml").exists():
                    self.create_network_policy(k8s_dir)
                    changes_made.append("Created network policy")

                with open(yaml_file, 'w') as f:
                    f.write(content)

            except Exception as e:
                logger.error(f"Error remediating {yaml_file}: {e}")

        return {
            "status": "completed",
            "changes_made": changes_made,
            "files_modified": len(changes_made)
        }

    def create_network_policy(self, k8s_dir: Path):
        """Create a basic network policy."""
        policy = """
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-internal
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
"""
        with open(k8s_dir / "network-policy.yaml", 'w') as f:
            f.write(policy)

    def test_remediation_sandbox(self) -> Dict[str, Any]:
        """Test remediation changes in sandbox environment."""
        logger.info("Testing remediation in sandbox...")

        if not self.docker_client:
            return {"status": "skipped", "reason": "Docker not available"}

        try:
            # Build test image
            image, build_logs = self.docker_client.images.build(
                path=".",
                dockerfile="docker/Dockerfile",
                tag="quantumguard-test:latest"
            )

            # Run basic security tests
            container = self.docker_client.containers.run(
                "quantumguard-test:latest",
                command="whoami",
                detach=False,
                remove=True
            )

            result = container.decode() if isinstance(container, bytes) else str(container)

            if "root" in result:
                return {"status": "failed", "reason": "Container still running as root"}
            else:
                return {"status": "passed", "message": "Sandbox test successful"}

        except DockerException as e:
            logger.error(f"Sandbox test failed: {e}")
            return {"status": "failed", "error": str(e)}

    def rollback_changes(self) -> Dict[str, Any]:
        """Rollback all changes made during remediation."""
        logger.info("Starting rollback process...")

        rolled_back = []
        failed_rollbacks = []

        for backup_info in reversed(self.rollback_stack):
            try:
                shutil.copy2(backup_info["backup_path"], backup_info["original_path"])
                rolled_back.append(backup_info["original_path"])
                logger.info(f"Rolled back {backup_info['original_path']}")
            except Exception as e:
                failed_rollbacks.append({
                    "file": backup_info["original_path"],
                    "error": str(e)
                })
                logger.error(f"Failed to rollback {backup_info['original_path']}: {e}")

        return {
            "status": "completed",
            "rolled_back": rolled_back,
            "failed_rollbacks": failed_rollbacks
        }

    def run_full_remediation(self) -> Dict[str, Any]:
        """Run complete auto-remediation process."""
        logger.info("Starting full auto-remediation process...")

        reports = self.load_scan_reports()

        remediation_results = {
            "timestamp": time.time(),
            "phases": {}
        }

        # Phase 1: Dependency updates
        if "sca" in reports:
            remediation_results["phases"]["dependencies"] = self.remediate_dependencies(reports["sca"])

        # Phase 2: Dockerfile hardening
        if "container" in reports:
            remediation_results["phases"]["dockerfile"] = self.remediate_dockerfile(reports["container"])

        # Phase 3: Kubernetes security
        if "iac" in reports:
            remediation_results["phases"]["kubernetes"] = self.remediate_kubernetes(reports["iac"])

        # Phase 4: Sandbox testing
        remediation_results["phases"]["sandbox_test"] = self.test_remediation_sandbox()

        # Save remediation report
        report_path = self.reports_dir / "remediation-report.json"
        with open(report_path, 'w') as f:
            json.dump(remediation_results, f, indent=2)

        logger.info(f"Remediation report saved to {report_path}")
        return remediation_results

def main():
    """Main entry point."""
    remediator = AutoRemediator()

    if not remediator.initialize_docker():
        logger.warning("Docker not available. Sandbox testing will be skipped.")

    results = remediator.run_full_remediation()

    logger.info("Auto-remediation process completed")
    print(json.dumps(results, indent=2))

    # Ask user if they want to rollback
    response = input("Do you want to rollback changes? (y/N): ").strip().lower()
    if response == 'y':
        rollback_results = remediator.rollback_changes()
        print("Rollback completed:", json.dumps(rollback_results, indent=2))

if __name__ == "__main__":
    main()
