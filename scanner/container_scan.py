#!/usr/bin/env python3
"""
QuantumGuard: Container Scanner using Trivy
Performs container image vulnerability scanning.
Generates JSON report with findings and risk scores.
"""

import subprocess
import json
import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/container_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ContainerScanner:
    def __init__(self, image_name: str = "quantumguard-app", reports_dir: str = "reports"):
        self.image_name = image_name
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.report_path = self.reports_dir / "container-report.json"

    def check_prerequisites(self) -> bool:
        """Check if Trivy is installed."""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Trivy version: {result.stdout.strip()}")
                return True
            else:
                logger.error("Trivy not found or not working.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error checking Trivy: {e}")
            return False

    def check_docker_image(self) -> bool:
        """Check if Docker image exists."""
        try:
            result = subprocess.run(
                ["docker", "images", "-q", self.image_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                logger.info(f"Docker image {self.image_name} found.")
                return True
            else:
                logger.warning(f"Docker image {self.image_name} not found.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error checking Docker image: {e}")
            return False

    def run_scan(self) -> Dict[str, Any]:
        """Run container scan using Trivy."""
        if not self.check_prerequisites():
            return {"error": "Prerequisites not met"}

        if not self.check_docker_image():
            return {"error": f"Docker image {self.image_name} not found"}

        try:
            # Run Trivy scan
            cmd = [
                "trivy",
                "image",
                "--format", "json",
                "--output", str(self.report_path),
                "--no-progress",
                "--timeout", "10m",
                self.image_name
            ]

            logger.info(f"Running container scan on {self.image_name}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )

            if result.returncode == 0:
                logger.info("Container scan completed successfully.")
                return self.process_results()
            else:
                logger.error(f"Container scan failed: {result.stderr}")
                return {"error": f"Scan failed: {result.stderr}"}

        except subprocess.TimeoutExpired:
            logger.error("Container scan timed out.")
            return {"error": "Scan timed out"}
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return {"error": str(e)}

    def process_results(self) -> Dict[str, Any]:
        """Process and enhance scan results with risk scoring."""
        try:
            if not self.report_path.exists():
                return {"error": "Report file not generated"}

            with open(self.report_path, 'r') as f:
                data = json.load(f)

            # Extract vulnerabilities
            vulnerabilities = []
            total_vulns = 0
            severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "UNKNOWN": 0}

            if isinstance(data, list) and len(data) > 0:
                results = data[0].get("Results", [])
                for result in results:
                    if "Vulnerabilities" in result:
                        for vuln in result["Vulnerabilities"]:
                            severity = vuln.get("Severity", "UNKNOWN").upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                                total_vulns += 1

                                vulnerability = {
                                    "vulnerability_id": vuln.get("VulnerabilityID", ""),
                                    "pkg_name": vuln.get("PkgName", ""),
                                    "installed_version": vuln.get("InstalledVersion", ""),
                                    "fixed_version": vuln.get("FixedVersion", ""),
                                    "severity": severity,
                                    "description": vuln.get("Description", ""),
                                    "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0),
                                    "references": vuln.get("References", []),
                                    "risk_score": self.calculate_risk_score(severity, vuln)
                                }
                                vulnerabilities.append(vulnerability)

            # Calculate overall risk score
            overall_risk = self.calculate_overall_risk(severity_counts, total_vulns)

            processed_data = {
                "scan_type": "Container",
                "tool": "Trivy",
                "target": self.image_name,
                "timestamp": data[0].get("CreatedAt", "") if isinstance(data, list) and len(data) > 0 else "",
                "total_vulnerabilities": total_vulns,
                "severity_breakdown": severity_counts,
                "overall_risk_score": overall_risk,
                "vulnerabilities": vulnerabilities[:100],  # Limit to top 100
                "recommendations": self.generate_recommendations(severity_counts)
            }

            # Save processed results
            processed_path = self.reports_dir / "container-processed.json"
            with open(processed_path, 'w') as f:
                json.dump(processed_data, f, indent=2)

            logger.info(f"Processed container results saved to {processed_path}")
            return processed_data

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON report: {e}")
            return {"error": "Invalid JSON report"}
        except Exception as e:
            logger.error(f"Error processing results: {e}")
            return {"error": str(e)}

    def calculate_risk_score(self, severity: str, vuln: Dict) -> float:
        """Calculate risk score for individual vulnerability."""
        base_scores = {"LOW": 2.0, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 10.0, "UNKNOWN": 1.0}
        base_score = base_scores.get(severity.upper(), 1.0)

        # Adjust based on CVSS score
        cvss = vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0)
        if cvss >= 9.0:
            base_score *= 1.2
        elif cvss >= 7.0:
            base_score *= 1.1

        # Adjust if no fix available
        if not vuln.get("FixedVersion"):
            base_score *= 1.1

        return min(base_score, 10.0)

    def calculate_overall_risk(self, severity_counts: Dict, total_vulns: int) -> float:
        """Calculate overall risk score."""
        if total_vulns == 0:
            return 0.0

        weighted_score = (
            severity_counts.get("LOW", 0) * 2 +
            severity_counts.get("MEDIUM", 0) * 4 +
            severity_counts.get("HIGH", 0) * 7 +
            severity_counts.get("CRITICAL", 0) * 10 +
            severity_counts.get("UNKNOWN", 0) * 1
        )

        # Normalize and add container complexity factor
        risk_score = (weighted_score / total_vulns) * (1 + total_vulns / 20)
        return min(risk_score, 10.0)

    def generate_recommendations(self, severity_counts: Dict) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("Update base image and rebuild container immediately")
        if severity_counts.get("HIGH", 0) > 10:
            recommendations.append("Address high-severity container vulnerabilities")
        if severity_counts.get("MEDIUM", 0) > 20:
            recommendations.append("Review and update medium-risk packages")

        recommendations.append("Use minimal base images (e.g., Alpine Linux)")
        recommendations.append("Regularly scan containers in CI/CD pipeline")
        recommendations.append("Implement container image signing and SBOM")

        return recommendations

def main():
    """Main entry point."""
    scanner = ContainerScanner()
    results = scanner.run_scan()

    if "error" in results:
        logger.error(f"Scan failed: {results['error']}")
        sys.exit(1)
    else:
        logger.info(f"Scan completed. Risk score: {results.get('overall_risk_score', 0):.2f}")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
