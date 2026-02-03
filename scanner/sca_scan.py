#!/usr/bin/env python3
"""
QuantumGuard: SCA Scanner using OWASP Dependency-Check
Performs Software Composition Analysis on dependencies.
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
        logging.FileHandler('data/sca_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SCAScanner:
    def __init__(self, target_dir: str = ".", reports_dir: str = "reports"):
        self.target_dir = Path(target_dir)
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.report_path = self.reports_dir / "sca-report.json"

    def check_prerequisites(self) -> bool:
        """Check if OWASP Dependency-Check is installed."""
        try:
            result = subprocess.run(
                ["dependency-check", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"OWASP Dependency-Check version: {result.stdout.strip()}")
                return True
            else:
                logger.error("OWASP Dependency-Check not found or not working.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error checking OWASP Dependency-Check: {e}")
            return False

    def run_scan(self) -> Dict[str, Any]:
        """Run SCA scan using OWASP Dependency-Check."""
        if not self.target_dir.exists():
            logger.error(f"Target directory {self.target_dir} does not exist.")
            return {"error": "Target directory not found"}

        if not self.check_prerequisites():
            return {"error": "Prerequisites not met"}

        try:
            # Run OWASP Dependency-Check scan
            cmd = [
                "dependency-check",
                "--scan", str(self.target_dir),
                "--format", "JSON",
                "--out", str(self.report_path),
                "--nvdValidForHours", "24",  # Cache NVD data for 24 hours
                "--enableExperimental",  # Enable experimental analyzers
                "--enableRetired"  # Include retired analyzers
            ]

            logger.info(f"Running SCA scan on {self.target_dir}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )

            if result.returncode == 0:
                logger.info("SCA scan completed successfully.")
                return self.process_results()
            else:
                logger.error(f"SCA scan failed: {result.stderr}")
                return {"error": f"Scan failed: {result.stderr}"}

        except subprocess.TimeoutExpired:
            logger.error("SCA scan timed out.")
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

            # Extract dependencies and vulnerabilities
            dependencies = []
            vulnerabilities = []
            total_deps = 0
            total_vulns = 0
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

            if "dependencies" in data:
                for dep in data["dependencies"]:
                    total_deps += 1

                    dep_info = {
                        "file_name": dep.get("fileName", ""),
                        "file_path": dep.get("filePath", ""),
                        "md5": dep.get("md5", ""),
                        "sha1": dep.get("sha1", ""),
                        "sha256": dep.get("sha256", ""),
                        "evidence_collected": dep.get("evidenceCollected", {}),
                        "packages": dep.get("packages", [])
                    }
                    dependencies.append(dep_info)

                    # Process vulnerabilities for this dependency
                    if "vulnerabilities" in dep:
                        for vuln in dep["vulnerabilities"]:
                            severity = vuln.get("severity", "UNKNOWN").upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                                total_vulns += 1

                                vulnerability = {
                                    "cve_id": vuln.get("name", ""),
                                    "description": vuln.get("description", ""),
                                    "severity": severity,
                                    "cvss_score": vuln.get("cvssv2", {}).get("score", 0) or vuln.get("cvssv3", {}).get("baseScore", 0),
                                    "cvss_vector": vuln.get("cvssv2", {}).get("vectorString", "") or vuln.get("cvssv3", {}).get("vectorString", ""),
                                    "cwe": vuln.get("cwe", ""),
                                    "references": vuln.get("references", []),
                                    "file_name": dep.get("fileName", ""),
                                    "packages": dep.get("packages", []),
                                    "risk_score": self.calculate_risk_score(severity, vuln)
                                }
                                vulnerabilities.append(vulnerability)

            # Calculate overall risk score
            overall_risk = self.calculate_overall_risk(severity_counts, total_deps, total_vulns)

            processed_data = {
                "scan_type": "SCA",
                "tool": "OWASP Dependency-Check",
                "target": str(self.target_dir),
                "timestamp": data.get("scanInfo", {}).get("startTime", ""),
                "total_dependencies": total_deps,
                "total_vulnerabilities": total_vulns,
                "severity_breakdown": severity_counts,
                "overall_risk_score": overall_risk,
                "vulnerabilities": vulnerabilities[:200],  # Limit to top 200
                "dependencies": dependencies[:100],  # Limit to top 100
                "recommendations": self.generate_recommendations(severity_counts, total_deps)
            }

            # Save processed results
            processed_path = self.reports_dir / "sca-processed.json"
            with open(processed_path, 'w') as f:
                json.dump(processed_data, f, indent=2)

            logger.info(f"Processed SCA results saved to {processed_path}")
            return processed_data

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON report: {e}")
            return {"error": "Invalid JSON report"}
        except Exception as e:
            logger.error(f"Error processing results: {e}")
            return {"error": str(e)}

    def calculate_risk_score(self, severity: str, vuln: Dict) -> float:
        """Calculate risk score for individual vulnerability."""
        base_scores = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 2.0, "INFO": 1.0}
        base_score = base_scores.get(severity.upper(), 1.0)

        # Adjust based on CVSS score
        cvss_score = vuln.get("cvssv2", {}).get("score", 0) or vuln.get("cvssv3", {}).get("baseScore", 0)
        if cvss_score >= 9.0:
            base_score *= 1.2
        elif cvss_score >= 7.0:
            base_score *= 1.1
        elif cvss_score < 4.0:
            base_score *= 0.8

        # Adjust based on CWE (Common Weakness Enumeration)
        cwe = vuln.get("cwe", "")
        if "CWE-79" in cwe or "CWE-89" in cwe:  # XSS or SQL Injection
            base_score *= 1.3
        elif "CWE-287" in cwe:  # Improper Authentication
            base_score *= 1.2

        return min(base_score, 10.0)

    def calculate_overall_risk(self, severity_counts: Dict, total_deps: int, total_vulns: int) -> float:
        """Calculate overall risk score."""
        if total_deps == 0:
            return 0.0

        weighted_score = (
            severity_counts.get("CRITICAL", 0) * 10 +
            severity_counts.get("HIGH", 0) * 7 +
            severity_counts.get("MEDIUM", 0) * 4 +
            severity_counts.get("LOW", 0) * 2 +
            severity_counts.get("INFO", 0) * 1
        )

        # Normalize and add dependency complexity factor
        vuln_ratio = total_vulns / total_deps if total_deps > 0 else 0
        risk_score = (weighted_score / max(total_vulns, 1)) * (1 + vuln_ratio * 2)
        return min(risk_score, 10.0)

    def generate_recommendations(self, severity_counts: Dict, total_deps: int) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("Address critical vulnerabilities immediately - update affected dependencies")
        if severity_counts.get("HIGH", 0) > 5:
            recommendations.append("Review and update high-severity dependency vulnerabilities")
        if total_deps > 100:
            recommendations.append("Consider reducing dependency footprint for better security")

        recommendations.extend([
            "Regular dependency updates and security patches",
            "Use dependency scanning in CI/CD pipeline",
            "Implement software bill of materials (SBOM)",
            "Monitor dependencies for new vulnerabilities",
            "Consider using dependency locking mechanisms (requirements.txt, package-lock.json)"
        ])

        return recommendations

def main():
    """Main entry point."""
    scanner = SCAScanner()
    results = scanner.run_scan()

    if "error" in results:
        logger.error(f"Scan failed: {results['error']}")
        sys.exit(1)
    else:
        logger.info(f"Scan completed. Risk score: {results.get('overall_risk_score', 0):.2f}")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
