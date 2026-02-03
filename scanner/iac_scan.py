#!/usr/bin/env python3
"""
QuantumGuard: IaC Scanner using tfsec
Performs Infrastructure as Code security scanning.
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
        logging.FileHandler('data/iac_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class IACScanner:
    def __init__(self, target_dir: str = "terraform", reports_dir: str = "reports"):
        self.target_dir = Path(target_dir)
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.report_path = self.reports_dir / "iac-report.json"

    def check_prerequisites(self) -> bool:
        """Check if tfsec is installed."""
        try:
            result = subprocess.run(
                ["tfsec", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"tfsec version: {result.stdout.strip()}")
                return True
            else:
                logger.error("tfsec not found or not working.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error checking tfsec: {e}")
            return False

    def run_scan(self) -> Dict[str, Any]:
        """Run IaC scan using tfsec."""
        if not self.target_dir.exists():
            logger.error(f"Target directory {self.target_dir} does not exist.")
            return {"error": "Target directory not found"}

        if not self.check_prerequisites():
            return {"error": "Prerequisites not met"}

        try:
            # Run tfsec scan
            cmd = [
                "tfsec",
                "--format", "json",
                "--out", str(self.report_path),
                str(self.target_dir)
            ]

            logger.info(f"Running IaC scan on {self.target_dir}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            if result.returncode == 0 or result.returncode == 1:  # tfsec returns 1 for findings
                logger.info("IaC scan completed successfully.")
                return self.process_results()
            else:
                logger.error(f"IaC scan failed: {result.stderr}")
                return {"error": f"Scan failed: {result.stderr}"}

        except subprocess.TimeoutExpired:
            logger.error("IaC scan timed out.")
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

            # Extract results
            results = []
            total_findings = 0
            severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

            if "results" in data:
                for result in data["results"]:
                    if "passed_checks" in result:
                        # Process passed checks (for completeness)
                        pass

                    if "failed_checks" in result:
                        for check in result["failed_checks"]:
                            severity = check.get("severity", "UNKNOWN").upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                                total_findings += 1

                                finding = {
                                    "rule_id": check.get("rule_id", ""),
                                    "rule_description": check.get("rule_description", ""),
                                    "severity": severity,
                                    "resource": check.get("resource", ""),
                                    "file": check.get("range", {}).get("filename", ""),
                                    "start_line": check.get("range", {}).get("start_line", 0),
                                    "end_line": check.get("range", {}).get("end_line", 0),
                                    "impact": check.get("impact", ""),
                                    "resolution": check.get("resolution", ""),
                                    "risk_score": self.calculate_risk_score(severity, check)
                                }
                                results.append(finding)

            # Calculate overall risk score
            overall_risk = self.calculate_overall_risk(severity_counts, total_findings)

            processed_data = {
                "scan_type": "IaC",
                "tool": "tfsec",
                "target": str(self.target_dir),
                "timestamp": "",  # tfsec doesn't provide timestamp in JSON
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "overall_risk_score": overall_risk,
                "findings": results[:100],  # Limit to top 100
                "recommendations": self.generate_recommendations(severity_counts)
            }

            # Save processed results
            processed_path = self.reports_dir / "iac-processed.json"
            with open(processed_path, 'w') as f:
                json.dump(processed_data, f, indent=2)

            logger.info(f"Processed IaC results saved to {processed_path}")
            return processed_data

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON report: {e}")
            return {"error": "Invalid JSON report"}
        except Exception as e:
            logger.error(f"Error processing results: {e}")
            return {"error": str(e)}

    def calculate_risk_score(self, severity: str, finding: Dict) -> float:
        """Calculate risk score for individual finding."""
        base_scores = {"LOW": 2.0, "MEDIUM": 4.0, "HIGH": 7.0, "CRITICAL": 10.0}
        base_score = base_scores.get(severity.upper(), 1.0)

        # Adjust based on impact description
        impact = finding.get("impact", "").lower()
        if "data exposure" in impact or "privilege escalation" in impact:
            base_score *= 1.5
        elif "misconfiguration" in impact:
            base_score *= 1.2

        # Adjust based on rule ID (specific security concerns)
        rule_id = finding.get("rule_id", "").lower()
        if "encryption" in rule_id or "access" in rule_id:
            base_score *= 1.3

        return min(base_score, 10.0)

    def calculate_overall_risk(self, severity_counts: Dict, total_findings: int) -> float:
        """Calculate overall risk score."""
        if total_findings == 0:
            return 0.0

        weighted_score = (
            severity_counts.get("LOW", 0) * 2 +
            severity_counts.get("MEDIUM", 0) * 4 +
            severity_counts.get("HIGH", 0) * 7 +
            severity_counts.get("CRITICAL", 0) * 10
        )

        # Normalize and add infrastructure complexity factor
        risk_score = (weighted_score / total_findings) * (1 + total_findings / 50)
        return min(risk_score, 10.0)

    def generate_recommendations(self, severity_counts: Dict) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append("Address critical IaC security issues immediately")
        if severity_counts.get("HIGH", 0) > 5:
            recommendations.append("Review and fix high-severity infrastructure misconfigurations")
        if severity_counts.get("MEDIUM", 0) > 10:
            recommendations.append("Address medium-risk configuration issues")

        recommendations.append("Use tfsec in CI/CD pipeline for automated IaC security checks")
        recommendations.append("Implement infrastructure security best practices")
        recommendations.append("Regularly review and update Terraform configurations")
        recommendations.append("Use Terraform modules for consistent security configurations")

        return recommendations

def main():
    """Main entry point."""
    scanner = IACScanner()
    results = scanner.run_scan()

    if "error" in results:
        logger.error(f"Scan failed: {results['error']}")
        sys.exit(1)
    else:
        logger.info(f"Scan completed. Risk score: {results.get('overall_risk_score', 0):.2f}")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
