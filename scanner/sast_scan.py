#!/usr/bin/env python3
"""
QuantumGuard: SAST Scanner using Semgrep
Performs Static Application Security Testing on the vulnerable app.
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
        logging.FileHandler('data/sast_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SASTScanner:
    def __init__(self, target_dir: str = "app", reports_dir: str = "reports"):
        self.target_dir = Path(target_dir)
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.report_path = self.reports_dir / "sast-report.json"

    def check_prerequisites(self) -> bool:
        """Check if Semgrep is installed."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Semgrep version: {result.stdout.strip()}")
                return True
            else:
                logger.error("Semgrep not found or not working.")
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Error checking Semgrep: {e}")
            return False

    def run_scan(self) -> Dict[str, Any]:
        """Run SAST scan using Semgrep."""
        if not self.target_dir.exists():
            logger.error(f"Target directory {self.target_dir} does not exist.")
            return {"error": "Target directory not found"}

        if not self.check_prerequisites():
            return {"error": "Prerequisites not met"}

        try:
            # Run Semgrep scan
            cmd = [
                "semgrep",
                "--config", "auto",
                "--json",
                "--output", str(self.report_path),
                str(self.target_dir)
            ]

            logger.info(f"Running SAST scan on {self.target_dir}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )

            if result.returncode == 0 or result.returncode == 1:  # Semgrep returns 1 for findings
                logger.info("SAST scan completed successfully.")
                return self.process_results()
            else:
                logger.error(f"SAST scan failed: {result.stderr}")
                return {"error": f"Scan failed: {result.stderr}"}

        except subprocess.TimeoutExpired:
            logger.error("SAST scan timed out.")
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

            # Extract findings
            findings = []
            total_findings = 0
            severity_counts = {"INFO": 0, "WARNING": 0, "ERROR": 0}

            if "results" in data:
                for result in data["results"]:
                    if "extra" in result and "severity" in result["extra"]:
                        severity = result["extra"]["severity"].upper()
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                        total_findings += 1

                        finding = {
                            "rule_id": result.get("check_id", ""),
                            "message": result.get("extra", {}).get("message", ""),
                            "severity": severity,
                            "file": result.get("path", ""),
                            "line": result.get("start", {}).get("line", 0),
                            "risk_score": self.calculate_risk_score(severity, result)
                        }
                        findings.append(finding)

            # Calculate overall risk score
            overall_risk = self.calculate_overall_risk(severity_counts, total_findings)

            processed_data = {
                "scan_type": "SAST",
                "tool": "Semgrep",
                "target": str(self.target_dir),
                "timestamp": data.get("scanned_at", ""),
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "overall_risk_score": overall_risk,
                "findings": findings[:100],  # Limit to top 100 findings
                "recommendations": self.generate_recommendations(severity_counts)
            }

            # Save processed results
            processed_path = self.reports_dir / "sast-processed.json"
            with open(processed_path, 'w') as f:
                json.dump(processed_data, f, indent=2)

            logger.info(f"Processed SAST results saved to {processed_path}")
            return processed_data

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON report: {e}")
            return {"error": "Invalid JSON report"}
        except Exception as e:
            logger.error(f"Error processing results: {e}")
            return {"error": str(e)}

    def calculate_risk_score(self, severity: str, finding: Dict) -> float:
        """Calculate risk score for individual finding."""
        base_scores = {"INFO": 1.0, "WARNING": 3.0, "ERROR": 5.0}
        base_score = base_scores.get(severity.upper(), 1.0)

        # Adjust based on rule category
        rule_id = finding.get("check_id", "").lower()
        if "sql" in rule_id or "injection" in rule_id:
            base_score *= 1.5
        elif "auth" in rule_id or "crypto" in rule_id:
            base_score *= 1.3

        return min(base_score, 10.0)  # Cap at 10

    def calculate_overall_risk(self, severity_counts: Dict, total_findings: int) -> float:
        """Calculate overall risk score."""
        if total_findings == 0:
            return 0.0

        weighted_score = (
            severity_counts.get("INFO", 0) * 1 +
            severity_counts.get("WARNING", 0) * 3 +
            severity_counts.get("ERROR", 0) * 5
        )

        # Normalize and add complexity factor
        risk_score = (weighted_score / total_findings) * (1 + total_findings / 100)
        return min(risk_score, 10.0)

    def generate_recommendations(self, severity_counts: Dict) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        if severity_counts.get("ERROR", 0) > 0:
            recommendations.append("Address high-severity vulnerabilities immediately")
        if severity_counts.get("WARNING", 0) > 10:
            recommendations.append("Review and fix medium-severity issues")
        if severity_counts.get("INFO", 0) > 50:
            recommendations.append("Consider code quality improvements for informational findings")

        recommendations.append("Run regular SAST scans in CI/CD pipeline")
        recommendations.append("Implement secure coding practices and training")

        return recommendations

def main():
    """Main entry point."""
    scanner = SASTScanner()
    results = scanner.run_scan()

    if "error" in results:
        logger.error(f"Scan failed: {results['error']}")
        sys.exit(1)
    else:
        logger.info(f"Scan completed. Risk score: {results.get('overall_risk_score', 0):.2f}")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
