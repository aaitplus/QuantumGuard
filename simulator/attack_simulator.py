#!/usr/bin/env python3
"""
QuantumGuard: Attack Simulation Engine
Simulates cyber attacks in sandboxed Docker containers.
Uses Python + C++ for performance-critical components.
"""

import subprocess
import json
import os
import sys
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import docker
from docker.errors import DockerException
import requests
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/attack_simulator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class AttackSimulator:
    def __init__(self, target_url: str = "http://localhost:3000", reports_dir: str = "reports"):
        self.target_url = target_url
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
        self.docker_client = None
        self.simulation_results = []

    def initialize_docker(self) -> bool:
        """Initialize Docker client."""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            logger.info("Docker client initialized successfully")
            return True
        except DockerException as e:
            logger.error(f"Failed to initialize Docker: {e}")
            return False

    def check_target_availability(self) -> bool:
        """Check if target application is available."""
        try:
            response = requests.get(self.target_url, timeout=10)
            if response.status_code == 200:
                logger.info(f"Target application available at {self.target_url}")
                return True
            else:
                logger.warning(f"Target application returned status {response.status_code}")
                return False
        except requests.RequestException as e:
            logger.error(f"Target application not available: {e}")
            return False

    def simulate_sql_injection(self) -> Dict[str, Any]:
        """Simulate SQL Injection attacks."""
        logger.info("Starting SQL Injection simulation...")

        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users --",
            "admin' --",
            "' OR 1=1 --"
        ]

        results = []
        vulnerable_endpoints = []

        # Test common endpoints
        endpoints = ["/login", "/search", "/api/search", "/user/profile"]

        for endpoint in endpoints:
            full_url = urljoin(self.target_url, endpoint)
            for payload in payloads:
                try:
                    # Test in username field (assuming login form)
                    data = {"username": payload, "password": "test"}
                    response = requests.post(full_url, data=data, timeout=5)

                    if self.detect_sql_injection(response):
                        vulnerable_endpoints.append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "response_status": response.status_code,
                            "response_length": len(response.text)
                        })
                        logger.warning(f"Potential SQL injection vulnerability at {endpoint}")

                except requests.RequestException:
                    continue

        result = {
            "attack_type": "SQL Injection",
            "vulnerable_endpoints": vulnerable_endpoints,
            "total_tests": len(endpoints) * len(payloads),
            "vulnerabilities_found": len(vulnerable_endpoints),
            "risk_score": min(len(vulnerable_endpoints) * 2.0, 10.0)
        }

        self.simulation_results.append(result)
        return result

    def simulate_xss(self) -> Dict[str, Any]:
        """Simulate Cross-Site Scripting (XSS) attacks."""
        logger.info("Starting XSS simulation...")

        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>"
        ]

        results = []
        vulnerable_endpoints = []

        # Test common input fields
        endpoints = ["/search", "/comment", "/feedback", "/profile"]

        for endpoint in endpoints:
            full_url = urljoin(self.target_url, endpoint)
            for payload in payloads:
                try:
                    data = {"query": payload, "comment": payload, "feedback": payload}
                    response = requests.post(full_url, data=data, timeout=5)

                    if payload in response.text:
                        vulnerable_endpoints.append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "response_status": response.status_code
                        })
                        logger.warning(f"Potential XSS vulnerability at {endpoint}")

                except requests.RequestException:
                    continue

        result = {
            "attack_type": "XSS",
            "vulnerable_endpoints": vulnerable_endpoints,
            "total_tests": len(endpoints) * len(payloads),
            "vulnerabilities_found": len(vulnerable_endpoints),
            "risk_score": min(len(vulnerable_endpoints) * 1.5, 10.0)
        }

        self.simulation_results.append(result)
        return result

    def simulate_misconfigured_permissions(self) -> Dict[str, Any]:
        """Simulate attacks on misconfigured permissions."""
        logger.info("Starting misconfigured permissions simulation...")

        # Test for common misconfigurations
        tests = [
            {"endpoint": "/admin", "method": "GET", "expected_status": 403},
            {"endpoint": "/api/users", "method": "GET", "expected_status": 401},
            {"endpoint": "/.env", "method": "GET", "expected_status": 404},
            {"endpoint": "/config.json", "method": "GET", "expected_status": 404},
            {"endpoint": "/backup.sql", "method": "GET", "expected_status": 404}
        ]

        vulnerabilities = []

        for test in tests:
            full_url = urljoin(self.target_url, test["endpoint"])
            try:
                if test["method"] == "GET":
                    response = requests.get(full_url, timeout=5)
                elif test["method"] == "POST":
                    response = requests.post(full_url, timeout=5)

                if response.status_code not in [test["expected_status"], 404, 403, 401]:
                    vulnerabilities.append({
                        "endpoint": test["endpoint"],
                        "actual_status": response.status_code,
                        "expected_status": test["expected_status"],
                        "issue": "Unexpected access granted"
                    })
                    logger.warning(f"Misconfigured permissions at {test['endpoint']}")

            except requests.RequestException:
                continue

        result = {
            "attack_type": "Misconfigured Permissions",
            "vulnerabilities": vulnerabilities,
            "total_tests": len(tests),
            "vulnerabilities_found": len(vulnerabilities),
            "risk_score": min(len(vulnerabilities) * 3.0, 10.0)
        }

        self.simulation_results.append(result)
        return result

    def simulate_privilege_escalation(self) -> Dict[str, Any]:
        """Simulate privilege escalation in containers (requires Docker)."""
        logger.info("Starting privilege escalation simulation...")

        if not self.docker_client:
            return {"error": "Docker not available for container simulation"}

        vulnerabilities = []

        try:
            # Create a test container with potential privilege issues
            container = self.docker_client.containers.run(
                "alpine:latest",
                command="sleep 30",
                detach=True,
                privileged=False,  # Intentionally not privileged
                volumes={'/host': {'bind': '/tmp', 'mode': 'ro'}}  # Mount host directory
            )

            # Test for privilege escalation vectors
            exec_result = container.exec_run("whoami")
            if "root" in exec_result.output.decode():
                vulnerabilities.append({
                    "issue": "Container running as root",
                    "severity": "HIGH"
                })

            # Test file access
            exec_result = container.exec_run("ls /host")
            if exec_result.exit_code == 0:
                vulnerabilities.append({
                    "issue": "Container can access host filesystem",
                    "severity": "CRITICAL"
                })

            container.stop()
            container.remove()

        except DockerException as e:
            logger.error(f"Docker container simulation failed: {e}")
            return {"error": str(e)}

        result = {
            "attack_type": "Privilege Escalation",
            "vulnerabilities": vulnerabilities,
            "total_tests": 2,  # whoami and file access tests
            "vulnerabilities_found": len(vulnerabilities),
            "risk_score": sum(5.0 if v["severity"] == "CRITICAL" else 3.0 for v in vulnerabilities)
        }

        self.simulation_results.append(result)
        return result

    def detect_sql_injection(self, response) -> bool:
        """Detect potential SQL injection vulnerability."""
        indicators = [
            "sql syntax",
            "mysql_fetch",
            "ORA-01756",  # Oracle error
            "Microsoft OLE DB Provider for ODBC Drivers",
            "PostgreSQL query failed"
        ]

        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in indicators)

    def run_all_simulations(self) -> Dict[str, Any]:
        """Run all attack simulations."""
        logger.info("Starting comprehensive attack simulation suite...")

        if not self.check_target_availability():
            return {"error": "Target application not available"}

        simulations = [
            self.simulate_sql_injection,
            self.simulate_xss,
            self.simulate_misconfigured_permissions,
            self.simulate_privilege_escalation
        ]

        results = {}
        total_risk = 0.0

        for simulation in simulations:
            try:
                result = simulation()
                if "error" not in result:
                    results[result["attack_type"]] = result
                    total_risk += result.get("risk_score", 0)
                else:
                    logger.error(f"Simulation failed: {result['error']}")
            except Exception as e:
                logger.error(f"Unexpected error in simulation: {e}")

        # Calculate overall risk
        overall_risk = min(total_risk / len(simulations), 10.0)

        final_report = {
            "simulation_summary": {
                "total_simulations": len(simulations),
                "successful_simulations": len(results),
                "overall_risk_score": overall_risk,
                "timestamp": time.time()
            },
            "attack_results": results,
            "recommendations": self.generate_simulation_recommendations(results)
        }

        # Save report
        report_path = self.reports_dir / "attack-simulation-report.json"
        with open(report_path, 'w') as f:
            json.dump(final_report, f, indent=2)

        logger.info(f"Attack simulation report saved to {report_path}")
        return final_report

    def generate_simulation_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on simulation results."""
        recommendations = []

        for attack_type, result in results.items():
            vuln_count = result.get("vulnerabilities_found", 0)
            risk_score = result.get("risk_score", 0)

            if attack_type == "SQL Injection" and vuln_count > 0:
                recommendations.append("Implement prepared statements and input validation")
                recommendations.append("Use ORM libraries to prevent SQL injection")
            elif attack_type == "XSS" and vuln_count > 0:
                recommendations.append("Implement Content Security Policy (CSP)")
                recommendations.append("Sanitize user inputs and use safe encoding")
            elif attack_type == "Misconfigured Permissions" and vuln_count > 0:
                recommendations.append("Review and tighten access controls")
                recommendations.append("Implement proper authentication and authorization")
            elif attack_type == "Privilege Escalation" and risk_score > 5:
                recommendations.append("Run containers with non-root users")
                recommendations.append("Limit container capabilities and privileges")

        recommendations.extend([
            "Regular security testing and vulnerability assessments",
            "Implement Web Application Firewall (WAF)",
            "Conduct security training for developers",
            "Regular dependency updates and patch management"
        ])

        return list(set(recommendations))  # Remove duplicates

def main():
    """Main entry point."""
    simulator = AttackSimulator()

    if not simulator.initialize_docker():
        logger.error("Failed to initialize Docker. Some simulations may not run.")

    report = simulator.run_all_simulations()

    if "error" in report:
        logger.error(f"Attack simulation failed: {report['error']}")
        sys.exit(1)
    else:
        logger.info("Attack simulation completed successfully")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
