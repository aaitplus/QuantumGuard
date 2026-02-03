# QuantumGuard: Quantum-Enhanced Cyber Defense Simulator

## Project Description

QuantumGuard is a complete offline, autonomous, cyber-defense simulator designed to simulate vulnerabilities, predict risks, auto-harden systems, and visually display security analytics in a modern cyberpunk/purple hacker-style dashboard. This system operates entirely offline, utilizing self-contained intelligence through Python, C++, heuristics, and local machine learning models. No external AI APIs or cloud services are required, ensuring full autonomy and security.

Key Features:
- **Vulnerable Application Layer**: Deploys OWASP Juice Shop with a custom cyberpunk theme for training purposes.
- **Scanner & Risk Analyzer**: Performs SAST, SCA, container, and IaC scans using local CLI tools, generating reports and predicting risks via graph analysis, statistical scoring, and heuristics.
- **Attack Simulation Engine**: Simulates attacks like SQL Injection, XSS, and privilege escalation in sandboxed Docker containers, with performance-critical parts in C++.
- **Auto-Hardening & Remediation**: Automatically fixes vulnerabilities, updates dependencies, hardens containers, and adjusts Kubernetes manifests with rollback capabilities.
- **Cyberpunk Dashboard**: Interactive web dashboard with animated maps, heatmaps, and real-time metrics, styled in a neon purple hacker theme.
- **Self-Learning Module**: Uses offline ML (scikit-learn) to learn from scan data and improve risk predictions over time.
- **CI/CD Pipeline**: GitHub Actions workflow for automated builds, scans, and remediation.
- **Infrastructure as Code**: Terraform configurations for secure, cloud-agnostic deployments.

## Architecture Diagram

```
+-------------------+     +-------------------+     +-------------------+
|   Vulnerable App  |     |     Scanner &     |     |  Attack Simulator |
|   (OWASP Juice    |     |   Risk Analyzer   |     |   (Python + C++)  |
|     Shop + Theme) |     | (SAST/SCA/Trivy/ |     |                   |
|                   |     |     tfsec)        |     |                   |
+-------------------+     +-------------------+     +-------------------+
          |                         |                         |
          |                         |                         |
          v                         v                         v
+-------------------+     +-------------------+     +-------------------+
| Auto-Hardening &  |     | Cyberpunk         |     | Self-Learning     |
|   Remediation     |     | Dashboard         |     | Module (Offline   |
| (Scripts for      |     | (Flask + React/   |     | ML: scikit-learn) |
|  fixes & rollback)|     | Three.js)         |     |                   |
+-------------------+     +-------------------+     +-------------------+
          |                         |                         |
          |                         |                         |
          v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|   CI/CD Pipeline  |     | Infrastructure as |     |   Data Storage    |
| (GitHub Actions)  |     | Code (Terraform)  |     | (Logs, Reports,   |
|                   |     |                   |     |   ML Models)      |
+-------------------+     +-------------------+     +-------------------+
```

## Toolchain Explanation

- **Programming Languages**: Python (for backend, ML, scripting), C++ (for performance-critical simulations).
- **Libraries**: NumPy, Pandas, Scikit-learn (offline ML), NetworkX (graph analysis).
- **Tools**: Docker (containerization), Kubernetes (orchestration), Terraform (IaC), GitHub Actions (CI/CD).
- **Security Scanners**: Semgrep (SAST), OWASP Dependency-Check (SCA), Trivy (containers), tfsec (IaC).
- **Frontend**: Flask/FastAPI (backend), React/Three.js (interactive dashboard).
- **Offline ML**: Decision trees, clustering, anomaly detection using local models stored in pickle files or SQLite DB.

## Dashboard Screenshots

*(Placeholder: Screenshots will be added after dashboard implementation)*

- Animated attack simulation map with neon purple visuals.
- Real-time risk heatmaps for containers and services.
- Terminal-style panels displaying security metrics and logs.

## Setup Instructions

1. **Prerequisites**:
   - Docker installed and running.
   - Git for cloning repositories.
   - Python 3.8+ with pip.
   - Node.js for frontend (if using React).
   - CLI tools: semgrep, dependency-check, trivy, tfsec (install via package managers or binaries).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/aaitplus/QuantumGuard.git
   cd QuantumGuard
   ```

3. **Deploy Vulnerable App**:
   - Run `app/clone.sh` to download OWASP Juice Shop.
   - Run `app/apply-theme.sh` to inject the cyberpunk theme.
   - Build and run with Docker: `docker build -t quantumguard-app ./docker && docker run -p 3000:3000 quantumguard-app`

4. **Run Security Scans**:
   - Execute scanner scripts in `scanner/` directory.
   - Example: `python scanner/sast_scan.py` for SAST using Semgrep.

5. **Launch Dashboard**:
   - Navigate to `dashboard/` and run `python app.py` (Flask backend).
   - Open browser to `http://localhost:5000` for the cyberpunk dashboard.

6. **CI/CD**:
   - Push to GitHub to trigger `.github/workflows/ci-cd.yml`.
   - Use `act` for local testing: `act -j build-and-scan`.

## Security Scan Instructions

1. **SAST (Static Application Security Testing)**:
   - Use Semgrep: `semgrep --config auto --output reports/sast-report.json app/`

2. **SCA (Software Composition Analysis)**:
   - OWASP Dependency-Check: `dependency-check --scan app/ --format JSON --out reports/sca-report.json`

3. **Container Scanning**:
   - Trivy: `trivy image --format json --output reports/container-report.json quantumguard-app`

4. **IaC Scanning**:
   - tfsec: `tfsec --format json terraform/ > reports/iac-report.json`

Reports are stored in `reports/` folder. Risk analysis scripts in `scanner/` process these for predictions.

## Psychological Impact

This system predicts and auto-hardens vulnerable environments without any external AI, fully offline. By simulating real-world cyber threats and autonomously adapting defenses, QuantumGuard empowers users with a sense of control and foresight in an increasingly digital world, fostering a proactive security mindset.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read the contributing guidelines and submit pull requests.

## Psychological Edge / Portfolio Impact

Mind-blowing Complexity: Demonstrates mastery of multiple layers — code, container, orchestration, IaC, predictive intelligence.

Offline Autonomy: Shows you can engineer AI-free, fully offline intelligence — a rare skill.

Cyberpunk Dashboard: Impresses recruiters visually and technically.

Self-Learning Module: Gives an impression that the system “thinks” and adapts — recruiters feel you’re at the top of DevSecOps hierarchy.

Complete Professional Structure: CI/CD, IaC, scanning, attack simulation, and remediation — all in one project.

## Contact

For questions or support, contact [your-email@example.com].
