// QuantumGuard Dashboard JavaScript
// Handles real-time updates, visualizations, and user interactions

class QuantumGuardDashboard {
    constructor() {
        this.currentSection = 'overview';
        this.updateInterval = 5000; // 5 seconds
        this.riskHeatmap = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.startDataUpdates();
        this.initializeCharts();
        this.loadInitialData();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const section = e.target.textContent.toLowerCase().replace(' ', '-');
                this.showSection(section);
            });
        });

        // Log filters
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.filterLogs(e.target.textContent);
            });
        });
    }

    showSection(sectionName) {
        // Update navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[onclick="showSection('${sectionName}')"]`).classList.add('active');

        // Update sections
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(sectionName).classList.add('active');

        this.currentSection = sectionName;
    }

    startDataUpdates() {
        this.updateData();
        setInterval(() => this.updateData(), this.updateInterval);
    }

    async updateData() {
        try {
            const [health, scans, simulations, remediation, logs] = await Promise.all([
                this.fetchData('/api/health'),
                this.fetchData('/api/scans'),
                this.fetchData('/api/simulations'),
                this.fetchData('/api/remediation'),
                this.fetchData('/api/logs')
            ]);

            this.updateHealthStatus(health);
            this.updateScanData(scans);
            this.updateSimulationData(simulations);
            this.updateRemediationData(remediation);
            this.updateLogs(logs);
            this.updateHeatmap();

        } catch (error) {
            console.error('Error updating dashboard data:', error);
        }
    }

    async fetchData(endpoint) {
        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    }

    updateHealthStatus(health) {
        const statusElement = document.getElementById('health-status');
        const riskElement = document.getElementById('overall-risk');
        const scansElement = document.getElementById('active-scans');
        const vulnsElement = document.getElementById('total-vulns');
        const updateElement = document.getElementById('last-update');

        if (health) {
            statusElement.textContent = health.overall_health;
            statusElement.className = `status-indicator ${health.overall_health.toLowerCase()}`;

            riskElement.textContent = health.average_risk_score.toFixed(1);
            scansElement.textContent = health.active_scans;

            // Calculate total vulnerabilities from scan data
            this.fetchData('/api/scans').then(scans => {
                let totalVulns = 0;
                Object.values(scans).forEach(scan => {
                    totalVulns += scan.findings || 0;
                });
                vulnsElement.textContent = totalVulns;
            });

            updateElement.textContent = new Date(health.last_update * 1000).toLocaleTimeString();
        }
    }

    updateScanData(scans) {
        const scanMappings = {
            sast: ['sast-risk', 'sast-findings'],
            sca: ['sca-risk', 'sca-vulns'],
            container: ['container-risk', 'container-issues'],
            iac: ['iac-risk', 'iac-findings']
        };

        Object.entries(scanMappings).forEach(([scanType, [riskId, countId]]) => {
            const scanData = scans[scanType];
            if (scanData) {
                document.getElementById(riskId).textContent = scanData.risk_score.toFixed(1);
                document.getElementById(countId).textContent = scanData.findings || 0;
            }
        });
    }

    updateSimulationData(simulations) {
        if (simulations && simulations.overall_risk !== undefined) {
            document.getElementById('sim-overall-risk').textContent = simulations.overall_risk.toFixed(1);

            const attackMappings = {
                'SQL Injection': 'sql-risk',
                'XSS': 'xss-risk',
                'Misconfigured Permissions': 'perms-risk',
                'Privilege Escalation': 'priv-risk'
            };

            Object.entries(attackMappings).forEach(([attackType, elementId]) => {
                const attackData = simulations.simulations[attackType];
                if (attackData) {
                    document.getElementById(elementId).textContent = attackData.risk_score.toFixed(1);
                }
            });
        }
    }

    updateRemediationData(remediation) {
        if (remediation && remediation.phases) {
            const phaseMappings = {
                dependencies: 'dep-status',
                dockerfile: 'docker-status',
                kubernetes: 'k8s-status',
                sandbox_test: 'test-status'
            };

            Object.entries(phaseMappings).forEach(([phase, elementId]) => {
                const phaseData = remediation.phases[phase];
                if (phaseData) {
                    const status = phaseData.status || 'UNKNOWN';
                    const element = document.getElementById(elementId);
                    element.textContent = status.toUpperCase();
                    element.className = `phase-status ${status.toLowerCase()}`;
                }
            });
        }
    }

    updateLogs(logs) {
        const logContainer = document.getElementById('log-entries');
        if (logs && logs.logs) {
            logContainer.innerHTML = logs.logs.map(log => `
                <div class="log-entry">
                    <span class="log-timestamp">${log.timestamp}</span>
                    <span class="log-level ${log.level}">${log.level}</span>
                    <span class="log-message">${log.message}</span>
                </div>
            `).join('');
        }
    }

    initializeCharts() {
        const ctx = document.getElementById('riskHeatmap').getContext('2d');
        this.riskHeatmap = new Chart(ctx, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Risk Heatmap',
                    data: [],
                    backgroundColor: 'rgba(0, 255, 255, 0.6)',
                    borderColor: 'rgba(0, 255, 255, 1)',
                    borderWidth: 1,
                    pointRadius: 8,
                    pointHoverRadius: 12
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'linear',
                        position: 'bottom',
                        title: {
                            display: true,
                            text: 'Service Index',
                            color: '#00ffff'
                        },
                        ticks: {
                            color: '#cccccc'
                        },
                        grid: {
                            color: '#333333'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Risk Score',
                            color: '#00ffff'
                        },
                        ticks: {
                            color: '#cccccc'
                        },
                        grid: {
                            color: '#333333'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }

    updateHeatmap() {
        this.fetchData('/api/heatmap-data').then(data => {
            if (data && data.services) {
                const heatmapData = data.services.map((service, index) => ({
                    x: index,
                    y: service.risk,
                    label: service.name
                }));

                this.riskHeatmap.data.datasets[0].data = heatmapData;
                this.riskHeatmap.update();
            }
        });
    }

    filterLogs(level) {
        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');

        const logEntries = document.querySelectorAll('.log-entry');
        logEntries.forEach(entry => {
            if (level === 'ALL' || entry.querySelector('.log-level').textContent === level) {
                entry.style.display = 'flex';
            } else {
                entry.style.display = 'none';
            }
        });
    }

    async triggerScan(scanType) {
        try {
            const response = await fetch(`/api/trigger-scan/${scanType}`);
            const result = await response.json();

            if (result.status === 'started') {
                this.showNotification(`Started ${scanType.toUpperCase()} scan`, 'success');
            } else {
                this.showNotification(`Failed to start ${scanType.toUpperCase()} scan`, 'error');
            }
        } catch (error) {
            console.error('Error triggering scan:', error);
            this.showNotification('Error triggering scan', 'error');
        }
    }

    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;

        // Add to page
        document.body.appendChild(notification);

        // Remove after 3 seconds
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 3000);
    }

    loadInitialData() {
        this.updateData();
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new QuantumGuardDashboard();
});

// Global functions for HTML onclick handlers
function showSection(section) {
    window.dashboard.showSection(section);
}

function triggerScan(scanType) {
    window.dashboard.triggerScan(scanType);
}

function filterLogs(level) {
    window.dashboard.filterLogs(level);
}
