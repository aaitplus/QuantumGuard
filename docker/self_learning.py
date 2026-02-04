#!/usr/bin/env python3
"""
QuantumGuard: Self-Learning Module
Offline machine learning for risk prediction and anomaly detection.
Uses scikit-learn for model training and prediction.
"""

import json
import os
import sys
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Check for optional dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    pd = None

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/self_learning.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class SelfLearningModule:
    def __init__(self, data_dir: str = "data", models_dir: str = "data/models"):
        self.data_dir = Path(data_dir)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ML components only if available
        if HAS_SKLEARN:
            self.scaler = StandardScaler()
            self.label_encoder = LabelEncoder()
        else:
            self.scaler = None
            self.label_encoder = None

        self.risk_model_path = self.models_dir / "risk_model.pkl"
        self.anomaly_model_path = self.models_dir / "anomaly_model.pkl"
        self.historical_data_path = self.data_dir / "historical_scans.json"

        # Check capabilities
        self.capabilities = {
            'numpy': HAS_NUMPY,
            'pandas': HAS_PANDAS,
            'sklearn': HAS_SKLEARN,
            'networkx': HAS_NETWORKX
        }
        logger.info(f"Self-learning capabilities: {self.capabilities}")

    def load_historical_data(self) -> List[Dict[str, Any]]:
        """Load historical scan and attack data for training."""
        if not self.historical_data_path.exists():
            logger.warning("No historical data found. Starting with empty dataset.")
            return []

        try:
            with open(self.historical_data_path, 'r') as f:
                data = json.load(f)
                logger.info(f"Loaded {len(data)} historical records")
                return data
        except json.JSONDecodeError as e:
            logger.error(f"Error loading historical data: {e}")
            return []

    def save_historical_data(self, data: List[Dict[str, Any]]):
        """Save updated historical data."""
        try:
            with open(self.historical_data_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved {len(data)} historical records")
        except Exception as e:
            logger.error(f"Error saving historical data: {e}")

    def extract_features(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from scan data for ML training."""
        features = {}

        # Basic scan metrics
        features['total_findings'] = scan_data.get('total_findings', 0)
        features['severity_high'] = scan_data.get('severity_breakdown', {}).get('HIGH', 0)
        features['severity_critical'] = scan_data.get('severity_breakdown', {}).get('CRITICAL', 0)
        features['overall_risk'] = scan_data.get('overall_risk_score', 0)

        # Code complexity indicators
        findings = scan_data.get('findings', [])
        features['avg_severity_score'] = np.mean([
            {'INFO': 1, 'WARNING': 2, 'ERROR': 3}.get(f.get('severity', 'INFO'), 1)
            for f in findings[:100]  # Limit for performance
        ]) if findings else 0

        # Dependency graph features
        features['dependency_count'] = scan_data.get('total_dependencies', 0)
        features['vulnerable_deps'] = scan_data.get('total_vulnerabilities', 0)

        # Attack simulation features (if available)
        attack_data = scan_data.get('attack_simulation', {})
        features['attack_success_rate'] = attack_data.get('success_rate', 0)
        features['attack_types_tested'] = len(attack_data.get('attack_types', []))

        return features

    def train_risk_model(self, force_retrain: bool = False) -> bool:
        """Train the risk prediction model using historical data."""
        if self.risk_model_path.exists() and not force_retrain:
            logger.info("Risk model already exists. Use force_retrain=True to retrain.")
            return True

        historical_data = self.load_historical_data()
        if len(historical_data) < 10:
            logger.warning("Insufficient historical data for training. Need at least 10 records.")
            return False

        try:
            # Prepare training data
            X = []
            y = []

            for record in historical_data:
                features = self.extract_features(record)
                X.append(list(features.values()))

                # Determine risk label based on overall risk score
                risk_score = record.get('overall_risk_score', 0)
                if risk_score >= 8:
                    label = 'CRITICAL'
                elif risk_score >= 6:
                    label = 'HIGH'
                elif risk_score >= 4:
                    label = 'MEDIUM'
                else:
                    label = 'LOW'
                y.append(label)

            X = np.array(X)
            y_encoded = self.label_encoder.fit_transform(y)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=0.2, random_state=42
            )

            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train model
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            model.fit(X_train_scaled, y_train)

            # Evaluate model
            y_pred = model.predict(X_test_scaled)
            logger.info("Model training completed")
            logger.info(f"Classification Report:\n{classification_report(y_test, y_pred, target_names=self.label_encoder.classes_)}")

            # Save model and scaler
            with open(self.risk_model_path, 'wb') as f:
                pickle.dump({
                    'model': model,
                    'scaler': self.scaler,
                    'label_encoder': self.label_encoder,
                    'feature_names': list(self.extract_features(historical_data[0]).keys())
                }, f)

            logger.info(f"Risk model saved to {self.risk_model_path}")
            return True

        except Exception as e:
            logger.error(f"Error training risk model: {e}")
            return False

    def predict_new_threats(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict risk level for new scan data."""
        if not self.risk_model_path.exists():
            logger.warning("Risk model not found. Run train_risk_model() first.")
            return {"predicted_risk": "UNKNOWN", "confidence": 0.0}

        try:
            # Load model
            with open(self.risk_model_path, 'rb') as f:
                model_data = pickle.load(f)

            model = model_data['model']
            scaler = model_data['scaler']
            label_encoder = model_data['label_encoder']

            # Extract features
            features = self.extract_features(scan_data)
            X = np.array([list(features.values())])
            X_scaled = scaler.transform(X)

            # Predict
            prediction = model.predict(X_scaled)[0]
            probabilities = model.predict_proba(X_scaled)[0]

            predicted_risk = label_encoder.inverse_transform([prediction])[0]
            confidence = probabilities[prediction]

            result = {
                "predicted_risk": predicted_risk,
                "confidence": round(confidence, 3),
                "probabilities": {
                    label: round(prob, 3)
                    for label, prob in zip(label_encoder.classes_, probabilities)
                }
            }

            logger.info(f"Risk prediction: {predicted_risk} (confidence: {confidence:.3f})")
            return result

        except Exception as e:
            logger.error(f"Error predicting risk: {e}")
            return {"predicted_risk": "UNKNOWN", "confidence": 0.0}

    def update_model(self, new_scan_data: Dict[str, Any]):
        """Update the model with new scan data."""
        historical_data = self.load_historical_data()
        historical_data.append({
            **new_scan_data,
            'timestamp': time.time(),
            'model_version': 'incremental_update'
        })

        # Keep only last 1000 records for performance
        if len(historical_data) > 1000:
            historical_data = historical_data[-1000:]

        self.save_historical_data(historical_data)

        # Retrain model with new data
        logger.info("Updating model with new data...")
        self.train_risk_model(force_retrain=True)

    def anomaly_detection(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in scan data using isolation forest."""
        if not self.anomaly_model_path.exists():
            # Train anomaly model if it doesn't exist
            self._train_anomaly_model()

        try:
            # Load anomaly model
            with open(self.anomaly_model_path, 'rb') as f:
                model_data = pickle.load(f)

            model = model_data['model']
            scaler = model_data['scaler']

            # Extract features
            features = self.extract_features(scan_data)
            X = np.array([list(features.values())])
            X_scaled = scaler.transform(X)

            # Predict anomaly score (-1 for anomaly, 1 for normal)
            anomaly_score = model.decision_function(X_scaled)[0]
            is_anomaly = model.predict(X_scaled)[0] == -1

            result = {
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(anomaly_score, 3),
                "confidence": round(abs(anomaly_score), 3)
            }

            if is_anomaly:
                logger.warning(f"Anomaly detected in scan data (score: {anomaly_score:.3f})")
            else:
                logger.info(f"No anomaly detected (score: {anomaly_score:.3f})")

            return result

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return {"is_anomaly": False, "anomaly_score": 0.0, "confidence": 0.0}

    def _train_anomaly_model(self):
        """Train the anomaly detection model."""
        historical_data = self.load_historical_data()
        if len(historical_data) < 20:
            logger.warning("Insufficient data for anomaly training. Using default model.")
            # Create a basic model
            model = IsolationForest(contamination=0.1, random_state=42)
            # Dummy training
            X_dummy = np.random.rand(100, 10)
            model.fit(X_dummy)
            scaler = StandardScaler()
            scaler.fit(X_dummy)
        else:
            try:
                # Prepare training data
                X = []
                for record in historical_data:
                    features = self.extract_features(record)
                    X.append(list(features.values()))

                X = np.array(X)
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

                # Train model
                model = IsolationForest(contamination=0.1, random_state=42)
                model.fit(X_scaled)

                logger.info("Anomaly detection model trained")

            except Exception as e:
                logger.error(f"Error training anomaly model: {e}")
                return

        # Save model
        try:
            with open(self.anomaly_model_path, 'wb') as f:
                pickle.dump({
                    'model': model,
                    'scaler': scaler,
                    'feature_names': list(self.extract_features(historical_data[0]).keys()) if historical_data else []
                }, f)
            logger.info(f"Anomaly model saved to {self.anomaly_model_path}")
        except Exception as e:
            logger.error(f"Error saving anomaly model: {e}")

    def build_dependency_graph(self, scan_data: Dict[str, Any]) -> nx.Graph:
        """Build a dependency graph from scan data for analysis."""
        G = nx.Graph()

        dependencies = scan_data.get('dependencies', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])

        # Add dependency nodes
        for dep in dependencies:
            dep_name = dep.get('file_name', 'unknown')
            G.add_node(dep_name, type='dependency', **dep)

        # Add vulnerability edges
        vuln_deps = set()
        for vuln in vulnerabilities:
            dep_name = vuln.get('file_name', 'unknown')
            vuln_deps.add(dep_name)
            G.add_edge(dep_name, f"vuln_{vuln.get('cve_id', 'unknown')}",
                      type='vulnerability', **vuln)

        # Add transitive dependencies (simplified)
        for dep in dependencies:
            dep_name = dep.get('file_name', 'unknown')
            packages = dep.get('packages', [])
            for pkg in packages:
                pkg_name = pkg.get('id', 'unknown')
                if pkg_name != dep_name:
                    G.add_edge(dep_name, pkg_name, type='package')

        logger.info(f"Built dependency graph with {len(G.nodes)} nodes and {len(G.edges)} edges")
        return G

    def analyze_dependency_risks(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze dependency graph for risk patterns."""
        try:
            G = self.build_dependency_graph(scan_data)

            # Calculate graph metrics
            analysis = {
                "total_dependencies": len([n for n, d in G.nodes(data=True) if d.get('type') == 'dependency']),
                "total_vulnerabilities": len([e for e in G.edges(data=True) if e[2].get('type') == 'vulnerability']),
                "graph_density": nx.density(G),
                "average_clustering": nx.average_clustering(G),
                "connected_components": nx.number_connected_components(G)
            }

            # Find high-risk dependencies (many vulnerabilities)
            vuln_counts = {}
            for edge in G.edges(data=True):
                if edge[2].get('type') == 'vulnerability':
                    dep = edge[0]
                    vuln_counts[dep] = vuln_counts.get(dep, 0) + 1

            high_risk_deps = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            analysis["high_risk_dependencies"] = [
                {"dependency": dep, "vulnerability_count": count}
                for dep, count in high_risk_deps
            ]

            logger.info(f"Dependency analysis completed: {analysis['total_vulnerabilities']} vulnerabilities found")
            return analysis

        except Exception as e:
            logger.error(f"Error analyzing dependencies: {e}")
            return {"error": str(e)}

def main():
    """Main entry point for testing."""
    module = SelfLearningModule()

    # Load and display historical data summary
    historical = module.load_historical_data()
    print(f"Historical records: {len(historical)}")

    if historical:
        # Train model
        success = module.train_risk_model()
        print(f"Model training: {'Success' if success else 'Failed'}")

        # Test prediction on latest data
        if success:
            prediction = module.predict_new_threats(historical[-1])
            print(f"Risk prediction: {prediction}")

            # Test anomaly detection
            anomaly = module.anomaly_detection(historical[-1])
            print(f"Anomaly detection: {anomaly}")

            # Analyze dependencies
            analysis = module.analyze_dependency_risks(historical[-1])
            print(f"Dependency analysis: {analysis}")

if __name__ == "__main__":
    main()
