# 🛡️ Cloud Security Posture & IAM Privilege Analyzer

[![CI/CD & DevSecOps Gate](https://github.com/devops-security/cloud-security-iam-analyzer/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/devops-security/cloud-security-iam-analyzer/actions/workflows/ci-cd.yml)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Docker Slim](https://img.shields.io/badge/docker-multi--stage%20slim-brightgreen.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade **Cloud Security Posture & IAM Privilege Analyzer** designed to detect identity misconfigurations, excessive administrative privileges, and suspicious API activity across multi-cloud environments (**AWS CloudTrail**, **Azure Activity Logs**, and **Google Cloud Audit Logs**).

Built using the standardized **DevOps Toolchain**:
- **Workspace & Dev Environment:** VS Code DevContainers, WSL2, Docker Desktop.
- **Application & Presentation:** Python 3.11, Streamlit.
- **Analytics & Machine Learning:** `pandas`, `scikit-learn` (`IsolationForest` for behavioral anomaly detection in API calls).
- **Visualization Layer:** `plotly.express` (interactive Choropleth world map for anomalous geo-logins, Sunburst chart for IAM role-to-permission inheritance hierarchies).
- **Packaging & Containerization:** Multi-stage, slim Dockerfile with non-root security context (`UID: 10001`).
- **CI/CD Orchestration:** GitHub Actions (`black` formatting, `flake8` linting, `pytest` coverage, Trivy SAST/container scanner, GHCR image publishing).
- **Workload Orchestration:** Production Kubernetes manifests (`Deployment`, `Service` LoadBalancer/NodePort, `ConfigMap`, liveness & readiness health probes).

---

## 🏗️ Architecture & Component Overview

```
cloud-security-iam-analyzer/
├── .devcontainer/
│   ├── devcontainer.json         # VS Code DevContainer specification
│   └── Dockerfile                # Development container base
├── .github/
│   └── workflows/
│       └── ci-cd.yml             # GitHub Actions CI/CD with Trivy DevSecOps gate
├── k8s/
│   ├── configmap.yaml            # Runtime environment parameters
│   ├── deployment.yaml           # Hardened K8s deployment with health probes
│   └── service.yaml              # LoadBalancer / NodePort service
├── sample_data/
│   ├── aws_cloudtrail_sample.json
│   ├── azure_activity_sample.json
│   ├── gcp_audit_sample.json
│   └── iam_policies_sample.json
├── src/
│   ├── analytics/
│   │   ├── anomaly.py            # IsolationForest behavioral anomaly detector
│   │   ├── iam_rules.py          # CIS Benchmark & IAM posture evaluator
│   │   └── metrics.py            # Security posture scoring (0-100) & KPIs
│   ├── data/
│   │   ├── generator.py          # Multi-cloud synthetic telemetry & attack injector
│   │   └── loader.py             # Telemetry normalizer (AWS, Azure, GCP)
│   ├── visualization/
│   │   ├── charts.py             # Temporal scatter and anomaly distributions
│   │   ├── geo_map.py            # Plotly Express Choropleth world map
│   │   └── sunburst.py           # Plotly Express Sunburst IAM hierarchy
│   ├── app.py                    # Streamlit dashboard application
│   └── config.py                 # Application settings & security thresholds
├── tests/
│   ├── test_anomaly.py           # IsolationForest unit tests
│   ├── test_generator.py         # Data generator unit tests
│   ├── test_iam_rules.py         # CIS posture & impossible travel tests
│   ├── test_loader.py            # Multi-cloud parser unit tests
│   └── test_metrics.py           # Posture scoring unit tests
├── .dockerignore
├── Dockerfile                    # Multi-stage hardened production Dockerfile
├── pyproject.toml                # Unified tooling config (black, flake8, pytest)
├── requirements.txt              # Production dependencies
└── requirements-dev.txt          # Development & testing dependencies
```

---

## 🚀 Quickstart & Local Setup

### Option 1: Using `uv` (Fastest)

```bash
# 1. Create a virtual environment using Python 3.11
uv venv --python 3.11 .venv

# 2. Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux/macOS/WSL2:
source .venv/bin/activate

# 3. Install dependencies
uv pip install -r requirements-dev.txt

# 4. Launch Streamlit application
streamlit run src/app.py
```

### Option 2: Standard `python` & `pip`

```bash
python3.11 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements-dev.txt
streamlit run src/app.py
```

Open your browser at `http://localhost:8501`.

---

## 💻 Development with VS Code DevContainers

This repository includes a turnkey `.devcontainer` configuration:
1. Open this directory in VS Code (`code .`).
2. Press `F1` or `Ctrl+Shift+P` and select:
   **"Dev Containers: Reopen in Container"**.
3. VS Code will automatically build the development container, configure Python 3.11, install all dependencies, and launch port forwarding on `8501`.

---

## 🐳 Containerization (Docker)

The production container uses a **multi-stage build** based on `python:3.11-slim` with a dedicated non-root user (`securityuser`, UID `10001`):

```bash
# Build the Docker image
docker build -t cloud-security-analyzer:latest .

# Run the container
docker run -d --rm -p 8501:8501 --name cloud-security-analyzer cloud-security-analyzer:latest

# Check health endpoint
curl -f http://localhost:8501/_stcore/health
```

---

## ☸️ Workload Orchestration (Kubernetes)

Deploy to Kubernetes (EKS, AKS, GKE, or local Minikube/Docker Desktop):

```bash
# Apply ConfigMap, Deployment, and Service
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Verify deployment and health probes
kubectl get pods -l app.kubernetes.io/name=cloud-security-analyzer
kubectl get svc cloud-security-analyzer-svc
```

The deployment includes:
- **Replicas:** 2 pods with rolling updates.
- **Security Context:** `runAsNonRoot: true`, `readOnlyRootFilesystem: false`, `allowPrivilegeEscalation: false`.
- **Health Probes:** Liveness and Readiness probes monitoring `/_stcore/health`.
- **Resource Constraints:** Request 250m CPU / 512Mi Memory; Limit 1000m CPU / 1Gi Memory.

---

## 🔄 CI/CD & DevSecOps Gate (GitHub Actions)

The `.github/workflows/ci-cd.yml` workflow enforces continuous quality and security:
1. **Linting & Code Quality:**
   - Formatting check: `black --check src/ tests/`
   - Code style check: `flake8 src/ tests/`
2. **Automated Testing:**
   - Full unit test execution: `pytest -v --cov=src tests/`
3. **DevSecOps Gate (Trivy Scan):**
   - Filesystem & dependency vulnerability scan for known CVEs.
   - Built container image vulnerability scan (`CRITICAL`, `HIGH`).
4. **Container Publication:**
   - Automatic publication to GitHub Container Registry (`ghcr.io`).

---

## 🧪 Running Tests & Quality Checks Locally

```bash
# Run unit test suite with coverage
pytest -v --cov=src tests/

# Check formatting
black --check --line-length 100 src/ tests/

# Run linter
flake8 src/ tests/ --max-line-length=100
```

---

## 🎯 Security Posture & Threat Detection Highlights

| Threat / Incident Type | Detection Mechanism | Severity | CIS / Security Benchmark |
| :--- | :--- | :--- | :--- |
| **Impossible Travel** | Haversine velocity calculation across consecutive sessions | **Critical** | SEC-GEO-001 |
| **Root Account Usage** | Direct API calls by `AWS:root` or Azure Global Administrator | **Critical** | CIS AWS Benchmark 1.1 |
| **Privilege Escalation** | Execution of `iam:PassRole`, `iam:AttachUserPolicy`, `iam:CreateAccessKey` | **Critical** | MITRE ATT&CK T1078 / T1098 |
| **Excessive Wildcard Policies** | IAM hierarchy traversal for `"Action": "*"` and `"Resource": "*"` | **High / Critical** | CIS AWS Benchmark 1.16 |
| **Dormant Credentials** | Detection of identities inactive for >90 days holding elevated roles | **Medium / High** | CIS AWS Benchmark 1.3 |
| **Behavioral Anomalies** | `scikit-learn` `IsolationForest` on time-cyclical features, call bursts, and rare APIs | **Dynamic (0-100)** | Behavioral Anomaly Baseline |
