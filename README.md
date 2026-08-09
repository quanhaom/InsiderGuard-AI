# InsiderGuard AI

> **AI-Powered Insider Threat Detection, UEBA & Security Operations Platform**
>
> Windows Telemetry • Sysmon • UEBA • MITRE ATT&CK • Threat Hunting • Digital Forensics • AI Investigation • Blockchain Evidence Integrity

---

## Overview

**InsiderGuard AI** is a cybersecurity monitoring and investigation platform designed to detect, analyze, and investigate insider threats and suspicious endpoint activity.

The platform combines:

* Windows Security Event monitoring
* Sysmon telemetry
* User & Entity Behavior Analytics (UEBA)
* Behavioral baselining
* Risk scoring
* Rule-based threat detection
* MITRE ATT&CK mapping
* Alert and incident management
* Threat hunting
* Digital forensic evidence preservation
* Blockchain-style evidence integrity
* AI-assisted incident investigation
* SOC monitoring and visualization

InsiderGuard AI supports an end-to-end security workflow:

```text
Windows Endpoint
      │
      ├── Windows Security Log
      └── Sysmon
              │
              ▼
    Windows Event Collector
              │
              ▼
       FastAPI Backend
              │
              ▼
       Parsing Pipeline
              │
              ▼
      Event Normalization
              │
              ▼
       Detection / UEBA
              │
              ▼
            Alert
              │
              ▼
           Incident
              │
       ┌──────┴───────┐
       ▼              ▼
    Evidence      Timeline
       │
       ▼
Blockchain Integrity
       │
       ▼
 AI Investigation
       │
       ▼
    SOC Dashboard
```

The platform can therefore process both simulated security events for development/testing and real Windows telemetry collected directly from a Windows endpoint.

---

# Key Capabilities

## 1. Real Windows Event Collection

InsiderGuard AI includes a Windows collector capable of reading events directly from a Windows host.

Sources currently supported:

### Windows Security Log

```text
Security
```

### Sysmon

```text
Microsoft-Windows-Sysmon/Operational
```

The collector:

* Reads real Windows Event Log records
* Reads Sysmon telemetry
* Retrieves the original event XML
* Tracks Windows Event Record IDs
* Prevents unnecessary replay of historical events
* Sends telemetry to the InsiderGuard API
* Maintains local collector state
* Continuously polls for new security events

Real collector:

```text
tools/windows_event_collector.py
```

Development/test simulator:

```text
tools/windows_agent.py
```

These tools serve different purposes:

```text
windows_agent.py
        │
        └── Simulated events
            for development/testing

windows_event_collector.py
        │
        └── Real Windows Security
            and Sysmon telemetry
```

---

# Supported Windows Security Events

| Event ID | Description                                   | Detection                             |
| -------: | --------------------------------------------- | ------------------------------------- |
|     4624 | Successful Login                              | Login / behavioral analysis           |
|     4625 | Failed Login                                  | Failed-login / brute-force detection  |
|     4672 | Special Privileges Assigned                   | Privilege detection                   |
|     4688 | Process Creation                              | Suspicious process detection          |
|     4720 | User Account Created                          | Account creation detection            |
|     4728 | Member Added to Security-Enabled Global Group | Privileged group membership detection |

Processing pipeline:

```text
Windows Event
     │
     ▼
RawWindowsEvent
     │
     ▼
Parser Registry
     │
     ▼
NormalizedWindowsEvent
     │
     ▼
Detector / UEBA
     │
     ▼
Alert
     │
     ▼
Incident
     │
     ▼
Evidence
     │
     ▼
Blockchain
     │
     ▼
AI Investigation
```

---

# Sysmon Integration

InsiderGuard AI supports endpoint telemetry collected through Microsoft Sysmon.

Currently supported:

| Sysmon Event ID | Description        | InsiderGuard Usage                        |
| --------------: | ------------------ | ----------------------------------------- |
|               1 | Process Creation   | Process behavior and suspicious execution |
|               3 | Network Connection | Process-to-network activity analysis      |

Sysmon log source:

```text
Microsoft-Windows-Sysmon/Operational
```

The repository includes a Sysmon configuration for telemetry required by InsiderGuard:

```text
tools/sysmonconfig.xml
```

Future Sysmon coverage will include:

```text
Event 11 → File Create
Event 13 → Registry Value Set
Event 22 → DNS Query
```

---

# Event Parsing Pipeline

Windows telemetry is processed through a centralized event pipeline.

```text
Raw Event
   │
   ▼
WindowsPipelineExecutor
   │
   ▼
Parser
   │
   ▼
Pydantic Event Schema
   │
   ▼
WindowsNormalizer
   │
   ▼
Normalized Event
   │
   ▼
Detection Engine
```

This design separates:

* Event ingestion
* Event parsing
* Event normalization
* Detection logic
* Incident handling

and allows additional Windows/Sysmon events to be added without redesigning the entire ingestion system.

---

# User & Entity Behavior Analytics — UEBA

InsiderGuard builds behavioral profiles from user activity.

Current behavioral features include:

* Average login time
* Login frequency
* Historical login activity
* Common source IP addresses
* New source IP detection
* Login-time deviations
* Weekend activity
* Night-time activity

Behavior profiles provide context for determining whether activity deviates from established user behavior.

Example:

```text
Normal behavior

User: alice
Typical login: 08:00–09:00
Known IP: 192.168.1.10

             ↓

Observed activity

Login: 02:17
IP: 10.10.50.20

             ↓

Behavior deviation

             ↓

Higher risk score
```

---

# Risk Scoring

Detections can be assigned deterministic risk scores according to their security impact and behavioral context.

Typical risk classification:

|  Score | Risk Level |
| -----: | ---------- |
|   0–30 | LOW        |
|  31–60 | MEDIUM     |
|  61–80 | HIGH       |
| 81–100 | CRITICAL   |

Risk factors can include:

* Failed login bursts
* Abnormal login times
* New source addresses
* Dangerous privilege assignments
* Suspicious processes
* Account creation
* Privileged group modification
* Suspicious network behavior

---

# Detection Engine

## Failed Login Detection

Source:

```text
Windows Event 4625
```

Analyzes failed authentication activity and can identify suspicious patterns such as repeated authentication failures.

Pipeline:

```text
4625
 ↓
Parser4625
 ↓
FailedLoginEvent
 ↓
FailedLoginDetector
 ↓
Alert / Incident
```

---

## Privilege Detection

Source:

```text
Windows Event 4672
```

Monitors assignment of sensitive Windows privileges.

Examples include:

* SeDebugPrivilege
* SeImpersonatePrivilege
* SeTakeOwnershipPrivilege
* SeLoadDriverPrivilege
* SeTcbPrivilege

Suspicious privilege assignments can increase the risk score and trigger an alert.

---

## Suspicious Process Detection

Sources:

```text
Windows Security Event 4688
Sysmon Event 1
```

Processes of interest can include:

* powershell.exe
* cmd.exe
* rundll32.exe
* regsvr32.exe
* mshta.exe
* certutil.exe
* wmic.exe
* psexec.exe
* mimikatz.exe

Command-line indicators can include:

* Encoded PowerShell
* Base64 payloads
* Hidden execution
* Invoke-Expression
* DownloadString
* LOLBin abuse

Sysmon provides additional endpoint context that can improve process analysis.

---

# Account Creation Detection

Source:

```text
Windows Event 4720
```

Detects creation of new Windows user accounts.

The detector can assign additional risk when account characteristics indicate administrative, temporary, or service-style usage.

Example:

```text
Account Created
      │
      ▼
tempadmin
      │
      ▼
AccountCreationDetector
      │
      ▼
HIGH Risk
```

---

# Privileged Group Membership Detection

Source:

```text
Windows Event 4728
```

Detects users being added to security-enabled global groups.

High-value groups such as:

```text
Domain Admins
```

can generate critical detections.

Example:

```text
User: bob
       │
       ▼
Added to Domain Admins
       │
       ▼
PRIVILEGED_GROUP_MEMBERSHIP
       │
       ▼
Risk Score: 85
       │
       ▼
CRITICAL
```

---

# Sysmon Process Detection

Source:

```text
Sysmon Event 1
```

Provides enhanced process telemetry including information such as:

* Process image
* Command line
* Parent process
* Process ID
* User context
* File hashes, depending on Sysmon configuration

This provides richer process visibility than standard Windows auditing alone.

---

# Sysmon Network Detection

Source:

```text
Sysmon Event 3
```

Monitors network connections initiated by processes.

Relevant telemetry can include:

* Process image
* Source IP
* Source port
* Destination IP
* Destination port
* Protocol
* User
* Process ID

Pipeline:

```text
Process
   │
   ▼
Network Connection
   │
   ▼
Sysmon Event 3
   │
   ▼
SysmonNetworkDetector
   │
   ▼
Risk Analysis
```

---

# MITRE ATT&CK Mapping

InsiderGuard maps selected detections to MITRE ATT&CK techniques to provide standardized security context.

Examples:

| Activity                           | MITRE ATT&CK |
| ---------------------------------- | ------------ |
| PowerShell                         | T1059.001    |
| Windows Command Shell              | T1059.003    |
| Rundll32                           | T1218.011    |
| Regsvr32                           | T1218.010    |
| Mshta                              | T1218.005    |
| Windows Management Instrumentation | T1047        |
| Account Manipulation               | T1098        |
| OS Credential Dumping              | T1003        |

MITRE mappings are also included in AI-assisted investigation reports where applicable.

---

# Alert Engine

Detectors can generate alerts containing information such as:

* Alert type
* Severity
* Risk score
* Detection reason
* User
* Source event
* Security context

Example:

```text
Alert Type:
PRIVILEGED_GROUP_MEMBERSHIP

Severity:
CRITICAL

Risk Score:
85

Reason:
User bob was added to security group Domain Admins.
```

---

# Incident Management

High-risk detections can be promoted into security incidents.

Incident capabilities include:

* Incident creation
* Severity tracking
* Risk tracking
* Status management
* Detection context
* Evidence association
* Timeline generation
* Investigation support

Typical statuses:

```text
OPEN
INVESTIGATING
RESOLVED
CLOSED
```

---

# Incident Timeline

InsiderGuard maintains an audit trail of important incident activity.

Timeline events can include:

* Incident Created
* Status Changed
* Evidence Captured
* Blockchain Sealed
* Detection Generated
* Investigation Generated

This provides analysts with a chronological view of an incident.

---

# Evidence Vault

Security evidence can be captured from incidents and stored for investigation.

Evidence may contain:

* Alert information
* Detection reason
* Risk score
* User context
* Event information
* Behavioral context
* Investigation context

Evidence integrity is protected using SHA-256 hashing.

```text
Incident
   │
   ▼
Evidence Snapshot
   │
   ▼
SHA-256
   │
   ▼
Evidence Hash
```

---

# Blockchain Evidence Integrity

InsiderGuard includes a blockchain-style audit chain for protecting evidence integrity.

Each block contains information such as:

* Evidence ID
* Evidence hash
* Previous block hash
* Block hash
* Nonce
* Creation timestamp

Structure:

```text
Evidence #1
    │
    ▼
Block #1
Hash A
    │
    ▼
Block #2
Previous Hash = Hash A
    │
    ▼
Block #3
Previous Hash = Hash B
```

The blockchain can be verified to detect modification of recorded evidence.

This component is intended as an evidence-integrity and audit mechanism rather than a cryptocurrency blockchain.

---

# Threat Hunting

The Threat Hunting module allows analysts to investigate normalized security telemetry.

Hunting capabilities include:

* Windows event investigation
* User activity analysis
* Process hunting
* Privilege activity review
* Account activity
* Network activity
* Timeline analysis

Normalized telemetry provides a common structure across different Windows event types.

---

# AI-Assisted Investigation

InsiderGuard includes an AI-assisted investigation layer for generating structured incident reports.

Reports can contain:

1. Executive Summary
2. Technical Analysis
3. MITRE ATT&CK Mapping
4. Recommended Actions
5. Analyst Notes

Example investigation:

```text
Incident
   │
   ▼
Timeline
   +
Evidence
   +
Alert
   +
Risk Context
   │
   ▼
AI Investigator
   │
   ▼
Investigation Report
```

Reports include model metadata and a confidence value when available.

AI-generated findings are intended to assist analysts and should be validated against the underlying security telemetry and forensic evidence before remediation decisions are made.

---

# SOC Dashboard

The React frontend provides a central interface for monitoring and investigating security activity.

The interface includes views for areas such as:

* Security overview
* Alerts
* Incidents
* Incident details
* Investigation reports
* Event activity
* Threat hunting
* Risk information
* Evidence and timeline context

Frontend:

```text
http://localhost:5173
```

---

# Current Architecture

```text
┌──────────────────────────────┐
│       Windows Endpoint       │
│                              │
│  Security Log       Sysmon   │
└─────────┬─────────────┬──────┘
          │             │
          └──────┬──────┘
                 ▼
       Windows Event Collector
                 │
                 │ HTTP / JSON
                 ▼
┌──────────────────────────────┐
│       FastAPI Backend        │
│                              │
│  Raw Event Ingestion         │
│          ↓                   │
│  Parser Pipeline             │
│          ↓                   │
│  Event Normalization         │
│          ↓                   │
│  UEBA / Detectors            │
│          ↓                   │
│  Alert Engine                │
│          ↓                   │
│  Incident Engine             │
│          ↓                   │
│  Evidence Vault              │
│          ↓                   │
│  Blockchain Integrity        │
│          ↓                   │
│  AI Investigator             │
└──────────────┬───────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
 PostgreSQL           Redis
       │
       ▼
┌──────────────────────────────┐
│       React SOC UI           │
│                              │
│ Dashboard                    │
│ Alerts                       │
│ Incidents                    │
│ Investigation                │
│ Threat Hunting               │
└──────────────────────────────┘
```

---

# Technology Stack

## Backend

* Python
* FastAPI
* SQLAlchemy
* Pydantic
* Uvicorn

## Database

* PostgreSQL 18

## Cache / Infrastructure

* Redis 7

## Frontend

* React
* Vite
* Recharts

## Endpoint Telemetry

* Windows Event Log
* Microsoft Sysmon
* pywin32

## Security

* UEBA
* MITRE ATT&CK
* SHA-256
* Evidence integrity verification
* Blockchain-style audit chain

## Infrastructure

* Docker
* Docker Compose

## Development

* Git
* GitHub
* Pytest

---

# Project Structure

```text
InsiderGuard-AI/
│
├── backend/
│   │
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── models/
│   │   ├── repositories/
│   │   ├── schemas/
│   │   ├── services/
│   │   │
│   │   └── modules/
│   │       ├── users/
│   │       ├── events/
│   │       ├── windows_events/
│   │       ├── parsers/
│   │       ├── behavior_profile/
│   │       ├── failed_login_events/
│   │       ├── ueba/
│   │       ├── incidents/
│   │       ├── evidence/
│   │       ├── blockchain/
│   │       ├── dashboard/
│   │       ├── threat_hunting/
│   │       └── investigator/
│   │
│   ├── scripts/
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   └── package.json
│
├── tools/
│   ├── windows_agent.py
│   ├── windows_event_collector.py
│   └── sysmonconfig.xml
│
├── compose.yaml
├── .gitignore
└── README.md
```

---

# Database Initialization

InsiderGuard currently uses SQLAlchemy metadata to initialize the database schema.

Database tables are created through:

```python
Base.metadata.create_all(bind=engine)
```

Initialize manually when running the backend outside Docker:

```bash
cd backend

python -m scripts.init_db
```

The project currently does **not depend on Alembic migrations** for database initialization.

---

# Current Database Schema

The platform currently uses tables including:

```text
users
login_events
failed_login_events
behavior_profiles
risk_assessments
alerts
incidents
incident_events
evidences
blockchain_blocks
raw_windows_events
normalized_windows_events
devices
investigation_reports
```

The exact schema may evolve as additional detection and telemetry modules are introduced.

---

# Docker Deployment

InsiderGuard AI can run as a Docker Compose stack.

Services include:

```text
Frontend
Backend
PostgreSQL
Redis
```

The Windows Event Collector runs directly on the Windows host because it requires access to the Windows Event Log API.

Architecture:

```text
Windows Host
│
├── Sysmon
├── Windows Event Log
└── Windows Collector
          │
          │ localhost:8000
          ▼
Docker
│
├── Backend
├── Frontend
├── PostgreSQL
└── Redis
```

---

# Running with Docker

## 1. Clone Repository

```bash
git clone https://github.com/quanhaom/InsiderGuard-AI.git

cd InsiderGuard-AI
```

---

## 2. Configure Environment

Create the required environment configuration based on the project environment variables.

Example development configuration:

```env
POSTGRES_USER=postgres
POSTGRES_PASSWORD=change_me
POSTGRES_DB=insiderguard

POSTGRES_HOST=postgres
POSTGRES_PORT=5432

DATABASE_URL=postgresql://postgres:change_me@postgres:5432/insiderguard

REDIS_HOST=redis
REDIS_PORT=6379
```

Do not commit production credentials or local `.env` files.

---

## 3. Start Docker Stack

```bash
docker compose up -d --build
```

Check services:

```bash
docker compose ps
```

Expected services:

```text
insiderguard-backend
insiderguard-frontend
insiderguard-postgres
insiderguard-redis
```

---

## 4. View Backend Logs

```bash
docker compose logs -f backend
```

Frontend:

```bash
docker compose logs -f frontend
```

PostgreSQL:

```bash
docker compose logs -f postgres
```

---

# Application URLs

## SOC Dashboard

```text
http://localhost:5173
```

## FastAPI Swagger

```text
http://localhost:8000/docs
```

---

# Windows Collector Setup

The real Windows collector must run directly on the monitored Windows endpoint.

It should not run inside the Linux backend container because it requires access to Windows Event Log APIs.

## Requirements

* Windows 10/11
* Python
* pywin32
* requests
* Administrator privileges for Security log access

Install dependencies:

```powershell
python -m pip install pywin32 requests
```

Verify Windows Event API access:

```powershell
python -c "import win32evtlog; print('Windows Event API OK')"
```

---

# Installing Sysmon

Download Microsoft Sysmon from the official Microsoft Sysinternals distribution.

Extract Sysmon and open PowerShell as Administrator.

Example:

```powershell
cd C:\Tools\Sysmon

.\Sysmon64.exe -accepteula -i
```

Verify service:

```powershell
Get-Service *sysmon*
```

Expected:

```text
Running  Sysmon64
```

Verify event channel:

```powershell
Get-WinEvent -ListLog *Sysmon*
```

Expected channel:

```text
Microsoft-Windows-Sysmon/Operational
```

---

# Apply InsiderGuard Sysmon Configuration

Apply the configuration included in the repository:

```powershell
.\Sysmon64.exe -c `
  C:\path\to\InsiderGuard-AI\tools\sysmonconfig.xml
```

Check active Sysmon configuration:

```powershell
.\Sysmon64.exe -c
```

The current configuration is intended to provide telemetry required for:

```text
Event 1 → Process Creation
Event 3 → Network Connection
```

---

# Running the Real Windows Collector

Open PowerShell **as Administrator**.

Navigate to the repository:

```powershell
cd C:\path\to\InsiderGuard-AI
```

Activate the Python environment if one is being used:

```powershell
.\backend\.venv\Scripts\Activate.ps1
```

Run:

```powershell
python tools\windows_event_collector.py
```

Expected output:

```text
=================================
 InsiderGuard Windows Collector
=================================

API: http://127.0.0.1:8000/api/v1/windows-events

Initial state:
{
  "Security": 123456,
  "Microsoft-Windows-Sysmon/Operational": 789
}

Listening for new Windows events...
```

New Windows events are then sent to the InsiderGuard backend.

---

# Collector State

The collector stores its last processed Event Record IDs in:

```text
tools/collector_state.json
```

This file is runtime state and should not be committed.

Add it to `.gitignore`:

```gitignore
tools/collector_state.json
```

The state mechanism prevents the collector from unnecessarily replaying all historical Windows events whenever it restarts.

---

# Testing Real Telemetry

## Sysmon Process Creation

With the collector running:

```powershell
notepad.exe
```

Inspect Sysmon:

```powershell
Get-WinEvent `
  -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    Id=1
  } `
  -MaxEvents 5
```

The collector should detect the new Sysmon Event 1 and send it to InsiderGuard.

---

## Sysmon Network Connection

Generate a normal HTTPS connection:

```powershell
curl.exe https://example.com
```

Inspect:

```powershell
Get-WinEvent `
  -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    Id=3
  } `
  -MaxEvents 5
```

The collector should process the resulting Sysmon network telemetry when Event 3 logging is enabled.

---

# Development Simulator

For deterministic development and testing, InsiderGuard retains a simulated Windows agent:

```text
tools/windows_agent.py
```

This allows developers to test specific security events without modifying the real Windows endpoint.

Use cases include:

* Parser development
* Detector testing
* Incident pipeline testing
* Regression testing
* Demo scenarios

The simulator should not be confused with the production-oriented Windows Event Collector.

---

# API Documentation

FastAPI automatically exposes interactive Swagger documentation:

```text
http://localhost:8000/docs
```

The API provides endpoints for modules such as:

* Windows events
* Alerts
* Incidents
* Evidence
* Blockchain
* UEBA
* Behavior profiles
* Threat hunting
* Investigation

---

# Example End-to-End Detection Flow

A privileged group modification may follow this pipeline:

```text
Windows Endpoint
       │
       ▼
Security Event 4728
       │
       ▼
Windows Collector
       │
       ▼
Raw Event
       │
       ▼
Parser4728
       │
       ▼
WindowsNormalizer
       │
       ▼
GroupMembershipDetector
       │
       ▼
PRIVILEGED_GROUP_MEMBERSHIP
       │
       ▼
Risk Score 85
       │
       ▼
CRITICAL Alert
       │
       ▼
Incident
       │
       ▼
Evidence
       │
       ▼
Blockchain Seal
       │
       ▼
AI Investigation
```

Example investigation output:

```text
Executive Summary

A CRITICAL insider-risk incident was detected
for a user following privileged group membership
activity.

Technical Analysis

The account was added to a security group
providing elevated administrative privileges.

MITRE ATT&CK

T1098 - Account Manipulation

Recommended Actions

Review the affected account, originating device,
related Windows telemetry, and administrative
activity.
```

---

# Demonstration Workflow

A typical InsiderGuard demonstration can include:

```text
1. Start Docker stack
        ↓
2. Start Windows collector
        ↓
3. Generate legitimate Windows activity
        ↓
4. Observe Windows/Sysmon telemetry
        ↓
5. InsiderGuard ingests event
        ↓
6. Parser + Normalizer process telemetry
        ↓
7. Detector evaluates activity
        ↓
8. Alert appears
        ↓
9. Incident is created
        ↓
10. Evidence is captured
        ↓
11. Blockchain integrity is verified
        ↓
12. AI Investigation Report is generated
```

This demonstrates the complete flow from endpoint telemetry to SOC investigation.

---

# Security Considerations

InsiderGuard AI is currently a research and development platform.

When deploying outside a local lab environment:

* Protect API endpoints with authentication
* Use TLS
* Do not expose PostgreSQL publicly
* Do not expose Redis publicly
* Store secrets securely
* Restrict Windows collector permissions
* Validate collector identity
* Implement API rate limiting
* Protect forensic evidence access
* Maintain audit logs
* Validate AI-generated investigation results

---

# Roadmap

## Completed

* FastAPI backend
* PostgreSQL integration
* SQLAlchemy database initialization
* React SOC frontend
* Docker deployment
* Docker Compose
* Redis integration
* Windows Event ingestion
* Real Windows Event Collector
* Sysmon integration
* Event normalization
* Windows Security Event 4624
* Windows Security Event 4625
* Windows Security Event 4672
* Windows Security Event 4688
* Windows Security Event 4720
* Windows Security Event 4728
* Sysmon Event 1
* Sysmon Event 3
* UEBA engine
* Behavioral profiling
* Risk scoring
* Failed login detection
* Privilege detection
* Suspicious process detection
* Account creation detection
* Privileged group membership detection
* Alert engine
* Incident engine
* Incident timeline
* Evidence vault
* SHA-256 evidence hashing
* Blockchain audit chain
* Blockchain verification
* Threat hunting
* MITRE ATT&CK mapping
* AI-assisted investigation reports

---

## In Progress

* SOC Dashboard improvements
* Real endpoint telemetry validation
* Sysmon detector tuning
* Detection false-positive reduction
* AI Investigator improvements
* MITRE ATT&CK coverage visualization

---

## Planned

### Endpoint Telemetry

* Sysmon Event 11 — File Create
* Sysmon Event 13 — Registry Value Set
* Sysmon Event 22 — DNS Query
* USB monitoring
* File activity monitoring

### Detection Engineering

* Correlation Engine
* Rule Engine
* Multi-event attack detection
* Detection rule configuration
* False-positive tuning

### Machine Learning

* Isolation Forest anomaly detection
* AutoEncoder anomaly detection
* Behavioral anomaly models
* Hybrid deterministic + ML scoring

### Response

* Automated response engine
* Email notifications
* Webhooks
* SOC integrations

### Infrastructure

* RabbitMQ
* CI/CD pipeline
* Production deployment
* Kubernetes
* Centralized logging
* Monitoring and observability

---

# Current Status

InsiderGuard AI currently supports a functional end-to-end pipeline:

```text
Real Windows Telemetry
        ↓
Collection
        ↓
Parsing
        ↓
Normalization
        ↓
Detection / UEBA
        ↓
Risk Scoring
        ↓
Alert
        ↓
Incident
        ↓
Timeline
        ↓
Evidence
        ↓
Blockchain Integrity
        ↓
AI Investigation
        ↓
SOC Dashboard
```

The project has moved beyond simulated event ingestion and can collect real Windows Security and Sysmon telemetry from a Windows endpoint.

It remains a research/development platform and continues to evolve toward a broader insider-threat detection and SOC investigation system.

---

# Development Notes

Runtime/generated files should not be committed.

Recommended `.gitignore` entries include:

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
venv/

# Node
node_modules/
dist/

# Environment
.env
.env.*
!.env.example

# Testing / Cache
.pytest_cache/
.mypy_cache/
.ruff_cache/

# IDE
.vscode/
.idea/

# Logs
*.log

# Windows collector
tools/collector_state.json

# OS
.DS_Store
Thumbs.db
```

---

# Contributing

Contributions, experiments, detection rules, parser improvements, and security research are welcome.

Areas of particular interest include:

* Windows telemetry
* Sysmon
* UEBA
* Threat detection
* Digital forensics
* MITRE ATT&CK
* Detection engineering
* SOC automation
* Machine learning for cybersecurity

---

# Author

**Phan Hoang Quan**

Cybersecurity Student

Areas of interest:

* Digital Forensics
* SOC Engineering
* Threat Hunting
* Insider Threat Detection
* Detection Engineering
* AI Security
* Backend Development

GitHub:

`quanhaom`

---

# Disclaimer

InsiderGuard AI is intended for cybersecurity research, education, defensive security monitoring, and authorized testing.

The platform should only be deployed on systems and networks where the operator has appropriate authorization.

AI-generated investigation results should be treated as analyst-assistance output and validated against the underlying telemetry and forensic evidence.

---

# License

Released under the **MIT License**.
