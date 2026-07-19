# InsiderGuard AI

> **AI-Powered Insider Threat Detection & Security Operations Platform**
>
> UEBA • Windows Event Analytics • MITRE ATT&CK • Threat Hunting • Digital Forensics • Blockchain Evidence Integrity

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue)
![React](https://img.shields.io/badge/React-Frontend-61DAFB)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

# Overview

**InsiderGuard AI** is a modern cybersecurity platform designed to detect, investigate, and respond to insider threats through behavioral analytics, Windows event monitoring, UEBA (User & Entity Behavior Analytics), MITRE ATT&CK mapping, and blockchain-based evidence integrity.

The platform combines:

* Behavioral baselining
* Risk scoring
* Threat detection
* Incident management
* Digital forensics
* Security operations monitoring

Unlike traditional login monitoring systems, InsiderGuard AI continuously analyzes user behavior and Windows security events to identify suspicious activities such as:

* Brute-force attacks
* Privilege escalation
* Suspicious PowerShell execution
* Living-off-the-Land (LOLBins) abuse
* Abnormal login behavior

---

# Key Capabilities

## Windows Event Collection

InsiderGuard collects and processes Windows Security Events.

Currently supported:

| Event ID | Description                 |
| -------- | --------------------------- |
| 4624     | Successful Login            |
| 4625     | Failed Login                |
| 4672     | Special Privileges Assigned |
| 4688     | Process Creation            |

Pipeline:

```text
Raw Windows Event
        ↓
Parser
        ↓
Normalization
        ↓
Detection Engine
        ↓
Alert
        ↓
Incident
        ↓
Evidence
        ↓
Blockchain
```

---

## User & Entity Behavior Analytics (UEBA)

Builds behavioral profiles for users and devices.

Behavioral features:

* Average login time
* Login frequency
* Common source IPs
* Login history
* Behavioral baseline

Risk scoring includes:

* Night logins
* Weekend logins
* New source IPs
* Abnormal login times

Risk Levels:

| Score  | Level    |
| ------ | -------- |
| 0–30   | LOW      |
| 31–60  | MEDIUM   |
| 61–80  | HIGH     |
| 81–100 | CRITICAL |

---

## Threat Detection Engine

### Brute Force Detection

Windows Event 4625

Detects:

* Consecutive failed logins
* Password spraying attempts
* Login bursts

---

### Privilege Escalation Detection

Windows Event 4672

Detects assignment of dangerous privileges:

* SeDebugPrivilege
* SeImpersonatePrivilege
* SeTakeOwnershipPrivilege
* SeLoadDriverPrivilege
* SeTcbPrivilege

---

### Suspicious Process Detection

Windows Event 4688

Monitors execution of high-risk binaries:

* powershell.exe
* cmd.exe
* rundll32.exe
* regsvr32.exe
* mshta.exe
* certutil.exe
* wmic.exe
* psexec.exe
* mimikatz.exe

Detects suspicious command-line arguments such as:

* EncodedCommand
* Base64 payloads
* Hidden PowerShell
* Invoke-Expression
* DownloadString
* LOLBin abuse

---

# MITRE ATT&CK Mapping

InsiderGuard automatically maps detections to MITRE ATT&CK techniques.

Examples:

| Process        | Technique |
| -------------- | --------- |
| powershell.exe | T1059.001 |
| cmd.exe        | T1059.003 |
| rundll32.exe   | T1218.011 |
| regsvr32.exe   | T1218.010 |
| mshta.exe      | T1218.005 |
| certutil.exe   | T1105     |
| wmic.exe       | T1047     |
| psexec.exe     | T1021.002 |
| mimikatz.exe   | T1003     |

---

# Incident Management

Automatically creates incidents for high-risk detections.

Features:

* Incident lifecycle
* Status management
* Analyst workflow
* Investigation support
* Timeline tracking

Incident statuses:

* OPEN
* INVESTIGATING
* RESOLVED
* CLOSED

---

# Incident Timeline

Every security event is tracked through a complete audit trail.

Examples:

* Incident Created
* Status Changed
* Evidence Captured
* Blockchain Sealed
* Suspicious Process Detected
* Privilege Escalation Detected

---

# Evidence Vault

Stores forensic snapshots for every incident.

Evidence contains:

* Alert information
* Detection results
* Risk score
* User behavior profile
* Investigation context

Integrity protection:

* SHA-256 hashing
* Immutable evidence records

---

# Blockchain Audit Chain

Every evidence snapshot is recorded into a blockchain-style audit chain.

Each block contains:

* Evidence ID
* Evidence Hash
* Previous Hash
* Block Hash
* Timestamp

Supports full chain verification.

---

# Threat Hunting

Provides security analysts with a searchable view of normalized security events.

Capabilities:

* Event investigation
* User activity review
* Process hunting
* Privilege activity review
* Timeline analysis

---

# Current Architecture

```text
Windows Security Events
          │
          ▼
Raw Event Collector
          │
          ▼
Event Normalization
          │
          ▼
Detection Engine
          │
          ▼
MITRE ATT&CK Mapping
          │
          ▼
Alert Engine
          │
          ▼
Incident Engine
          │
          ▼
Evidence Vault
          │
          ▼
Blockchain Integrity Layer
          │
          ▼
Threat Hunting
          │
          ▼
SOC Dashboard
```

---

# Project Structure

```text
backend/
│
├── app
│   ├── api
│   ├── core
│   ├── db
│   ├── models
│   ├── repositories
│   ├── schemas
│   ├── services
│   └── modules
│       ├── users
│       ├── events
│       ├── windows_events
│       ├── parsers
│       ├── behavior_profile
│       ├── ueba
│       ├── incidents
│       ├── evidence
│       ├── blockchain
│       ├── dashboard
│       ├── threat_hunting
│       └── investigator
│
├── alembic
├── scripts
├── tests
└── tools
```

---

# Technology Stack

Backend

* FastAPI
* SQLAlchemy
* Alembic
* Pydantic

Database

* PostgreSQL

Frontend

* React
* Vite
* Recharts

Security

* UEBA
* MITRE ATT&CK
* SHA-256
* Blockchain Evidence Chain

Development

* Git
* Docker (Planned)
* Pytest (Planned)

---

# API Documentation

Swagger UI:

```text
http://localhost:8000/docs
```

---

# Current Database Schema

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

---

# Roadmap

## Completed

* FastAPI Backend
* PostgreSQL Integration
* Alembic Migrations
* UEBA Engine
* Behavior Profiling
* Alert Engine
* Incident Engine
* Evidence Vault
* Blockchain Audit Chain
* Windows Event Ingestion
* Event Normalization
* Threat Hunting API
* MITRE ATT&CK Mapping
* Incident Timeline

---

## In Progress

* SOC Dashboard V2
* MITRE Coverage Dashboard
* AI Investigator

---

## Planned

* Sysmon Integration
* Event ID 4720 Detection
* Event ID 4728 Detection
* USB Monitoring
* File Activity Monitoring
* Isolation Forest Detection
* AutoEncoder Detection
* Redis
* RabbitMQ
* CI/CD Pipeline
* Docker Deployment
* Kubernetes

---

# Current Status

Estimated completion:

**≈ 80%**

The platform already supports a complete security event → alert → incident → evidence → blockchain workflow and is evolving toward a full SOC and insider threat detection platform.

---

# Author

**Phan Hoang Quan**

Cybersecurity Student

Interests:

* Digital Forensics
* SOC Engineering
* Threat Hunting
* Insider Threat Detection
* AI Security
* Backend Development

---

# License

Released under the MIT License.
