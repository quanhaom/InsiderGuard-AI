# InsiderGuard AI

> **Enterprise Insider Threat Detection Platform powered by AI, UEBA, Digital Behavior Twin, and Blockchain Evidence Integrity.**

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-green)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## Overview

**InsiderGuard AI** is an enterprise-style cybersecurity platform designed to detect and investigate insider threats through behavioral analytics, User & Entity Behavior Analytics (UEBA), digital behavior profiling, blockchain-based evidence integrity, and AI-assisted investigations.

Unlike traditional login monitoring systems, InsiderGuard AI analyzes user behavior over time, calculates dynamic risk scores, automatically creates security incidents, preserves forensic evidence, and ensures evidence integrity through a tamper-evident blockchain audit chain.

The project is built as a modular, production-oriented backend using **FastAPI**, **PostgreSQL**, **SQLAlchemy**, and **Alembic**.

---

# Features

## User & Event Management

* User management
* Login event ingestion
* Event history
* PostgreSQL persistence

---

## Digital Behavior Twin

Builds a behavioral profile for each employee, including:

* Average login time
* Common source IP
* Login frequency
* Behavioral baseline

---

## UEBA Risk Engine

Calculates user risk scores using behavioral rules.

Current rules include:

* Night login
* Weekend login
* New IP address
* Abnormal login time

Risk Levels

| Score  | Level    |
| ------ | -------- |
| 0–30   | LOW      |
| 31–60  | MEDIUM   |
| 61–80  | HIGH     |
| 81–100 | CRITICAL |

---

## Incident Engine

Automatically creates security incidents when abnormal behavior is detected.

Features

* Automatic incident generation
* Incident history
* Incident status management
* Investigation workflow

---

## Evidence Vault

Stores immutable forensic snapshots for every incident.

Evidence contains:

* Incident details
* Behavior profile
* Risk assessment
* Triggered rules
* SHA-256 integrity hash

---

## Blockchain Audit Chain

Every evidence snapshot is recorded into a private blockchain-like audit chain.

Each block stores:

* Evidence ID
* Evidence SHA-256
* Previous Block Hash
* Current Block Hash
* Timestamp

Supports integrity verification for the complete chain.

---

# Current Architecture

```
Login Event
      │
      ▼
Behavior Twin
      │
      ▼
UEBA Risk Engine
      │
      ▼
Risk Assessment
      │
      ▼
Incident Engine
      │
      ▼
Evidence Vault
      │
      ▼
Blockchain Audit Chain
```

---

# Project Structure

```
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
│       ├── behavior_twin
│       ├── ueba
│       ├── incidents
│       ├── evidence
│       ├── blockchain
│       └── investigator
│
├── alembic
├── tests
└── scripts
```

---

# Technology Stack

Backend

* FastAPI
* SQLAlchemy
* Pydantic
* Alembic

Database

* PostgreSQL

Security

* SHA-256
* Blockchain Audit Chain
* UEBA
* Digital Behavior Twin

Development

* Git
* Docker (planned)
* Pytest (planned)

---

# API Modules

Current REST APIs

* Users
* Login Events
* Behavior Twin
* UEBA
* Risk Assessment
* Incidents
* Evidence
* Blockchain

Swagger

```
http://localhost:8000/docs
```

---

# Database

Current schema

```
users

login_events

behavior_profiles

risk_assessments

incidents

evidences

blockchain_blocks
```

---

# Roadmap

## Completed

* FastAPI Backend
* PostgreSQL
* SQLAlchemy
* Alembic Migration
* Behavior Twin
* UEBA
* Risk Assessment
* Incident Engine
* Evidence Vault
* Blockchain Audit Chain

---

## In Progress

* AI Investigator

---

## Planned

* MITRE ATT&CK Mapping
* Windows Event Collector
* Sysmon Collector
* USB Monitoring
* File Activity Monitoring
* Isolation Forest Detection
* AutoEncoder Detection
* SOC Dashboard
* Docker Deployment
* Redis
* RabbitMQ
* CI/CD Pipeline
* Kubernetes

---

# Future Architecture

```
Windows Collector
        │
        ▼
Event Collector API
        │
        ▼
Behavior Twin
        │
        ▼
UEBA
        │
        ▼
Risk Assessment
        │
        ▼
Incident
        │
        ▼
Evidence Vault
        │
        ▼
Blockchain
        │
        ▼
AI Investigation
        │
        ▼
SOC Dashboard
```

---

# Current Status

This project is under active development.

Current completion estimate:

**≈ 65%**

---

# Author

**Phan Hoang Quan**

Cybersecurity Student

Interested in

* Digital Forensics
* SOC Engineering
* Insider Threat Detection
* AI Security
* Backend Development

---

# License

This project is released under the MIT License.
