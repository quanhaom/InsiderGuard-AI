# Blockchain Evidence Preservation

## Objective

Preserve evidence integrity.

## Evidence Flow

Incident
    ↓
Evidence Generation
    ↓
SHA256 Hash
    ↓
Blockchain Ledger

## Block Structure

{
  "index":1,
  "timestamp":"",
  "incident_id":"INC-001",
  "evidence_hash":"",
  "previous_hash":"",
  "block_hash":""
}

## Verification

Current Evidence
    ↓
SHA256
    ↓
Compare
    ↓
Blockchain Ledger

If Match:
Evidence Valid

If Mismatch:
Evidence Tampered