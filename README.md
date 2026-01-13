# 🔒 SilentMatch (Prototype)

### Privacy-Preserving Fraud Detection Protocol

![Status](https://img.shields.io/badge/Status-Prototype-orange) ![Python](https://img.shields.io/badge/Made%20with-Python-blue) ![License](https://img.shields.io/badge/License-MIT-green)

## 📋 Overview
**SilentMatch** is a Private Set Intersection (PSI) tool designed to help financial institutions collaborate on fraud detection while remaining compliant with strict data privacy regulations (such as **Quebec's Law 25** and **GDPR**).

This protocol allows two parties (e.g., a Bank and a Fintech) to compute the intersection of their high-risk user lists **without ever revealing their non-shared data to each other.**

## ⚡ Key Features (v0.1)
* **Zero-Knowledge OPRF Protocol:** Uses Oblivious Pseudorandom Functions with modular arithmetic to ensure neither party learns the other's data.
* **Multi-Attribute Matching:** Supports email, phone, SIN/NAS, and name fields for comprehensive identity verification.
* **Smart Normalization ETL:** Automatically cleans and standardizes messy data (emails, names) to ensure accurate matching despite input formatting errors.
* **Versioned Key Management:** Supports key rotation with automatic data archival for enhanced security.
* **Lightweight Architecture:** Python-based prototype optimized for rapid deployment and testing.

## 🛠️ Architecture
The current prototype implements an Oblivious Pseudorandom Function (OPRF) based Private Set Intersection (PSI) protocol for privacy-preserving fraud detection.

```mermaid
sequenceDiagram
    participant Bank as Bank/Fintech Client
    participant Server as SilentMatch Server

    Note over Bank,Server: Ingestion Phase (Risk Data Upload)
    Bank->>Bank: Normalize attributes (email, phone, SIN, name)
    Bank->>Bank: Map to group element H(attr)
    Bank->>Bank: Blind: H(attr)^r mod p
    Bank->>Server: Send blinded value
    Server->>Server: Sign: blinded^k mod p
    Server->>Bank: Return signed value + key version
    Bank->>Bank: Unblind: signed^(1/r) mod p → OPRF signature
    Bank->>Server: Register signature + risk metadata
    Server->>Server: Store in versioned ledger

    Note over Bank,Server: Verification Phase (Applicant Screening)
    Bank->>Bank: Normalize applicant attributes
    Bank->>Bank: Compute OPRF signatures (same process)
    Bank->>Server: Query signatures
    Server->>Server: Check against ledger
    Server->>Bank: Return matches (risk info) or clean status
    Bank->>Bank: Generate alerts for matches
