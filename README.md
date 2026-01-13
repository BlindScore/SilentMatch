# 🔒 SilentMatch (Prototype)

### Privacy-Preserving Fraud Detection Protocol

![Status](https://img.shields.io/badge/Status-Prototype-orange) ![Python](https://img.shields.io/badge/Made%20with-Python-blue) ![License](https://img.shields.io/badge/License-MIT-green)

## 📋 Overview
**SilentMatch** is a Private Set Intersection (PSI) tool designed to help financial institutions collaborate on fraud detection while remaining compliant with strict data privacy regulations (such as **Quebec's Law 25** and **GDPR**).

This protocol allows two parties (e.g., a Bank and a Fintech) to compute the intersection of their high-risk user lists **without ever revealing their non-shared data to each other.**

## ⚡ Key Features (v0.1)
* **Zero-Knowledge Exposure:** Uses SHA-256 hashing with cryptographic salting to obscure PII (Personally Identifiable Information).
* **Smart Normalization ETL:** Automatically cleans and standardizes messy data (emails, names) to ensure accurate matching despite input formatting errors.
* **Lightweight Architecture:** Python-based prototype optimized for rapid deployment and testing.

## 🛠️ Architecture
The current prototype implements a "Naive PSI" approach using hashed buckets.

```mermaid
graph LR
    A[Bank A Data] -->|Normalize & Hash| B(Secured Hashes)
    C[Fintech B Data] -->|Normalize & Hash| D(Secured Hashes)
    B --> E{SilentMatch Engine}
    D --> E
    E -->|Comparison| F[Intersection Found]
    F --> G[Risk Alert]
