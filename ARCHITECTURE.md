# Security Intelligence Platform Architecture v1

## Purpose

The platform separates three different decisions instead of merging them into one large dashboard.

```text
Observe / Interpret  →  Investigate / Relate  →  Prioritize  →  Act
```

| Layer | Tool | Primary question |
|---|---|---|
| Observe / Interpret | Security Intelligence Library | What is happening, and why does it matter? |
| Investigate / Relate | Threat Investigation | What is this entity, how is it related, and what is the evidence? |
| Prioritize | Vulnerability Intelligence | What should be addressed first? |
| Act | Operational / management process | What action should be taken? |

The tools remain separate user interfaces. They share concepts and navigation contracts instead of duplicating all functions.

## Threat Investigation responsibility

Threat Investigation is the investigation layer. It:

- resolves ATT&CK entities by name, alias, and ATT&CK ID;
- displays source-recorded ATT&CK metadata and relationships;
- separates direct evidence from dashboard-derived lenses and environment context;
- supports Threat Actor, Software, Technique, Campaign Profile, and Platform metadata investigation;
- accepts stable deep links from sibling tools;
- can hand environment context to Vulnerability Intelligence.

It does **not** own the news archive, vulnerability prioritization score, or a general-purpose asset inventory.

## Shared conceptual model

The common model is evidence-centric rather than merely entity-centric.

### Entities

- Threat Actor / ATT&CK Group
- Software / Malware / Tool
- Technique / Tactic
- Campaign
- Platform
- Vulnerability
- Vendor / Product
- Intelligence Item

### Evidence classes

1. **Source-recorded direct evidence** — e.g. ATT&CK relationship or platform metadata.
2. **External intelligence evidence** — e.g. government, vendor, or other CTI reporting.
3. **Dashboard-derived context** — e.g. curated Investigation Lens.
4. **Environment-derived context** — e.g. normalized overlap with My Environment.

A shared Technique, name normalization, or environment overlap must not silently become a direct relationship.

## Shared Context Layer

`My Environment` is a shared context layer, not a standalone intelligence source.

```text
My Environment
  ├─ Platforms
  ├─ Products
  └─ Technologies
       ↓
Saved Environment View
       ↓
Environment Overlay (per investigation)
```

Current shared localStorage key:

```text
peridotan-security-environment-v1
```

Threat Investigation must remain usable when My Environment is empty.

## Current Intelligence ownership

Current Intelligence is primarily owned by Security Intelligence Library.

The intended flow is:

```text
Security Intelligence Library
  Intelligence Item
       ↓ entity reference
Threat Investigation
       ↓ evidence-aware investigation
Vulnerability Intelligence (when relevant)
```

Threat Investigation receives an entity reference and optional navigation context. The navigation context is not automatically promoted to ATT&CK evidence.

## Cross-tool principles

- Deep links identify entities; they do not assert relationships.
- Source-recorded and derived relationships are displayed separately.
- No implicit Actor → CVE relationship is inferred from shared Techniques or Products.
- No proprietary risk score is created merely from relationship counts.
- Every tool keeps its own primary responsibility.

## Version direction

- v0.8.0: rename + Architecture v1 + entity deep-link foundation.
- v1.0.0: Architecture v1 is frozen as the stable public contract; feature growth moves to v1.1+.
- v0.8.x: Security Intelligence Library → Threat Investigation integration and evidence-aware cross-navigation.
- v0.9: shared Intelligence Item / Entity manifest refinement.
- v1.0: stable Security Intelligence Platform contracts.
