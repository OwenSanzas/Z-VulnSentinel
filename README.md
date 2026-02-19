# VulnSentinel

Enterprise vulnerability early-warning system that detects security fixes in upstream libraries **at commit time** — before CVE disclosure — and assesses whether client code is affected.

## Problem

When an open-source library patches a vulnerability, the fix is public but the CVE is typically not assigned for weeks or months. Attackers can reverse-engineer the patch while downstream users remain unaware. Traditional detection methods (keyword matching, CVE databases, diff statistics) all operate at the syntax level and cannot determine whether a commit is a security fix.

## Approach

VulnSentinel uses LLMs to semantically analyze diffs and classify commits as security bugfixes in real time. When a fix is detected, the system automatically:

1. **Analyzes the vulnerability** — type, severity, affected versions
2. **Searches client code** — finds reachable call paths from entry points to the vulnerable function (via static analysis call graphs)
3. **Generates PoC** — attempts to produce a proof-of-concept exploit
4. **Alerts the client** — delivers a detailed vulnerability report

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Frontend                       │
│              React (Dashboard)                   │
└────────────────────┬────────────────────────────┘
                     │ REST API
┌────────────────────▼────────────────────────────┐
│                   Backend                        │
│              FastAPI (API Server)                 │
└───────┬────────────┬────────────────┬───────────┘
        │            │                │
        ▼            ▼                ▼
  ┌──────────┐ ┌──────────┐   ┌──────────────┐
  │PostgreSQL│ │ Engines  │   │   Engines    │
  │          │ │          │   │              │
  │ business │ │ monitor  │   │ static       │
  │ data     │ │ classify │   │ analysis     │
  │          │ │ (LLM)    │   │ call graph   │
  │          │ │          │   │ PoC gen      │
  └──────────┘ └──────────┘   └──────────────┘
```

| Layer | Stack | Role |
|-------|-------|------|
| Frontend | React | Dashboard, monitoring, alerts, reports |
| Backend | FastAPI | API gateway, auth, task scheduling, engine orchestration |
| Database | PostgreSQL + Neo4j | Business data (PostgreSQL), call graphs (Neo4j) |
| Engines | Python | Commit monitoring, LLM classification, static analysis, PoC generation |

## Project Structure

```
z_code_analyzer/       # Static analysis engine (SVF/Joern/Introspector backends)
docs/
  analyzer/            # z_code_analyzer design docs
  vulnsentinel/        # VulnSentinel system design docs
    frontend/          # Frontend page specs + data requirements
    backend/           # Backend API specs
    database/          # PostgreSQL schema + ER diagram
    engines/           # Engine design docs
tests/                 # Test suite
```

## Core Workflow

```
Client code → Extract dependencies → Monitor upstream libraries
                                              │
                                     Library commits a bugfix
                                              │
                                              ▼
                                   LLM classifies: security fix?
                                              │
                                     ┌────────┴────────┐
                                     │                 │
                                    YES               NO
                                     │                 │
                              Analyze vuln        Log & continue
                              Search call paths
                              Generate PoC
                                     │
                                ┌────┴────┐
                                │         │
                           Exploitable  Not affected
                                │         │
                           Alert client  Record
```

## Tech Stack

- **Python 3.12+**
- **FastAPI** — backend API
- **React** — frontend dashboard
- **PostgreSQL** — business data, relational queries
- **Neo4j** — function call graphs, reachability analysis
- **SVF / Joern / Introspector** — static analysis backends
