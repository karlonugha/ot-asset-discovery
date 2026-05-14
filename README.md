# OT Asset Discovery & Inventory Scanner

A full-stack platform for discovering, identifying, and monitoring Operational Technology (OT) devices on industrial networks. Passively sniffs network traffic, actively probes devices, builds a real-time inventory, scores risk, and presents everything through a React dashboard.

## Features

- **4 OT Protocol Parsers** — Modbus TCP, EtherNet/IP, S7comm, DNP3
- **Passive Network Capture** — Scapy AsyncSniffer in promiscuous mode, routes packets by port
- **Active Device Probing** — TCP probe requests with 5s timeout, 1 retry, 10-concurrent semaphore
- **Device Inventory** — MAC+IP uniqueness, merge logic (fill-null-only), audit history
- **Change Detection & Alerting** — New device (HIGH), disappeared (MEDIUM), firmware change (HIGH), new protocol (MEDIUM)
- **Risk Scoring** — Weighted sum: protocol (40%) + vulnerability (35%) + exposure (25%)
- **Topology Mapping** — Communication graph with packet counts, flush ≤60s, stale flag
- **JWT Auth + RBAC** — Viewer (read-only) and admin (full access) roles with rate limiting
- **REST API + WebSocket** — Devices, alerts, topology, scans, and CSV/JSON/PDF export
- **Scan Scheduling** — Cron-based with ≥5min validation, overlap detection, failure alerts
- **React Dashboard** — Device table, force-directed topology graph, real-time alert feed, scan management

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11+, FastAPI, Uvicorn |
| Database | PostgreSQL, SQLAlchemy (async), Alembic |
| Packet Capture | Scapy (AsyncSniffer) |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Data Fetching | @tanstack/react-query, WebSocket |
| Visualization | react-force-graph |
| Auth | JWT (python-jose), bcrypt (passlib) |
| Testing | pytest (700 tests), vitest (35 tests) |

## Project Structure

```
ot-asset-discovery/
├── app/
│   ├── api/              # FastAPI routers + WebSocket endpoints
│   ├── capture/          # PassiveSniffer + ActiveProber
│   ├── parsers/          # Modbus, EtherNet/IP, S7comm, DNP3
│   ├── detection/        # ChangeDetector (alerts)
│   ├── scoring/          # RiskScorer (weighted sub-scores)
│   ├── topology/         # TopologyMapper (communication graph)
│   ├── scheduling/       # ScanScheduler (cron + manual)
│   ├── export/           # CSV, JSON, PDF export service
│   ├── db/               # DeviceRepository, session management
│   ├── models/           # Pydantic domain + SQLAlchemy ORM models
│   ├── discovery_engine.py  # Orchestrator wiring all components
│   └── event_bus.py      # Async pub/sub for decoupled communication
├── frontend/
│   ├── src/components/   # React dashboard components
│   ├── src/hooks/        # Custom hooks (useDevices, useAlertWebSocket)
│   └── src/types/        # TypeScript interfaces
├── tests/                # 700 unit tests (pytest)
├── alembic/              # Database migrations
└── pyproject.toml        # Python dependencies
```

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Node.js 18+

### Backend Setup

```bash
# Install Python dependencies
pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
# Edit .env with your PostgreSQL connection string

# Run database migrations
alembic upgrade head

# Start the API server
uvicorn app.api:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

### Running Tests

```bash
# Backend tests (700 tests)
pytest tests/ -q

# Frontend tests (35 tests)
cd frontend && npm test
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List devices with filtering and pagination |
| GET | `/api/devices/{id}` | Device detail with audit history |
| POST | `/api/devices` | Create device (admin) |
| PUT | `/api/devices/{id}` | Update device (admin) |
| DELETE | `/api/devices/{id}` | Delete device (admin) |
| GET | `/api/alerts` | List alerts with filtering |
| GET | `/api/topology` | Network topology graph |
| GET/POST/PUT/DELETE | `/api/scans` | Scan schedule CRUD |
| POST | `/api/scans/{id}/trigger` | Manual scan trigger |
| GET | `/api/scans/{id}/history` | Scan execution history |
| GET | `/api/export/csv` | Export inventory as CSV |
| GET | `/api/export/json` | Export inventory as JSON |
| GET | `/api/export/pdf` | Export inventory as PDF report |
| WS | `/ws/alerts` | Real-time alert stream |
| WS | `/ws/topology` | Topology event stream |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    React Dashboard                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Devices  │ │ Topology │ │  Alerts  │ │  Scans   │       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
└───────┼─────────────┼────────────┼────────────┼─────────────┘
        │ REST        │ REST       │ WebSocket  │ REST
┌───────┼─────────────┼────────────┼────────────┼─────────────┐
│       ▼             ▼            ▼            ▼              │
│                    FastAPI + WebSocket                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Discovery Engine (Orchestrator)           │   │
│  │                                                       │   │
│  │  ┌─────────┐  ┌─────────────┐  ┌──────────────┐     │   │
│  │  │ Passive │  │   Change    │  │    Risk      │     │   │
│  │  │ Sniffer │──│  Detector   │──│   Scorer     │     │   │
│  │  └─────────┘  └─────────────┘  └──────────────┘     │   │
│  │  ┌─────────┐  ┌─────────────┐  ┌──────────────┐     │   │
│  │  │ Active  │  │  Topology   │  │    Event     │     │   │
│  │  │ Prober  │──│   Mapper    │──│     Bus      │     │   │
│  │  └─────────┘  └─────────────┘  └──────────────┘     │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                   │
│                    ┌──────┴──────┐                            │
│                    │ PostgreSQL  │                            │
│                    └─────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

## Risk Scoring

The risk score (0-100) is a weighted sum of three factors:

| Factor | Weight | Calculation |
|--------|--------|-------------|
| Protocol | 40% | 25pts per insecure protocol, 5pts per secure, capped at 100 |
| Vulnerability | 35% | Critical=100, High=75, Medium=50, Low=25, None=0 |
| Exposure | 25% | 0 peers→0, 1-5→25, 6-15→50, 16-30→75, >30→100 |

When the vulnerability database is unavailable, protocol and exposure are re-normalized to 100%.

## Supported OT Protocols

| Protocol | Parser | Identity Fields Extracted |
|----------|--------|--------------------------|
| Modbus TCP | Function code 0x2B, MEI 0x0E | Vendor, model, firmware (objects 0x00-0x06) |
| EtherNet/IP | List Identity (cmd 0x0063) | Vendor ID, device type, product code, revision, serial, product name |
| S7comm | SZL 0x0011 / 0x001C | PLC type, module name, firmware version, serial number |
| DNP3 | Object Group 0 (Device Attributes) | Manufacturer, model, firmware, serial (variations 246-254) |

## License

MIT
