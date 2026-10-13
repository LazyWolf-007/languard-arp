# Architecture and trust model

## Components

- `backend/app/models.py`: validated Pydantic data contracts for devices, observations, mappings, alerts, decisions, events, and metrics.
- `backend/app/engine.py`: deterministic mapping assessment and evaluation calculation, independent of HTTP.
- `backend/app/simulation.py`: labelled normal, spoof, and one-click demonstration observations.
- `backend/app/state.py`: in-memory baseline and state snapshot.
- `backend/app/api.py`: REST commands, WebSocket snapshots, and simulation scenarios.
- `backend/app/main.py`: FastAPI application and local Vite CORS policy.
- `src/App.tsx`: responsive React dashboard; each control issues a backend request and receives WebSocket state updates.

## API outline

| Route | Purpose |
| --- | --- |
| `GET /api/state` | Current authoritative snapshot |
| `GET /api/health` | Service and simulation-only status |
| `POST /api/observations` | Validate and process an ARP observation |
| `POST /api/mode/{monitoring\|enforcement}` | Change simulated mitigation mode |
| `POST /api/monitoring/{start\|stop}` | Pause/resume observation processing |
| `POST /api/simulation/{normal\|spoof\|demo}` | Submit labelled example scenarios through the detection engine |
| `POST /api/reset` | Restore trusted baseline and clear the lab history |
| `WS /api/ws` | Send the current snapshot after each state-changing operation |

## Trust and uncertainty

The gateway and two clients begin with explicit trusted IP-to-MAC records. The simulated rogue has an identity but no trusted mapping. First-seen mappings remain unverified in monitoring mode and do not silently become trusted baselines; conflicting subsequent claims and suspicious unsolicited claims are flagged. A changed claim is suspicious when it differs from an established trusted MAC; an explicitly labelled `legitimate` observation can update that baseline without generating an alert. Enforcement rejects updates without a trusted baseline. This lab cannot infer legitimacy from real DHCP, switch, or administrator data, so labels represent scenario ground truth, not an automatic guarantee.

In monitoring mode the trusted mapping remains authoritative while the observation and decision are logged. Enforcement mode records a simulated rejection and preserves the trusted mapping. No network layer is involved.

## Evaluation

Only labelled simulation scenarios count toward evaluation. A positive scenario is a true positive if an alert references its scenario ID, otherwise a false negative. A negative scenario with an alert is a false positive; without an alert it is a true negative. Precision is `TP/(TP+FP)` and recall is `TP/(TP+FN)`; either is unavailable (`null`) when its denominator is zero. Mean detection latency averages measured in-process rule evaluation time for positive labelled alerts. It excludes transport, scheduling, and network latency. Unlabelled observations are counted separately and excluded. This is not measured real-network performance.

## Boundaries

Initial state is in memory and resets on process restart. The WebSocket broadcasts whole authoritative snapshots, keeping browser state aligned with REST state. CORS is limited to local Vite origins. There is no database, authentication, packet capture, attack traffic, or host network configuration code.
