# Vault OS Facility

Integration layer (“Day 21”) for **Vault OS**: one Python package that composes the six subsystem apps (**Access**, **Devices**, **Events**, **Invites**, **Personnel**, **Vault**) without changing their code. It wires access checks, personnel, vault custody, devices, events/alerts, and invites behind a single `Facility` façade and a small CLI.

## Requirements

- **Python 3.11+**
- A **Vault OS workspace layout**: by default the package assumes `Facility/` lives under `VaultOS/` next to `Access/`, `Devices/`, `Events/`, `Invites/`, `Personnel/`, and `Vault/`. If your tree differs, set **`VAULTOS_ROOT`** to the directory that contains those folders.

## Install

From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Linux / macOS

pip install -r requirements.txt
# or minimal runtime only:
pip install -e .
```

For test dependencies only:

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
python -m facility facility init --save facility_state.json
python -m facility --state facility_state.json status
python -m facility --state facility_state.json access gate-check KC-0002 "Operations Wing"
```

Console entry point (after install):

```bash
vaultos-facility status
```

## What this package owns

- Device orchestration (Devices)
- Access workflows (Access)
- Personnel workflows (Personnel)
- Vault inventory custody (Vault)
- Event publishing and alerts (Events)
- Invite codes (Invites)

## Persistence

State is saved as **JSON** by the integration layer. Each snapshot includes **`schema_version`** (currently `1`). Older files without that field are treated as version 1. Newer unsupported versions raise a clear error at load time.

Subsystem apps stay unchanged; **facility** serializes and restores around their public (and documented restore) APIs.

## Layout

| Path | Role |
|------|------|
| `facility/core.py` | `Facility` type, construction, save/load entry points |
| `facility/operations/` | Domain mixins (personnel, access, vault, invites, events, devices) |
| `facility/persistence.py` | JSON record format, schema checks, round-trip |
| `facility/demo.py` | Seeded demo facility |
| `facility/cli.py` | `python -m facility` / `vaultos-facility` |
| `facility/bootstrap.py` | `sys.path` for sibling subsystems; `VAULTOS_ROOT` |
| `facility/adapters.py` | Imports and small helpers bridging subsystems |

## Tests

```bash
pytest tests/ -q
```
