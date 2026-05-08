# Architecture Decision Record

## App 21 — Vault OS Facility

**Vault OS Group | Document 1 of 5**

**Status:** Accepted  
**Date:** 2026-05-08

---

## Title

Use a composition-first Facility façade to integrate the six Vault OS subsystem apps without modifying their code.

---

## Context

Vault OS already has six separate subsystem applications:

- **Access** for keycards, gates, access decisions, access logs, and suspicious activity monitoring.
- **Devices** for cameras, locks, alarms, thermostats, and a device panel.
- **Events** for publish/subscribe event routing, alert generation, event logs, deduplication, and alert state.
- **Invites** for temporary invite codes, validation, usage, revocation, expiry, and state summaries.
- **Personnel** for employees, visitors, contractors, check-in/check-out state, and on-site headcount.
- **Vault** for secure inventory, item custody, access levels, check-out/check-in, reconciliation, and audit records.

The goal of App 21 is not to rewrite those systems. The goal is to prove that they can be treated as subsystem boundaries and composed behind one integration package. The resulting package, `vaultos-facility`, provides a `Facility` object that coordinates cross-system workflows and a small command-line interface for common operations.

The important constraint is authorship and scope discipline: the six apps remain independent, and the integration layer owns only the glue code, orchestration rules, persistence snapshot, and façade API. This makes the project more architectural than algorithmic. Its value comes from wiring, boundaries, data movement, and operational consistency rather than from a new isolated feature.

---

## Decision Drivers

- **Preserve subsystem ownership.** Access, Devices, Events, Invites, Personnel, and Vault should continue to work as separate apps.
- **Avoid copied shared logic.** The Facility package should import sibling projects rather than duplicate their internals.
- **Keep App 21 scoped as an integration layer.** It should be a small façade and CLI, not a monolithic rewrite.
- **Expose cross-system workflows.** Operations like vault checkout must account for access cards, personnel presence, vault permissions, and event publication.
- **Make state portable.** The integrated system should save and load a JSON snapshot of composed subsystem state.
- **Keep the CLI approachable.** The CLI should demonstrate the integration without becoming a full interactive shell.
- **Maintain testability.** A demo facility should create deterministic enough state for integration and persistence tests.

---

## Options Considered

### Option 1 — Merge all subsystem code into one package

**Description:** Copy Access, Devices, Events, Invites, Personnel, and Vault into one `facility` package and refactor everything together.

**Rejected.**

This would make imports simple but would destroy the main learning goal. The purpose of the project is to compose existing subsystem apps, not erase their boundaries. A merge would also make it harder to demonstrate that earlier apps were independently designed and then integrated.

---

### Option 2 — Use a service-style architecture with separate processes

**Description:** Run each subsystem as an independent service and have Facility communicate through HTTP, sockets, queues, or subprocess calls.

**Rejected for App 21.**

This is a realistic production direction, but it would be too large for the academic scope of this app. It would require protocol design, service lifecycle management, authentication, network failures, and probably persistence per service. The portfolio goal here is software architecture and integration, not distributed systems.

---

### Option 3 — Import subsystem packages directly and coordinate them through a façade

**Description:** Use a package-level bootstrap to place sibling subsystem folders on `sys.path`, import each subsystem’s public classes and helpers through an adapter module, and expose a composed `Facility` object.

**Chosen.**

This option keeps the subsystem apps unchanged while allowing the integration layer to coordinate them in process. It is the right scope for a CLI portfolio app: it demonstrates integration, object composition, adapters, persistence, and cross-domain workflows without requiring a distributed runtime.

---

### Option 4 — Store only Facility-owned state and rebuild subsystems from demo seeds every time

**Description:** Persist only extra Facility mappings such as person-to-keycard links and device locations, while re-creating all subsystem state on startup.

**Rejected.**

This would be simple, but it would fail the persistence requirement. If vault custody, invite usage, access logs, device state, and event history are not saved, the integrated system cannot resume accurately. The app needs a real snapshot that includes the state of all major subsystems.

---

### Option 5 — Save each subsystem using its own independent persistence mechanism

**Description:** Ask each subsystem to own its own state file and make Facility reference them.

**Rejected for current codebase.**

The six subsystem apps do not all expose the same persistence interface. Requiring that would force changes across all six apps, which violates the “compose without changing their code” constraint. A single integration-layer snapshot is a better fit for this stage.

---

## Decision

App 21 will use a **composition-first Facility façade**.

The package defines:

- `facility.core.Facility` as the central object.
- `facility.adapters` as the subsystem import and translation layer.
- `facility.bootstrap` to locate sibling subsystem folders through `VAULTOS_ROOT` or the expected workspace layout.
- `facility.operations.*` mixins for access, personnel, vault, invites, events, and devices.
- `facility.persistence` for JSON serialization, schema version checks, and restoration.
- `facility.demo` for seeded demo state.
- `facility.cli` for command-line workflows.
- `facility.__main__` so `python -m facility` works.
- A console script entry point, `vaultos-facility`.

The `Facility` object owns references to subsystem objects rather than replacing them. It composes:

- `DevicePanel`
- `AccessController`
- `PersonnelRegistry`
- `Vault`
- `EventBus`
- `AlertManager`
- `InviteManager`
- `LogHandler`

It also owns integration-only mappings:

- `person_keycards`
- `device_locations`

---

## Rationale

The façade pattern is appropriate because the app needs one simple interface over several independent subsystems. A caller should not have to know how to manually coordinate a keycard registry, a personnel registry, a vault inventory, and an event bus for every operation. The façade becomes the place where cross-domain policies live.

For example, `vault_checkout()` is not just a Vault operation. It resolves a requester through personnel/keycard mappings, checks that the keycard is usable, verifies that a known person is on-site, maps Access access levels to Vault access levels, calls the Vault subsystem, and publishes success or denial events. That orchestration belongs in Facility, not inside Vault, because Vault should not need to know about personnel presence or access cards.

The mixin structure keeps the façade from becoming one long file. Each operation module owns one domain:

- `operations/access.py` owns gate checks and card revocation side effects.
- `operations/personnel.py` owns registration, check-in/check-out, and card/person resolution.
- `operations/vault.py` owns integrated custody flows.
- `operations/invites.py` owns invite generation, validation, use, and review.
- `operations/events.py` owns event publication, active alerts, history, and dashboard summaries.
- `operations/devices.py` owns breach simulation using demo devices.

The adapter module is a deliberate boundary. It centralizes imports, aliases naming collisions such as Access vs. Vault access levels, and provides small conversion helpers. This keeps the rest of the integration code readable.

---

## Trade-offs Accepted

### `sys.path` bootstrap instead of packaged dependencies

The repo expects sibling folders for `Access`, `Devices`, `Events`, `Invites`, `Personnel`, and `Vault`, or a `VAULTOS_ROOT` environment variable. This is less polished than published packages, but it fits the portfolio layout and avoids copying code.

### One large JSON snapshot

A single snapshot is easier to inspect, test, and move around. The trade-off is that persistence code must know how to serialize and restore many subsystem objects, including private state for some devices. That is acceptable for an integration app, but it is not ideal long-term.

### In-process integration

All subsystems run in the same Python process. This keeps the project simple and testable, but it means subsystem failures are not isolated. A bug in one imported subsystem can affect the whole Facility process.

### CLI as a demonstration surface

The CLI covers common workflows but does not expose every possible subsystem operation. The goal is to demonstrate integration, not to replace every individual subsystem CLI.

### Manual schema versioning

The snapshot includes `schema_version`, currently `1`. This is lightweight and understandable. The trade-off is that migrations are not yet implemented beyond accepting missing legacy schema version as version 1 and rejecting future unsupported versions.

---

## Consequences

### Positive Consequences

- The app demonstrates architectural composition across multiple prior projects.
- Each subsystem remains independently meaningful.
- Cross-system workflows become easy to call from code or CLI.
- Facility can save and restore integrated state.
- Tests can verify not only unit behavior but end-to-end subsystem interaction.
- The project introduces real integration concerns: bootstrapping, adapters, façade design, persistence contracts, and schema compatibility.

### Negative Consequences

- The app is sensitive to workspace layout.
- The adapter imports depend on subsystem module names staying stable.
- Persistence is coupled to subsystem object internals.
- The JSON snapshot can become large and complex.
- The CLI needs a demo default because full production setup is outside the app’s scope.
- The integration layer has to handle naming collisions, especially access level types.

---

## Superseded By

A future version could supersede this decision by packaging each subsystem as an installable dependency and replacing `sys.path` bootstrapping with proper dependency declarations. Another future version could split persistence into subsystem-owned snapshot adapters, or move toward a service-based architecture with explicit APIs between systems.

---

# Technical Design Document

## App 21 — Vault OS Facility

**Vault OS Group | Document 2 of 5**

---

## Purpose & Scope

Vault OS Facility is an integration package for the six Vault OS subsystem apps:

1. Access
2. Devices
3. Events
4. Invites
5. Personnel
6. Vault

Its purpose is to provide a single Facility façade and CLI that can coordinate cross-system operations.

The package owns:

- Import bootstrapping for sibling Vault OS projects.
- Adapter aliases and translation helpers.
- Facility object construction.
- Cross-system workflow methods.
- Demo facility seeding.
- JSON snapshot persistence.
- Schema version validation.
- CLI command dispatch.

The package does not own:

- The internal business logic of Access, Devices, Events, Invites, Personnel, or Vault.
- A network server.
- Authentication beyond the keycard/access model already present in the subsystems.
- A database.
- Background scheduling.
- Multi-user concurrency.
- A fully complete facility management product.

---

## System Context

The expected workspace layout is:

```text
VaultOS/
  Access/
  Devices/
  Events/
  Invites/
  Personnel/
  Vault/
  Facility/
    facility/
    tests/
    pyproject.toml
    README.md
```

If the repository is not in that layout, the user sets:

```bash
VAULTOS_ROOT=/path/to/VaultOS
```

The Facility package then appends the sibling subsystem folders to `sys.path` so imports such as `from access_control import AccessController` and `from devices import Camera` can resolve.

The installed package name is:

```text
vaultos-facility
```

The console script is:

```text
vaultos-facility
```

The module entry point is:

```bash
python -m facility
```

---

## Component Breakdown

### `facility.bootstrap`

Responsible for locating the Vault OS workspace root and injecting subsystem folders into `sys.path`.

Key responsibilities:

- Read `VAULTOS_ROOT` when present.
- Otherwise infer the root from the Facility package location.
- Append `Access`, `Devices`, `Events`, `Invites`, `Personnel`, and `Vault` folders to `sys.path`.
- Avoid duplicate path insertion.

This is the lowest-level integration component because all subsystem imports depend on it.

---

### `facility.adapters`

Responsible for importing subsystem classes and defining bridge helpers.

Major imported groups:

- Access: `AccessController`, `Keycard`, `AccessGate`, `AccessDecision`, `CardRegistry`, `SuspiciousActivityMonitor`, `build_demo_controller`, and access-level types.
- Devices: `Device`, `Camera`, `Lock`, `AlarmSystem`, `Thermostat`, device exceptions, and device log models.
- Events: `Event`, `EventBus`, `AlertManager`, `AlertHandler`, `LogHandler`, `Severity`, and event formatting.
- Invites: `InviteManager`, `InviteCode`, invite states, validation results, invite errors, and usage logs.
- Personnel: `Person`, `Employee`, `Visitor`, `Contractor`, `PersonnelRegistry`, and check-in errors.
- Vault: `Vault`, `Item`, vault access levels, item status, item condition, custody records, and vault errors.
- Devices panel: `DevicePanel`, demo constants, and `seed_demo_panel`.

Bridge helpers include:

- `ACCESS_TO_VAULT_LEVEL`
- `parse_access_level()`
- `to_vault_access_level()`
- `to_utc()`
- `facility_date()`
- `parse_schedule()`
- `schedule_record()`
- `money_string()`
- `PERSON_TYPES`
- `DEVICE_TYPES`

This module is intentionally import-heavy because it centralizes the boundary between the integration layer and subsystem packages.

---

### `facility.core`

Defines:

- `FacilityError`
- `FacilityStateError`
- `Facility`

`Facility` inherits from six operation mixins:

```python
class Facility(
    FacilityPersonnelMixin,
    FacilityAccessMixin,
    FacilityVaultMixin,
    FacilityInvitesMixin,
    FacilityEventsMixin,
    FacilityDevicesMixin,
):
    ...
```

The constructor accepts all subsystem instances:

- `device_panel`
- `access`
- `personnel`
- `vault`
- `event_bus`
- `alert_manager`
- `invite_manager`
- `event_log`

It also accepts integration mappings:

- `person_keycards`
- `device_locations`

Core factory and persistence methods:

- `Facility.create_demo()`
- `Facility._build_event_stack()`
- `Facility.save(path)`
- `Facility.load(path)`
- `Facility.to_record()`
- `Facility.from_record(record)`

---

### `facility.demo`

Seeds a realistic demo facility.

Demo people include:

- `EMP-001` Jordan Lee
- `EMP-002` Sam Rivera
- `EMP-003` Riley Chen
- `VIS-001` Avery Stone
- `CTR-001` Taylor Brooks

Demo behavior includes:

- Registering employees, visitor, and contractor.
- Issuing/linking a contractor keycard.
- Linking visitor keycard `KC-0001`.
- Checking several people in.
- Generating a staff-level invite.
- Publishing a `FACILITY_INITIALIZED` event.
- Exposing demo device codes from Devices constants through the event message.

The demo factory gives tests and CLI commands usable default state.

---

### `facility.operations.personnel`

Responsible for:

- Registering people.
- Linking person IDs to keycards.
- Checking people in.
- Checking people out.
- Resolving a person from a card.
- Resolving an actor from either person ID or card ID.
- Enforcing contractor date validity.
- Publishing personnel events.
- Warning when a person leaves while still holding vault items.

Important methods:

- `register_person()`
- `link_person_keycard()`
- `personnel_check_in()`
- `personnel_check_out()`
- `require_person()`
- `card_id_for_person()`
- `person_for_card()`
- `resolve_actor()`

---

### `facility.operations.access`

Responsible for:

- Integrated gate checks.
- Contractor restricted-area denial.
- Access log and suspicious activity handling.
- Publishing access events.
- Revoking keycards.
- Reviewing active invites when a keycard access level is revoked.
- Checking that a keycard is usable before sensitive operations.

Important methods:

- `gate_check()`
- `revoke_keycard()`
- `_ensure_card_is_usable()`

---

### `facility.operations.vault`

Responsible for:

- Integrated vault checkout.
- Integrated vault check-in.
- Enforcing that a known person must be on-site before checking out vault items.
- Mapping Access access levels to Vault access levels.
- Publishing vault success and denial events.
- Escalating expensive item checkout to warning severity.

Important methods:

- `vault_checkout()`
- `vault_check_in()`
- `items_checked_out_by_holder()`

---

### `facility.operations.invites`

Responsible for:

- Reviewing active invite summaries for a target access level.
- Generating invite codes through the InviteManager.
- Validating invite codes.
- Consuming invite codes.
- Publishing invite lifecycle events.

Important methods:

- `review_invites_for_access_level()`
- `generate_invite()`
- `validate_invite()`
- `use_invite()`

---

### `facility.operations.events`

Responsible for:

- Publishing events to the event bus.
- Reading event history.
- Listing active alerts.
- Building status dashboard dictionaries.

Important methods:

- `publish_event()`
- `event_history()`
- `active_alerts()`
- `status_dashboard()`

The dashboard aggregates:

- Device panel status.
- Personnel on-site counts by person type.
- Active alert count.
- Vault summary.
- Checked-out vault items.
- Recent formatted event lines.

---

### `facility.operations.devices`

Responsible for the integrated breach simulation.

`simulate_breach()`:

- Ensures the demo camera, lock, and alarm are powered on.
- Starts camera recording if needed.
- Publishes motion detection.
- Attempts invalid lock unlocks.
- Publishes forced-entry attempts.
- Arms/triggers the alarm.
- Publishes an alarm-triggered critical event.
- Returns only the events created by the simulation.

This method demonstrates Devices + Events + Alerts working together.

---

### `facility.persistence`

Responsible for:

- Serializing a live Facility into a JSON-compatible record.
- Restoring a Facility from a record.
- Writing and reading JSON files.
- Validating `schema_version`.
- Serializing and restoring subsystem state.

Top-level record fields:

```text
schema_version
name
device_locations
person_keycards
devices
access
personnel
vault
events
invites
```

Current schema:

```text
FACILITY_RECORD_VERSION = 1
```

Version behavior:

- Missing `schema_version` is treated as version 1.
- Invalid schema types are rejected.
- Versions below 1 are rejected.
- Future versions above the current maximum are rejected with a clear `FacilityStateError`.

---

### `facility.cli`

Responsible for:

- `argparse` parser construction.
- Global `--state` and `--save` options.
- Command dispatch.
- State resolution.
- CLI error handling.
- Human-readable status output.

Supported command domains:

- `facility`
- `status`
- `access`
- `personnel`
- `vault`
- `invite`
- `event`
- `alert`
- `simulate-breach`

The parser normalizes global options so `--state` and `--save` can be accepted even when users place them after subcommands.

---

## Module Dependency Graph

```text
facility.__main__
  -> facility.cli

facility.cli
  -> facility.core
  -> facility.adapters

facility.core
  -> facility.adapters
  -> facility.operations.personnel
  -> facility.operations.access
  -> facility.operations.vault
  -> facility.operations.invites
  -> facility.operations.events
  -> facility.operations.devices
  -> facility.demo
  -> facility.persistence

facility.adapters
  -> facility.bootstrap
  -> Access subsystem
  -> Devices subsystem
  -> Events subsystem
  -> Invites subsystem
  -> Personnel subsystem
  -> Vault subsystem

facility.persistence
  -> facility.adapters
  -> facility.core

facility.demo
  -> facility.adapters
  -> facility.core

facility.operations.*
  -> facility.adapters
  -> facility.core typing/errors
```

---

## Core Algorithms & Logic

### Workspace Bootstrapping

1. Read `VAULTOS_ROOT`.
2. If set, resolve it as the workspace root.
3. Otherwise infer the root two parents above `facility/bootstrap.py`.
4. For each subsystem name in `("Access", "Devices", "Events", "Invites", "Personnel", "Vault")`:
   - Build the absolute path.
   - Check whether it is already in `sys.path`.
   - Append it only if missing.

This allows the integration package to import sibling apps without copying them.

---

### Facility Demo Construction

1. Build an event stack:
   - `AlertManager`
   - `EventBus(dedup_threshold=10)`
   - `LogHandler`
2. Subscribe log and alert handlers.
3. Seed:
   - Device panel.
   - Access controller.
   - Vault inventory.
   - Empty personnel registry.
   - Empty invite manager.
4. Power on seeded devices.
5. Register demo employees, visitor, and contractor.
6. Link keycards.
7. Check in demo people.
8. Generate a demo invite.
9. Publish initialization event.
10. Return the fully wired Facility object.

---

### Integrated Gate Check

1. Normalize card ID.
2. Resolve gate by name.
3. Resolve person linked to card.
4. If the gate is unknown, raise `KeyError`.
5. If the person is a contractor and the gate/location is restricted:
   - Build denied `AccessDecision`.
   - Record access log entry.
   - Observe suspicious activity monitor.
   - Record monitor alert if triggered.
6. Otherwise delegate to `AccessController.attempt_access()`.
7. Publish `ACCESS_GRANTED` or `ACCESS_DENIED`.
8. If decision includes a warning, publish `SUSPICIOUS_ACTIVITY`.
9. Return the decision.

---

### Personnel Check-In

1. Resolve person by ID.
2. If contractor contract is inactive:
   - Revoke linked keycard when present.
   - Publish `PERSONNEL_CHECK_IN_DENIED`.
   - Raise `CheckInError`.
3. Attempt check-in through PersonnelRegistry.
4. If check-in fails:
   - Publish denial event.
   - Re-raise error.
5. On success:
   - Publish `PERSONNEL_CHECKED_IN`.
   - Return person.

---

### Personnel Check-Out

1. Resolve person.
2. Call PersonnelRegistry check-out.
3. Find any vault items still checked out to that person’s name.
4. Publish `PERSONNEL_CHECKED_OUT`.
5. Publish host departure warnings when the Personnel subsystem returns them.
6. Publish outstanding vault item warning when applicable.
7. Return warnings and held items.

---

### Vault Checkout

1. Resolve actor by person ID or card ID.
2. Ensure keycard is usable.
3. If actor is a known person and not on-site:
   - Publish `VAULT_CHECKOUT_DENIED`.
   - Raise `FacilityStateError`.
4. Map Access access level to Vault access level.
5. Call `Vault.check_out()`.
6. If Vault denies the operation:
   - Publish denial event.
   - Re-raise subsystem error.
7. Publish `VAULT_ITEM_CHECKED_OUT`.
8. Use warning severity for items valued at or above 100,000.00.
9. Return item snapshot.

---

### Vault Check-In

1. Resolve actor by person ID or card ID.
2. Ensure keycard is usable.
3. Map access level.
4. Call `Vault.check_in()`.
5. Publish denial event on Vault error.
6. Publish `VAULT_ITEM_CHECKED_IN` on success.
7. Return item snapshot.

---

### Invite Generation

1. Resolve creator by person ID or card ID.
2. Ensure creator keycard is usable.
3. Parse requested access level.
4. Convert expiry to UTC.
5. Delegate to InviteManager.
6. Publish `INVITE_GENERATED`.
7. Return invite object.

---

### Event Publication

1. Construct `Event` with source, event type, severity, message, and UTC timestamp.
2. Publish to EventBus.
3. EventBus dispatches to log and alert handlers.
4. Return tuple of dispatched events.

---

### Persistence Round Trip

1. Convert each subsystem into a JSON-compatible record:
   - Cards and gates.
   - Access logs and security alerts.
   - People and on-site state.
   - Devices and device-specific private state.
   - Vault inventory and custody chain.
   - Event bus history and alert state.
   - Invites through `InviteManager.to_record()`.
2. Include `schema_version`.
3. Write JSON file.
4. On load:
   - Parse JSON.
   - Validate schema version.
   - Reconstruct event stack first.
   - Reconstruct each subsystem.
   - Reconstruct Facility with restored mappings.
5. Return live Facility.

---

## Data Structures

### `Facility`

Main integration object with subsystem references and mappings.

### `person_keycards: dict[str, str]`

Maps personnel IDs to keycard IDs for visitors and contractors. Employees also carry assigned card IDs in their own records, so `_linked_cards()` merges both sources.

### `device_locations: dict[str, str]`

Maps device IDs to human-readable locations used in event messages and dashboards.

### Facility JSON Record

Top-level snapshot:

```json
{
  "schema_version": 1,
  "name": "Vault OS Demo Facility",
  "device_locations": {},
  "person_keycards": {},
  "devices": {},
  "access": {},
  "personnel": {},
  "vault": {},
  "events": {},
  "invites": {}
}
```

### Dashboard Dictionary

Returned by `status_dashboard()`:

```python
{
    "facility": str,
    "devices": list[dict],
    "personnel_on_site": dict[str, int],
    "active_alerts": int,
    "vault_summary": VaultSummary,
    "checked_out_items": list[ItemSnapshot],
    "recent_events": list[str],
}
```

### CLI Namespace

`argparse.Namespace` stores parsed domain/action values and global state/save paths.

---

## State Management

State is held in memory during a CLI command or library call.

Persistent state is written only when:

- The caller invokes `Facility.save(path)`.
- The CLI command `facility save PATH` is used.
- The global `--save PATH` option is provided.

State is loaded when:

- The caller invokes `Facility.load(path)`.
- The CLI command `facility load PATH` is used.
- The global `--state PATH` option is provided.

If no state path is supplied, the CLI creates a fresh demo facility for the command.

---

## Error Handling Strategy

The package defines:

- `FacilityError`
- `FacilityStateError`

The CLI catches:

- Facility errors.
- Personnel check-in errors.
- Key errors.
- Value errors.
- Invite validation errors.
- Vault state/access errors.
- Device authorization/lockout errors.
- JSON decode errors.
- OS errors.

Known domain errors are printed as:

```text
Error: <message>
```

and return exit code `1`.

Unexpected exceptions are printed as:

```text
Unexpected error: <message>
```

and also return exit code `1`.

Parser errors are handled by `argparse` and normally return exit code `2`.

---

## External Dependencies

### Runtime Dependencies

The package itself uses the standard library for its own code:

- `argparse`
- `json`
- `sys`
- `pathlib`
- `datetime`
- `decimal`
- `typing`
- `collections`
- `os`

The runtime also expects the six sibling subsystem folders to be present and importable:

- Access
- Devices
- Events
- Invites
- Personnel
- Vault

Those subsystem apps may have their own internal dependencies, but Facility primarily interacts with their public APIs.

### Development Dependencies

Declared optional development dependencies:

- `pytest>=9.0`
- `hypothesis>=6.140`
- `pytest-cov>=5.0`

---

## Concurrency Model

The application is synchronous and single-process.

There are no threads, async tasks, background workers, or file locks. The CLI loads state, performs one command, optionally saves state, and exits.

This is acceptable for a portfolio CLI integration layer. It would not be safe for multiple simultaneous users editing the same state file without an external locking or transaction mechanism.

---

## Known Limitations

- Requires a specific workspace layout or `VAULTOS_ROOT`.
- Subsystem imports are coupled to module names in sibling projects.
- Persistence reaches into some device private fields to preserve state.
- No database or transaction semantics.
- No state file locking.
- No authentication for CLI users.
- No encryption for saved facility JSON.
- Invite generation prints the full invite code in the CLI output.
- The CLI does not expose every operation available inside every subsystem.
- Demo facility is convenient but not a real deployment initializer.
- Schema migration is limited to version checks; no upgrade pipeline exists yet.

---

## Design Patterns Used

### Façade

`Facility` exposes a unified interface over six subsystem apps.

### Adapter

`facility.adapters` centralizes subsystem imports, aliases collisions, and exposes translation helpers.

### Mixin Composition

Operation modules separate domain workflows while contributing methods to the main `Facility` class.

### Snapshot Persistence

`facility.persistence` converts live objects into JSON-compatible records and reconstructs them.

### Event-Driven Integration

Facility workflows publish events into the Events subsystem, allowing logs and alerts to observe integrated behavior.

### Command Pattern

CLI command domains map to dispatch handlers such as `_handle_vault()`, `_handle_invites()`, and `_handle_personnel()`.

### Demo Fixture / Seed Pattern

`Facility.create_demo()` and `configure_demo_facility()` build a consistent facility scenario for tests and manual demos.

---

# Interface Design Specification

## App 21 — Vault OS Facility

**Vault OS Group | Document 3 of 5**

---

## Invocation Syntax

### Module Invocation

```bash
python -m facility <domain> <action> [arguments]
```

### Console Script

```bash
vaultos-facility <domain> <action> [arguments]
```

### With State File

```bash
python -m facility --state facility_state.json status
```

### With Save After Command

```bash
python -m facility facility init --save facility_state.json
```

The CLI normalizes `--state` and `--save` so these global flags can appear in flexible positions.

---

## Global Argument Reference

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `--state` | path | Optional | None | Path to JSON file | Loads an existing facility snapshot before executing the command. |
| `--save` | path | Optional | None | Path to JSON file | Saves the resulting facility snapshot after executing the command. |

---

## Command: `facility init`

Creates a seeded demo facility.

### Syntax

```bash
python -m facility facility init [--save PATH]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `facility` | literal | Required | N/A | `facility` | Selects facility meta-operations. |
| `init` | literal | Required | N/A | `init` | Creates a new demo facility. |
| `--save` | path | Optional | None | Valid writable path | Saves initialized state after command. |

### Output

Prints initialization message and a status summary.

---

## Command: `facility load`

Loads and summarizes a saved facility state.

### Syntax

```bash
python -m facility facility load PATH
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `path` | path | Required | N/A | Existing JSON state file | Facility snapshot to load. |

---

## Command: `facility save`

Saves the current facility state.

### Syntax

```bash
python -m facility --state facility_state.json facility save new_state.json
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `path` | path | Required | N/A | Writable JSON path | Destination for the saved snapshot. |

---

## Command: `status`

Shows the facility dashboard.

### Syntax

```bash
python -m facility [--state PATH] status [--recent N]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `--recent` | int | Optional | `5` | Integer >= 0 | Number of recent events to show. |

### Output

Displays:

- Facility name.
- Devices and state fields.
- Personnel on-site counts.
- Active alert count.
- Vault item count.
- Vault value in place.
- Vault value checked out.
- Recent events.

---

## Command: `access gate-check`

Runs an access control check.

### Syntax

```bash
python -m facility [--state PATH] access gate-check CARD_ID GATE_NAME [--at ISO_TIMESTAMP]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `CARD_ID` | string | Required | N/A | Known or unknown keycard ID | Card used for gate access. |
| `GATE_NAME` | string | Required | N/A | Known gate name | Gate being accessed. |
| `--at` | ISO datetime string | Optional | Current time | `datetime.fromisoformat` compatible | Timestamp used for the access check. |

### Output

```text
GRANTED: KC-0002 at Operations Wing -> Access granted.
```

or

```text
DENIED: KC-0001 at Vault Antechamber -> Insufficient access level.
```

---

## Command: `personnel check-in`

Checks a person into the facility.

### Syntax

```bash
python -m facility [--state PATH] personnel check-in PERSON_ID [--location LOCATION] [--at ISO_TIMESTAMP]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `PERSON_ID` | string | Required | N/A | Registered person ID | Person to check in. |
| `--location` | string | Optional | None | Any location text | Location recorded for the check-in. |
| `--at` | ISO datetime string | Optional | Current time | `datetime.fromisoformat` compatible | Timestamp for check-in. |

---

## Command: `personnel check-out`

Checks a person out of the facility.

### Syntax

```bash
python -m facility [--state PATH] personnel check-out PERSON_ID
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `PERSON_ID` | string | Required | N/A | Registered person ID | Person to check out. |

### Output Notes

May print warnings if the person’s departure creates host warnings or if the person still holds vault items.

---

## Command: `vault checkout`

Checks a vault item out to a requester.

### Syntax

```bash
python -m facility [--state PATH] vault checkout ITEM_ID REQUESTER [--notes TEXT]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `ITEM_ID` | string | Required | N/A | Existing vault item ID | Item to check out. |
| `REQUESTER` | string | Required | N/A | Person ID or keycard ID | Actor requesting custody. |
| `--notes` | string | Optional | `""` | Any text | Custody notes. |

### Contract

If `REQUESTER` resolves to a registered person, the person must be on-site. The requester’s keycard must be usable. The Access access level is mapped to a Vault access level before calling the Vault subsystem.

---

## Command: `vault checkin`

Checks a vault item back in.

### Syntax

```bash
python -m facility [--state PATH] vault checkin ITEM_ID REQUESTER [--notes TEXT]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `ITEM_ID` | string | Required | N/A | Existing vault item ID | Item to check in. |
| `REQUESTER` | string | Required | N/A | Person ID or keycard ID | Actor returning custody. |
| `--notes` | string | Optional | `""` | Any text | Custody notes. |

---

## Command: `invite generate`

Generates a temporary invite code.

### Syntax

```bash
python -m facility [--state PATH] invite generate CREATOR_REF REQUIRED_ACCESS_LEVEL [--uses N] [--hours HOURS]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `CREATOR_REF` | string | Required | N/A | Person ID or keycard ID | Actor creating the invite. |
| `REQUIRED_ACCESS_LEVEL` | string/int | Required | N/A | Access subsystem level name or value | Minimum level required by invite. |
| `--uses` | int | Optional | `1` | Positive integer expected by subsystem | Max use count. |
| `--hours` | float | Optional | `8.0` | Positive float recommended | Expiry window from now. |

### Output

Prints the generated invite code, masked code, and remaining uses.

---

## Command: `invite validate`

Validates an invite code without consuming it.

### Syntax

```bash
python -m facility [--state PATH] invite validate CODE
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `CODE` | string | Required | N/A | Invite code string | Code to validate. |

---

## Command: `invite use`

Consumes one invite use.

### Syntax

```bash
python -m facility [--state PATH] invite use CODE
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `CODE` | string | Required | N/A | Invite code string | Code to consume. |

---

## Command: `event history`

Shows recent event history.

### Syntax

```bash
python -m facility [--state PATH] event history [--limit N]
```

### Arguments

| Name | Type | Required | Default | Accepted Values | Description |
|---|---:|---:|---:|---|---|
| `--limit` | int | Optional | `10` | Integer >= 0 | Number of recent event lines to display. |

---

## Command: `alert list`

Lists active alerts.

### Syntax

```bash
python -m facility [--state PATH] alert list
```

### Output

If no alerts exist:

```text
No active alerts.
```

Otherwise each alert line includes:

- Alert ID.
- State.
- Severity.
- Source.
- Event type.
- Event message.

---

## Command: `simulate-breach`

Runs the demo breach simulation.

### Syntax

```bash
python -m facility [--state PATH] simulate-breach [--save PATH]
```

### Output

Prints the number of events generated and each event type/message.

---

## Input Contract

### State File

State files must be JSON objects compatible with the Facility record structure.

Required top-level fields for current records:

- `schema_version`
- `name`
- `device_locations`
- `person_keycards`
- `devices`
- `access`
- `personnel`
- `vault`
- `events`
- `invites`

Legacy records without `schema_version` are treated as version 1.

### Workspace

The subsystem folders must be importable through either:

- Expected sibling layout.
- `VAULTOS_ROOT`.

### Date/Time Inputs

CLI date strings must be parseable by `datetime.fromisoformat`.

---

## Output Contract

Normal output is human-readable text printed to stdout.

Errors are printed to stderr by the CLI as:

```text
Error: <message>
```

Unexpected errors are printed as:

```text
Unexpected error: <message>
```

---

## Exit Code Reference

| Exit Code | Meaning |
|---:|---|
| `0` | Command completed successfully. |
| `1` | Known business/domain error or unexpected runtime error caught by CLI. |
| `2` | Argument parsing error from `argparse`. |

---

## Error Output Behavior

The CLI catches common integration and subsystem errors and avoids raw tracebacks for expected failures. Examples include:

- Facility state errors.
- Check-in errors.
- Missing gates or people.
- Invalid invite usage.
- Vault item state errors.
- Vault access denied errors.
- Device authorization or lockout errors.
- Invalid JSON.
- OS file errors.

---

## Environment Variables

| Name | Required | Default | Description |
|---|---:|---|---|
| `VAULTOS_ROOT` | Optional | Inferred workspace root | Directory containing Access, Devices, Events, Invites, Personnel, and Vault folders. |

---

## Configuration Files

There is no separate configuration file beyond the optional Facility state JSON file.

---

## Side Effects

- May append subsystem folders to `sys.path`.
- May create or overwrite a JSON state file when saving.
- May mutate in-memory subsystem state during commands.
- May publish events and generate alerts.
- May change keycard, invite, personnel, device, and vault state.
- May expose full invite code in CLI output.
- Does not use a database.
- Does not start background processes.

---

## Usage Examples

### Basic: initialize and save a facility

```bash
python -m facility facility init --save facility_state.json
```

### Basic: show status

```bash
python -m facility --state facility_state.json status
```

### Advanced: gate check with saved state

```bash
python -m facility --state facility_state.json access gate-check KC-0002 "Operations Wing" --save facility_state.json
```

### Advanced: check out a vault item

```bash
python -m facility --state facility_state.json vault checkout ITM-0002 EMP-002 --notes "Temporary review" --save facility_state.json
```

### Edge Case: denied visitor access to vault area

```bash
python -m facility access gate-check KC-0001 "Vault Antechamber"
```

### Intentional Failure: missing state file

```bash
python -m facility --state missing.json status
```

Expected behavior: nonzero exit and an error message.

---

# Runbook

## App 21 — Vault OS Facility

**Vault OS Group | Document 4 of 5**

---

## Prerequisites

- Python 3.11 or newer.
- The Vault OS subsystem repositories/folders available in the expected workspace layout.
- Access to the Facility repository.
- Shell environment capable of running Python modules.
- Optional: virtual environment.

Expected workspace:

```text
VaultOS/
  Access/
  Devices/
  Events/
  Invites/
  Personnel/
  Vault/
  Facility/
```

If your layout differs, set:

```bash
export VAULTOS_ROOT=/path/to/VaultOS
```

On Windows PowerShell:

```powershell
$env:VAULTOS_ROOT = "C:\path\to\VaultOS"
```

---

## Installation Procedure

### Create and activate a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

### Install runtime package

```bash
pip install -e .
```

### Install development dependencies

```bash
pip install -e ".[dev]"
```

or:

```bash
pip install -r requirements.txt
```

---

## Configuration Steps

### 1. Verify subsystem folder layout

```bash
ls ..
```

Expected sibling folders:

```text
Access
Devices
Events
Invites
Personnel
Vault
```

### 2. Set `VAULTOS_ROOT` if needed

```bash
export VAULTOS_ROOT=/path/to/VaultOS
```

### 3. Verify module entry point

```bash
python -m facility status
```

### 4. Verify console script after install

```bash
vaultos-facility status
```

### 5. Create a saved state file

```bash
python -m facility facility init --save facility_state.json
```

---

## Standard Operating Procedures

### Show status from demo state

```bash
python -m facility status
```

### Initialize persistent state

```bash
python -m facility facility init --save facility_state.json
```

### Load saved state and show dashboard

```bash
python -m facility --state facility_state.json status
```

### Run a gate check and persist changes

```bash
python -m facility --state facility_state.json access gate-check KC-0002 "Operations Wing" --save facility_state.json
```

### Check in a person

```bash
python -m facility --state facility_state.json personnel check-in EMP-001 --location "Main Entrance" --save facility_state.json
```

### Check out a person

```bash
python -m facility --state facility_state.json personnel check-out EMP-001 --save facility_state.json
```

### Check out a vault item

```bash
python -m facility --state facility_state.json vault checkout ITM-0002 EMP-002 --notes "Review" --save facility_state.json
```

### Check in a vault item

```bash
python -m facility --state facility_state.json vault checkin ITM-0002 EMP-002 --notes "Returned" --save facility_state.json
```

### Generate an invite

```bash
python -m facility --state facility_state.json invite generate EMP-003 STAFF --uses 2 --hours 12 --save facility_state.json
```

### View recent events

```bash
python -m facility --state facility_state.json event history --limit 10
```

### List active alerts

```bash
python -m facility --state facility_state.json alert list
```

### Simulate breach

```bash
python -m facility --state facility_state.json simulate-breach --save facility_state.json
```

---

## Health Checks

### Import health check

```bash
python - <<'PY'
from facility import Facility
facility = Facility.create_demo()
print(facility.name)
print(len(facility.status_dashboard()["devices"]))
PY
```

Expected:

```text
Vault OS Demo Facility
4
```

### CLI health check

```bash
python -m facility status --recent 1
```

Expected:

```text
Facility: Vault OS Demo Facility
Devices:
...
```

### Persistence health check

```bash
python -m facility facility init --save /tmp/facility_state.json
python -m facility --state /tmp/facility_state.json status
```

Expected: both commands exit 0.

### Test suite

```bash
pytest tests/ -q
```

Expected: tests pass.

---

## Expected Output Samples

### Status

```text
Facility: Vault OS Demo Facility
Devices:
  CAM-01 Camera Main Entrance Camera [...]
  LOCK-01 Lock Vault Door [...]
Personnel on site:
  Employee: 3
  Visitor: 1
Active alerts: 0
Vault items: 3
Vault value in place: ...
Vault value checked out: ...
Recent events:
  ...
```

### Gate Check

```text
GRANTED: KC-0002 at Operations Wing -> Access granted.
```

or:

```text
DENIED: KC-0001 at Vault Antechamber -> Insufficient access level.
```

### Vault Checkout

```text
Checked out ITM-0002 to Sam Rivera.
```

### Invite Generation

```text
Generated invite <code> (masked: ****1234, uses: 2).
```

### Simulated Breach

```text
Simulated breach with 5 event(s).
MOTION_DETECTED: ...
FORCED_ENTRY_ATTEMPT: ...
ALARM_TRIGGERED: ...
```

---

## Known Failure Modes

### Subsystem import failure

**Symptom:**

```text
ModuleNotFoundError
```

**Likely Cause:** `VAULTOS_ROOT` is missing or workspace layout is wrong.

**Recovery:**

Set `VAULTOS_ROOT` to the directory containing the six subsystem folders.

---

### Invalid JSON state file

**Symptom:**

```text
Error: Expecting property name enclosed in double quotes...
```

**Likely Cause:** State file is not valid JSON.

**Recovery:**

Restore from a known-good state file or reinitialize:

```bash
python -m facility facility init --save facility_state.json
```

---

### Unsupported schema version

**Symptom:**

```text
Facility state schema_version X is not supported by this build
```

**Likely Cause:** State file was created by a future version.

**Recovery:**

Use a compatible version of `vaultos-facility` or re-export the state using schema version 1.

---

### Person not registered

**Symptom:**

```text
Error: EMP-999 is not registered in the facility.
```

**Recovery:**

Use a valid person ID from the demo or load a state file containing the person.

---

### Keycard not usable

**Symptom:**

```text
Error: Keycard KC-0002 is not usable (REVOKED).
```

**Recovery:**

Use a valid active keycard or initialize new demo state.

---

### Vault checkout denied because person is off-site

**Symptom:**

```text
Error: EMP-002 must be on-site before checking out vault items.
```

**Recovery:**

Check the person in first:

```bash
python -m facility --state facility_state.json personnel check-in EMP-002 --location "Sublevel 2" --save facility_state.json
```

---

### Invite use denied

**Symptom:**

```text
Error: <invite validation message>
```

**Likely Causes:**

- Code expired.
- Code already used up.
- Code revoked.
- Code unknown.

**Recovery:**

Generate a new invite.

---

## Troubleshooting Decision Tree

```text
Command fails?
|
+-- Is it an argparse usage error?
|   |
|   +-- Run command with --help.
|
+-- Is it ModuleNotFoundError?
|   |
|   +-- Check workspace layout.
|   +-- Set VAULTOS_ROOT.
|
+-- Is it a JSON error?
|   |
|   +-- Validate state file.
|   +-- Reinitialize state if needed.
|
+-- Is it schema_version error?
|   |
|   +-- Use compatible app version.
|   +-- Regenerate state.
|
+-- Is it person/card/item missing?
|   |
|   +-- Confirm state file.
|   +-- Use demo IDs.
|
+-- Is operation denied by business rule?
|   |
|   +-- Check on-site status.
|   +-- Check keycard status.
|   +-- Check access level.
|   +-- Check vault item status.
|
+-- Unexpected error?
    |
    +-- Re-run with minimal demo command.
    +-- Inspect traceback only if running from Python directly.
```

---

## Dependency Failure Handling

The Facility package depends on sibling subsystem imports. It does not vendor those apps.

If imports fail:

1. Confirm the subsystem folders exist.
2. Confirm `VAULTOS_ROOT` points to their parent directory.
3. Confirm subsystem package files still expose the expected module names.
4. Run from the Facility repo root or install editable.
5. Re-run import health check.

---

## Recovery Procedures

### Reset to known demo state

```bash
python -m facility facility init --save facility_state.json
```

### Backup before risky operation

```bash
cp facility_state.json facility_state.backup.json
```

Windows PowerShell:

```powershell
Copy-Item facility_state.json facility_state.backup.json
```

### Restore backup

```bash
cp facility_state.backup.json facility_state.json
```

### Recover from corrupted state

If the JSON file is corrupted and no backup exists, create a new demo state:

```bash
python -m facility facility init --save facility_state.json
```

### Recover from unsupported future schema

Use the newer app version that created the file, or reinitialize from demo state. Manual editing of schema version is not recommended because record structure may differ.

---

## Logging Reference

Facility does not maintain a separate log file. Operational history is captured primarily through:

- Event bus history.
- AlertManager active alerts.
- Access subsystem logs.
- Vault custody chains.
- Invite usage logs.
- Serialized state snapshots.

Use:

```bash
python -m facility --state facility_state.json event history --limit 20
python -m facility --state facility_state.json alert list
```

for operational visibility.

---

## Maintenance Notes

- Keep subsystem public APIs stable because Facility imports them directly.
- Add persistence tests whenever a new state field is added.
- Increment `FACILITY_RECORD_VERSION` if the snapshot format becomes incompatible.
- Avoid modifying subsystem internals from Facility unless no public restore API exists.
- Prefer new operation mixins over expanding `core.py`.
- Keep CLI commands thin; business rules should remain in Facility methods.
- Save state after any command that should persist changes.
- Avoid committing real facility state files if they contain sensitive invite codes or asset data.

---

# Lessons Learned

## App 21 — Vault OS Facility

**Vault OS Group | Document 5 of 5**

---

## Project Summary

Vault OS Facility is the integration layer for the Vault OS group of apps. It takes six independent CLI/library-style projects and composes them into one package with a single `Facility` façade.

This project is different from the earlier subsystem apps. Instead of focusing on one domain, it focuses on boundaries between domains. The main challenge is not implementing a new keycard, invite, vault item, or device. Those already exist. The challenge is deciding where coordination logic should live when an operation crosses subsystem boundaries.

The result is a package that can:

- Build a seeded demo facility.
- Register and resolve personnel.
- Link people to keycards.
- Run integrated gate checks.
- Check personnel in and out.
- Enforce on-site status for vault custody.
- Generate and validate invite codes.
- Publish events and alerts.
- Simulate a breach across devices and events.
- Save and restore a composed facility snapshot.
- Expose common workflows through a CLI.

---

## Original Goals vs. Actual Outcome

### Original Goals

- Compose six subsystem apps without changing their code.
- Provide one façade object.
- Provide a small CLI.
- Demonstrate integration between access, personnel, vault, devices, events, invites, and alerts.
- Preserve enough state to load/save the full facility.
- Keep the project scoped to a one-day integration app.

### Actual Outcome

The app meets the core goal. The `Facility` object is a useful façade over the six subsystems, and the CLI demonstrates key workflows. The persistence layer is more substantial than expected because each subsystem has different state structures and some state lives inside private attributes.

The final product feels like a real “system composition” project rather than another isolated CLI tool. It shows progression from writing small applications to integrating multiple applications with explicit architecture choices.

---

## Technical Decisions That Paid Off

### Keeping subsystem code unchanged

This was the most important decision. It forced the Facility layer to behave like a real integrator. The earlier apps remain meaningful and independent, and App 21 demonstrates that they can be composed.

### Centralizing imports in `adapters.py`

The adapter module is noisy, but it prevents import and aliasing complexity from spreading across the whole codebase. This is especially useful because Access and Vault both have access-level concepts.

### Using mixins for operation domains

The `Facility` class could have become too large. Splitting behavior into `operations/access.py`, `operations/personnel.py`, `operations/vault.py`, and similar modules made the integration easier to reason about.

### Adding schema versioning early

Even a simple `schema_version` field makes the persistence layer more honest. It acknowledges that snapshot formats change and that future records should not be silently loaded by old code.

### Publishing events from cross-system operations

Event publication gives integrated workflows an audit trail. Gate denials, vault checkout denials, invite generation, and breach simulation are not just return values; they become part of facility history.

### Building a demo facility

The demo seed makes the CLI usable immediately and gives tests consistent data. Without it, every test and command would require a long setup process.

---

## Technical Decisions That Created Debt

### `sys.path` bootstrapping

This is practical for a portfolio workspace, but it is not the ideal long-term packaging strategy. A more mature version should package the subsystem apps and depend on them directly.

### Persistence depending on subsystem internals

Some restore logic has to write private device attributes. This works, but it is fragile. A better long-term approach would be for each subsystem to expose its own `to_record()` and `from_record()` methods.

### One snapshot for everything

A single JSON file is simple and transparent, but it can become large. It also makes concurrent writes unsafe.

### CLI prints full invite code

This is convenient for a demo but not ideal for a security-oriented system. A real tool would need careful rules around secret display.

### Demo state as default CLI state

Defaulting to demo state makes manual testing easy, but it can hide the difference between ephemeral state and saved state. Users must remember to use `--save` if they want changes to persist.

---

## What Was Harder Than Expected

### Mapping identities across systems

A person, a keycard, and a vault actor are not the same thing. The integration layer needed explicit logic for person-to-keycard links, employee assigned cards, and actor resolution.

### Persistence

Saving one subsystem is straightforward. Saving six subsystems plus their relationships is much more complex. The persistence layer had to preserve:

- Device type-specific state.
- Access cards, gates, logs, security alerts, and monitor flags.
- Personnel subclasses and on-site state.
- Vault items, monetary values, statuses, conditions, and custody chains.
- Event history and alert state.
- Invite manager records.
- Facility-only mappings.

### Cross-system business rules

Rules like “a known person must be on-site before checking out a vault item” do not belong cleanly to only Personnel or only Vault. The Facility layer is the right place, but deciding that boundary takes design judgment.

### Error consistency

Each subsystem has its own exceptions and behavior. The CLI needed a broad but intentional error handling strategy to present clean messages.

---

## What Was Easier Than Expected

### Event integration

The Events subsystem fit naturally as the audit backbone. Once `publish_event()` existed, each workflow could publish meaningful events without changing the Events app.

### Demo facility construction

The prior subsystem demo helpers made seeding easier. `seed_demo_panel()`, `build_demo_controller()`, and `seed_demo_vault()` provided enough base state to focus on integration rather than object construction.

### CLI dispatch

A small `argparse` dispatcher was enough. The CLI did not need to be interactive because Facility’s goal is command workflow demonstration.

---

## Python-Specific Learnings

### Postponed annotations help with circular types

`from __future__ import annotations` makes it easier to type mixins and `Facility` references without creating import cycles.

### `Path` is safer than raw strings

Persistence, bootstrap, and CLI state paths are easier to manage with `pathlib.Path`.

### Explicit imports make integration visible

The adapter file is verbose, but it documents exactly which subsystem types are part of the integration contract.

### `datetime.fromisoformat()` is useful but strict

It gives a simple CLI timestamp parser, but the accepted format must be documented.

### JSON persistence needs careful conversions

Dates, datetimes, enums, decimals, and custom classes all need explicit serialization. A generic `json.dumps()` is not enough.

---

## Architecture Insights

### A façade is valuable when workflows cross boundaries

The Facility object exists because no single subsystem should own cross-domain behavior. A vault should not know whether a person is checked in. A personnel registry should not know vault custody rules. Access should not know invite review policy. Facility coordinates these.

### Adapters are not just for external APIs

Even local sibling projects benefit from an adapter layer. It gives one place to handle naming collisions, conversions, imports, and bridge functions.

### Persistence is part of architecture

The moment an app saves composed state, the structure of that state becomes a contract. Schema versioning and round-trip tests are not optional extras.

### Integration tests matter more than isolated tests here

The value of this app is that multiple systems work together. Tests that prove demo construction, gate denial alerts, contractor revocation, vault checkout, and state round-trip are more important than tiny unit tests alone.

---

## Testing Gaps

- More CLI command tests would strengthen confidence.
- More persistence tests for every device type would help.
- Invite CLI tests could verify masked/full code output decisions.
- Breach simulation tests could check exact alert behavior.
- Tests could cover `VAULTOS_ROOT` with a custom workspace path.
- Tests could cover save-after-command behavior.
- Tests could verify unsupported device type handling.
- Tests could cover corrupt but valid JSON with missing required record sections.
- Tests could cover concurrent state write risks, even if only to document expected failure.

---

## Reusable Patterns Identified

### `Facility.create_demo()`

A useful pattern for integration projects: build a realistic seed environment so tests and demos do not require long setup scripts.

### Domain mixins

A scalable way to keep a large façade organized by concern.

### `to_record()` / `from_record()`

A clear persistence contract that can be repeated in future subsystem apps.

### State schema versioning

Lightweight but important for any saved JSON format.

### Actor resolution

The `resolve_actor()` pattern is reusable anywhere a command may accept multiple identity references, such as person ID or keycard ID.

### Event publication wrapper

A single `publish_event()` method keeps event formatting and timestamp normalization consistent.

---

## If I Built This Again

I would consider these changes:

1. Package the six subsystem apps properly and replace `sys.path` bootstrapping with installable dependencies.
2. Add `to_record()` and `from_record()` methods to each subsystem app so Facility persistence does not need to know internal fields.
3. Add a state file lock to prevent concurrent CLI writes.
4. Add a `facility inspect` command to list people, keycards, invites, and vault items.
5. Mask invite codes by default and add an explicit `--show-secret` flag.
6. Add a `facility validate-state` command for snapshot diagnostics.
7. Add a richer dashboard command with JSON output for automation.
8. Add migration functions for future schema versions.
9. Split CLI dispatch into separate files if it grows.
10. Add structured logging for command execution and state changes.

---

## Open Questions

- Should Facility eventually become the only public interface to the six subsystem apps, or should it remain one optional integration layer?
- Should subsystem apps own their own persistence adapters?
- Should saved state be encrypted or signed?
- Should invite codes ever be printed in full?
- Should vault checkout require both access level and active gate presence?
- Should event alerts be acknowledged through the Facility CLI?
- Should breach simulations be configurable instead of hard-coded to demo device IDs?
- Should `VAULTOS_ROOT` be replaced by real package dependencies?
- Should Facility support multiple facilities in one state file?
- Should the CLI offer machine-readable JSON output for dashboards and automation?
