# Offline Autonomous Node Coordination

Minimal backend baseline for autonomous nodes that must keep working during long network outages and later reconcile state with explainable rules.

Requires Python 3.11 or newer and has no third-party runtime dependencies.

```bash
python -m offline_coordination status
python -m unittest discover -s tests -v
```

The current baseline exposes only a local status command. Persistent state is available via `offline_coordination.storage` and an append-only hash-chained audit log via `offline_coordination.audit`. Replication, conflict policies, security boundaries, observability, and network services are intentionally left for subsequent tasks.
