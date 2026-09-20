# Offline Autonomous Node Coordination

Minimal backend baseline for autonomous nodes that must keep working during long network outages and later reconcile state with explainable rules.

Requires Python 3.11 or newer and has no third-party runtime dependencies.

```bash
python -m offline_coordination status
python -m unittest discover -s tests -v
```

The current baseline exposes only a local status command. Replication, durable domain state, conflict policies, audit trails, security boundaries, observability, and network services are intentionally left for subsequent tasks.
