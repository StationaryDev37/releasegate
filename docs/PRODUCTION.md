# ReleaseGate production contract

ReleaseGate production is deliberately narrow: one ReleaseGate process, systemd supervision, one SQLite state file, and one Caddy TLS boundary. Nothing else is required by the release-decision law.

## Installed state

- `/opt/releasegate/bin/releasegate` — immutable verified release binary.
- `/opt/releasegate/bin/releasegate-launch` — secret loader and silicon-locked exec boundary.
- `/opt/releasegate/lib/silicon_ctl.py` — host topology attestation/affinity controller.
- `/etc/releasegate/runtime.env` — non-secret deterministic runtime configuration.
- `/etc/releasegate/secrets/*` — scoped authority material. Materialization is create-once and refuses silent rotation.
- `/etc/releasegate/silicon.lock` — host execution-topology commitment.
- `/etc/releasegate/github-app-contract.json` — exact GitHub permissions/events/webhook URLs.
- `/etc/releasegate/runtime-manifest.json` — binary, receipt-key and silicon-lock hashes for the installed host.
- `/etc/releasegate/Caddyfile` — HTTPS allow-list; every unrelated path is rejected.
- `/var/lib/releasegate/releasegate.db` — only mutable ReleaseGate database.

There is no Redis, queue service, ORM, generic service mesh, dashboard, or external database. SQLite WAL plus ReleaseGate's ownership-bound leases implement the required crash/replay semantics.

## Materialization

Three facts cannot be fabricated by ReleaseGate and therefore remain explicit inputs: the compiled/release-gated binary, the real GitHub App ID/private key, and the host's real public HTTPS origin. Host-local authority tokens, receipt signing keys, webhook secrets, the silicon lock and runtime manifest are generated on the target host.

```sh
sudo python3 scripts/production_materialize.py \
  --releasegate-binary ./target/release/releasegate \
  --github-app-id "$GITHUB_APP_ID" \
  --github-app-private-key /secure/input/github-app.pem \
  --public-base-url "https://$RELEASEGATE_HOST" \
  --bundle-host "$GITHUB_ATTESTATION_BUNDLE_HOST"
```

The command installs the runtime launcher and both systemd units. It refuses to overwrite an already-populated secret directory.

## GitHub contract

Apply `/etc/releasegate/github-app-contract.json` exactly to the GitHub App. The app needs only repository attestation read, Check write, contents read and metadata read, and subscribes only to `installation` and `push`. Marketplace delivery uses its independent secret and endpoint.

## HTTPS boundary

Caddy exposes only the concrete ReleaseGate routes and forwards to `127.0.0.1:8080`. Webhook bodies must remain byte-identical through the proxy because GitHub HMAC verification authenticates the raw payload bytes.

Enable only after the Rust and production gates pass for the same commit:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now releasegate.service releasegate-edge.service
```

## Operations

`scripts/ops_snapshot.py` reports operational state derived directly from release decisions, evidence truth, policy authorization, exactly-once usage events, Check dispatch and webhook delivery. It is not a dashboard.

`scripts/sqlite_snapshot.py` uses SQLite's online backup API and refuses to publish a backup that fails database-integrity or foreign-key verification.

A production release is **not** declared until `scripts/rust_gate.sh` and `scripts/production_gate.py` both pass on the same clean commit and the resulting binary SHA-256 is captured in the installed runtime manifest.

## Runtime placement and recovery invariants

The silicon lock is generated **inside the final runtime environment on the target host**, after the final cpuset/container/systemd placement exists. A lock generated on a build host or a different container placement is invalid operational evidence and must not be reused. Host migration requires deliberate re-materialization of the silicon lock and runtime manifest; it never changes cryptographic release truth.

ReleaseGate uses a single SQLite connection by design. SQLite has one writer; serializing ReleaseGate's write transitions through one connection removes intra-process writer contention while WAL preserves read-side operational snapshots. A bounded 5-second SQLite busy timeout exists only for external lock interference.

Webhook recovery re-verifies persisted bytes with the currently installed webhook secret. Therefore webhook-secret rotation is a state transition, not a blind file replacement: drain or explicitly disposition every nonterminal durable delivery before replacing the secret. Replacing the secret while durable deliveries remain can make those deliveries permanently unauthenticatable and ReleaseGate will reject them fail-closed.

The receipt public-key file must contain **exactly one** `PUBLIC KEY` or `RSA PUBLIC KEY` PEM block. Concatenated keyrings are rejected so receipt-key identity cannot depend on parser-first-key behavior.

Launcher exits `40` (missing runtime config/lock/binary) and `41` (missing/empty secret) are permanent configuration failures. The systemd unit keeps `Restart=on-failure` for runtime crashes but declares `RestartPreventExitStatus=40 41` to prevent restart storms on operator-fixable configuration faults.
