# ReleaseGate Silicon Lock

ReleaseGate does not treat hardware tuning as release truth. Silicon placement may change latency and throughput; it must never change `EvidenceTruth`, `PolicyAuthorization`, `ReleaseDecision`, evaluation identity, or receipt identity.

The silicon lock exists for one reason: make process/IRQ placement explicit, reproducible, and drift-detectable instead of relying on ambient scheduler behavior.

## Lock lifecycle

```sh
python3 scripts/silicon_ctl.py probe --nic eth0 --out /etc/releasegate/silicon.lock.json
python3 scripts/silicon_ctl.py validate --lock /etc/releasegate/silicon.lock.json
sudo python3 scripts/silicon_ctl.py apply-irqs --lock /etc/releasegate/silicon.lock.json
python3 scripts/silicon_ctl.py exec --lock /etc/releasegate/silicon.lock.json -- ./target/release/releasegate
```

`probe` records the exact architecture, kernel release, online CPUs, one representative thread per physical core, CPU-feature hash, NUMA layout, NIC/PCl identity, MTU, RX/TX queue topology, and io_uring policy. It then derives a deliberately small placement plan:

- housekeeping CPU(s): operating-system noise
- IRQ CPU(s): NIC interrupt placement
- runtime CPU(s): ReleaseGate and Tokio workers

The lock is content-addressed. Any edit without recomputing the lock fingerprint is rejected. Any host-topology drift is rejected before application.

## What the controller is allowed to mutate

Only two things:

1. NIC IRQ affinity, and only through the explicit `apply-irqs` command as root.
2. ReleaseGate process CPU affinity plus `TOKIO_WORKER_THREADS`, and only through the explicit `exec` command.

It intentionally does **not** modify GRO/GSO/TSO, TCP congestion control, socket buffer sysctls, huge pages, CPU governors, kernel mitigations, XDP programs, or cryptographic behavior. Those require workload-specific evidence before they earn a place in this system.

## Security invariant

`RELEASEGATE_SILICON_FINGERPRINT` is operational telemetry only. It is logged at process start and is deliberately excluded from evaluation and receipt identities. Same authenticated evidence and policy must produce the same decision regardless of which conforming host executes it.
