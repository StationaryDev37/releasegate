#!/usr/bin/env python3
"""ReleaseGate silicon lock controller.

Creates and enforces a host-specific placement lock for the ReleaseGate process.
It deliberately does not modify protocol semantics, networking offloads, sysctls,
or cryptographic policy. Its only mutable actions are CPU affinity and, when
explicitly requested as root, NIC IRQ affinity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
from pathlib import Path

SCHEMA = "releasegate.silicon.lock/v1"


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return default


def parse_cpu_list(text: str) -> list[int]:
    out: list[int] = []
    for part in text.strip().split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def fmt_cpu_list(cpus: list[int]) -> str:
    if not cpus:
        return ""
    cpus = sorted(set(cpus))
    runs: list[str] = []
    start = prev = cpus[0]
    for cpu in cpus[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        runs.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = cpu
    runs.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(runs)


def canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def physical_cores(online: list[int]) -> list[int]:
    chosen: dict[tuple[str, str], int] = {}
    for cpu in online:
        base = f"/sys/devices/system/cpu/cpu{cpu}/topology"
        package = read_text(f"{base}/physical_package_id", "0")
        core = read_text(f"{base}/core_id", str(cpu))
        chosen.setdefault((package, core), cpu)
    return sorted(chosen.values())


def default_nic() -> str:
    names = sorted(p.name for p in Path("/sys/class/net").glob("*") if p.name != "lo")
    if not names:
        raise SystemExit("SILICON_PROBE_BLOCKED no_non_loopback_nic")
    # Prefer an interface that is administratively up.
    for name in names:
        if read_text(f"/sys/class/net/{name}/operstate") == "up":
            return name
    return names[0]


def queue_ids(nic: str, kind: str) -> list[int]:
    result: list[int] = []
    for path in Path(f"/sys/class/net/{nic}/queues").glob(f"{kind}-*"):
        try:
            result.append(int(path.name.split("-", 1)[1]))
        except (IndexError, ValueError):
            pass
    return sorted(result)


def cpu_flags_hash() -> str:
    text = read_text("/proc/cpuinfo")
    flags: set[str] = set()
    for line in text.splitlines():
        if line.startswith("flags") or line.startswith("Features"):
            _, _, tail = line.partition(":")
            flags.update(tail.split())
    return sha256_hex(" ".join(sorted(flags)).encode())


def topology_identity(nic: str) -> dict[str, object]:
    online = parse_cpu_list(read_text("/sys/devices/system/cpu/online", "0"))
    cores = physical_cores(online)
    rx = queue_ids(nic, "rx")
    tx = queue_ids(nic, "tx")
    node_paths = sorted(Path("/sys/devices/system/node").glob("node[0-9]*"))
    numa = []
    for node in node_paths:
        cpus = parse_cpu_list(read_text(str(node / "cpulist")))
        numa.append({"node": int(node.name[4:]), "cpus": cpus})
    device = Path(f"/sys/class/net/{nic}/device")
    pci = "virtual"
    try:
        pci = device.resolve().name
    except OSError:
        pass
    return {
        "arch": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_online": online,
        "physical_core_representatives": cores,
        "cpu_flags_sha256": cpu_flags_hash(),
        "numa": numa,
        "nic": {
            "name": nic,
            "pci": pci,
            "mtu": int(read_text(f"/sys/class/net/{nic}/mtu", "0") or 0),
            "rx_queues": rx,
            "tx_queues": tx,
            "numa_node": int(read_text(f"/sys/class/net/{nic}/device/numa_node", "-1") or -1),
        },
        "io_uring_disabled": int(read_text("/proc/sys/kernel/io_uring_disabled", "-1") or -1),
    }


def derive_placement(identity: dict[str, object]) -> dict[str, object]:
    cores = list(identity["physical_core_representatives"])
    if not cores:
        raise SystemExit("SILICON_PROBE_BLOCKED no_cpu_cores")
    rxq = len(identity["nic"]["rx_queues"])  # type: ignore[index]
    n = len(cores)
    if n == 1:
        housekeeping = irq = runtime = cores[:]
        grade = "degraded"
    elif n == 2:
        housekeeping = irq = [cores[0]]
        runtime = [cores[1]]
        grade = "partial"
    else:
        housekeeping = [cores[0]]
        max_irq = max(1, min(rxq or 1, max(1, n // 4)))
        # Always leave at least one physical core for ReleaseGate.
        max_irq = min(max_irq, n - 2)
        irq = cores[1 : 1 + max_irq]
        runtime = cores[1 + max_irq :]
        if not runtime:
            runtime = [cores[-1]]
        grade = "isolated"
    return {
        "grade": grade,
        "housekeeping_cpus": housekeeping,
        "irq_cpus": irq,
        "runtime_cpus": runtime,
        "tokio_worker_threads": len(runtime),
    }


def build_lock(nic: str) -> dict[str, object]:
    identity = topology_identity(nic)
    placement = derive_placement(identity)
    core = {"schema": SCHEMA, "identity": identity, "placement": placement}
    return {**core, "host_fingerprint": sha256_hex(canonical(core))}


def load_lock(path: Path) -> dict[str, object]:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"SILICON_LOCK_INVALID {exc}") from exc
    if lock.get("schema") != SCHEMA:
        raise SystemExit("SILICON_LOCK_INVALID schema")
    expected = lock.get("host_fingerprint")
    core = {"schema": lock.get("schema"), "identity": lock.get("identity"), "placement": lock.get("placement")}
    actual = sha256_hex(canonical(core))
    if expected != actual:
        raise SystemExit("SILICON_LOCK_INVALID fingerprint")
    return lock


def validate_host(lock: dict[str, object]) -> None:
    nic = lock["identity"]["nic"]["name"]  # type: ignore[index]
    current = topology_identity(str(nic))
    if current != lock["identity"]:
        exp = sha256_hex(canonical(lock["identity"]))
        got = sha256_hex(canonical(current))
        raise SystemExit(f"SILICON_HOST_MISMATCH expected={exp} observed={got}")


def nic_irqs(nic: str) -> list[int]:
    text = read_text("/proc/interrupts")
    out: list[int] = []
    # Match queue labels and the interface name as a token, not arbitrary substring.
    token = re.compile(rf"(?:^|[^A-Za-z0-9_.-]){re.escape(nic)}(?:[-:@][A-Za-z0-9_.-]+)?(?:$|[^A-Za-z0-9_.-])")
    for line in text.splitlines():
        if not token.search(line):
            continue
        head, sep, _ = line.partition(":")
        if sep and head.strip().isdigit():
            out.append(int(head.strip()))
    return sorted(set(out))


def apply_irq_affinity(lock: dict[str, object]) -> None:
    if os.geteuid() != 0:
        raise SystemExit("SILICON_APPLY_BLOCKED root_required_for_irq_affinity")
    nic = str(lock["identity"]["nic"]["name"])  # type: ignore[index]
    irq_cpus = list(lock["placement"]["irq_cpus"])  # type: ignore[index]
    irqs = nic_irqs(nic)
    if not irqs:
        raise SystemExit(f"SILICON_APPLY_BLOCKED no_irqs_for_nic={nic}")
    if not irq_cpus:
        raise SystemExit("SILICON_APPLY_BLOCKED no_irq_cpus")
    for i, irq in enumerate(irqs):
        cpu = irq_cpus[i % len(irq_cpus)]
        Path(f"/proc/irq/{irq}/smp_affinity_list").write_text(f"{cpu}\n", encoding="ascii")
    print(f"SILICON_IRQ_AFFINITY_APPLIED nic={nic} irqs={','.join(map(str, irqs))} cpus={fmt_cpu_list(irq_cpus)}")


def exec_locked(lock: dict[str, object], lock_path: Path, argv: list[str]) -> None:
    if not argv:
        raise SystemExit("SILICON_EXEC_INVALID missing_command")
    runtime = set(int(x) for x in lock["placement"]["runtime_cpus"])  # type: ignore[index]
    if not runtime:
        raise SystemExit("SILICON_EXEC_INVALID empty_runtime_cpuset")
    os.sched_setaffinity(0, runtime)
    env = os.environ.copy()
    env["TOKIO_WORKER_THREADS"] = str(lock["placement"]["tokio_worker_threads"])  # type: ignore[index]
    env["RELEASEGATE_SILICON_FINGERPRINT"] = str(lock["host_fingerprint"])
    env["RELEASEGATE_RUNTIME_CPUSET"] = fmt_cpu_list(sorted(runtime))
    env["RELEASEGATE_SILICON_LOCK_PATH"] = str(lock_path.resolve())
    env["RELEASEGATE_SILICON_LOCK_SHA256"] = sha256_hex(lock_path.read_bytes())
    print(
        "SILICON_EXEC "
        f"cpus={fmt_cpu_list(sorted(runtime))} "
        f"tokio_workers={env['TOKIO_WORKER_THREADS']} "
        f"fingerprint={env['RELEASEGATE_SILICON_FINGERPRINT']}",
        file=sys.stderr,
    )
    os.execvpe(argv[0], argv, env)


def main() -> int:
    p = argparse.ArgumentParser(prog="silicon_ctl.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    probe = sub.add_parser("probe")
    probe.add_argument("--nic", default=None)
    probe.add_argument("--out", required=True, type=Path)
    val = sub.add_parser("validate")
    val.add_argument("--lock", required=True, type=Path)
    apply = sub.add_parser("apply-irqs")
    apply.add_argument("--lock", required=True, type=Path)
    run = sub.add_parser("exec")
    run.add_argument("--lock", required=True, type=Path)
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args()

    if args.cmd == "probe":
        nic = args.nic or default_nic()
        lock = build_lock(nic)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(canonical(lock) + b"\n")
        print(
            f"SILICON_LOCK_WRITTEN path={args.out} fingerprint={lock['host_fingerprint']} "
            f"runtime={fmt_cpu_list(lock['placement']['runtime_cpus'])} "
            f"irq={fmt_cpu_list(lock['placement']['irq_cpus'])}"
        )
        return 0
    lock = load_lock(args.lock)
    validate_host(lock)
    if args.cmd == "validate":
        print(f"SILICON_LOCK_PASS fingerprint={lock['host_fingerprint']}")
        return 0
    if args.cmd == "apply-irqs":
        apply_irq_affinity(lock)
        return 0
    if args.cmd == "exec":
        command = args.command
        if command and command[0] == "--":
            command = command[1:]
        exec_locked(lock, args.lock, command)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
