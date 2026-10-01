use std::{collections::BTreeSet, env, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RuntimeSiliconAttestation {
    pub host_fingerprint: String,
    pub lock_sha256: String,
    pub runtime_cpus: Vec<u32>,
    pub tokio_worker_threads: usize,
}

#[derive(Debug, Deserialize)]
struct SiliconLock {
    schema: String,
    host_fingerprint: String,
    placement: Placement,
}

#[derive(Debug, Deserialize)]
struct Placement {
    runtime_cpus: Vec<u32>,
    tokio_worker_threads: usize,
}

pub fn attest_runtime() -> Result<RuntimeSiliconAttestation> {
    let lock_path = required_env("RELEASEGATE_SILICON_LOCK_PATH")?;
    let expected_lock_sha256 = required_sha256("RELEASEGATE_SILICON_LOCK_SHA256")?;
    let expected_fingerprint = required_sha256("RELEASEGATE_SILICON_FINGERPRINT")?;
    let expected_cpuset = parse_cpu_list(&required_env("RELEASEGATE_RUNTIME_CPUSET")?)?;
    let expected_workers = required_env("TOKIO_WORKER_THREADS")?
        .parse::<usize>()
        .context("TOKIO_WORKER_THREADS must be a positive integer")?;
    if expected_workers == 0 {
        anyhow::bail!("TOKIO_WORKER_THREADS must be positive");
    }

    let path = PathBuf::from(lock_path);
    let raw = fs::read(&path).with_context(|| format!("failed to read silicon lock {}", path.display()))?;
    let observed_lock_sha256 = hex::encode(Sha256::digest(&raw));
    if observed_lock_sha256 != expected_lock_sha256 {
        anyhow::bail!("silicon lock byte hash mismatch");
    }
    let lock: SiliconLock = serde_json::from_slice(&raw).context("silicon lock JSON is invalid")?;
    if lock.schema != "releasegate.silicon.lock/v1" {
        anyhow::bail!("silicon lock schema mismatch");
    }
    if lock.host_fingerprint != expected_fingerprint {
        anyhow::bail!("silicon lock host fingerprint mismatch");
    }
    let locked_cpus = normalized(lock.placement.runtime_cpus);
    if locked_cpus != expected_cpuset {
        anyhow::bail!("silicon lock runtime cpuset does not match launcher cpuset");
    }
    if lock.placement.tokio_worker_threads != expected_workers {
        anyhow::bail!("silicon lock Tokio worker count does not match launcher worker count");
    }
    if expected_workers != expected_cpuset.len() {
        anyhow::bail!("Tokio worker count must equal the locked runtime CPU count");
    }

    let observed_cpuset = process_allowed_cpus()?;
    if observed_cpuset != expected_cpuset {
        anyhow::bail!(
            "process CPU affinity drift: expected {}, observed {}",
            format_cpu_list(&expected_cpuset),
            format_cpu_list(&observed_cpuset)
        );
    }

    Ok(RuntimeSiliconAttestation {
        host_fingerprint: expected_fingerprint,
        lock_sha256: observed_lock_sha256,
        runtime_cpus: observed_cpuset,
        tokio_worker_threads: expected_workers,
    })
}

fn required_env(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required environment variable {name}"))
}

fn required_sha256(name: &str) -> Result<String> {
    let value = required_env(name)?;
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        anyhow::bail!("{name} must be 64 lowercase hexadecimal characters");
    }
    Ok(value)
}

fn process_allowed_cpus() -> Result<Vec<u32>> {
    let status = fs::read_to_string("/proc/self/status").context("failed to read /proc/self/status")?;
    let cpus = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .context("/proc/self/status is missing Cpus_allowed_list")?;
    parse_cpu_list(cpus)
}

fn parse_cpu_list(text: &str) -> Result<Vec<u32>> {
    let mut cpus = BTreeSet::new();
    for part in text.split(',').filter(|part| !part.is_empty()) {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<u32>().context("invalid CPU range start")?;
            let end = end.parse::<u32>().context("invalid CPU range end")?;
            if start > end {
                anyhow::bail!("invalid descending CPU range");
            }
            cpus.extend(start..=end);
        } else {
            cpus.insert(part.parse::<u32>().context("invalid CPU id")?);
        }
    }
    if cpus.is_empty() {
        anyhow::bail!("CPU set must not be empty");
    }
    Ok(cpus.into_iter().collect())
}

fn normalized(cpus: Vec<u32>) -> Vec<u32> {
    cpus.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

fn format_cpu_list(cpus: &[u32]) -> String {
    cpus.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::parse_cpu_list;

    #[test]
    fn cpu_list_is_canonicalized() -> anyhow::Result<()> {
        assert_eq!(parse_cpu_list("4,2-3,3")?, vec![2, 3, 4]);
        Ok(())
    }

    #[test]
    fn descending_range_is_rejected() {
        assert!(parse_cpu_list("4-2").is_err());
    }
}
