use std::{env, net::SocketAddr};

use anyhow::{Context, Result};

use crate::secret::Secret;

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub github_app_id: u64,
    pub github_app_private_key_pem: Secret,
    pub github_app_webhook_secret: Secret,
    pub github_marketplace_webhook_secret: Secret,
    pub control_token: Secret,
    pub evaluator_token: Secret,
    pub auditor_token: Secret,
    pub receipt_signing_private_key_pem: Secret,
    pub receipt_signing_public_key_pem: String,
    pub receipt_signing_key_id: String,
    pub delivery_lease_seconds: i64,
    pub check_lease_seconds: i64,
    pub bundle_host: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind = env::var("RELEASEGATE_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse()
            .context("invalid RELEASEGATE_BIND")?;
        let database_url = env::var("RELEASEGATE_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://releasegate.db?mode=rwc".to_owned());
        let github_app_id = env::var("RELEASEGATE_GITHUB_APP_ID")
            .context("missing required environment variable RELEASEGATE_GITHUB_APP_ID")?
            .parse::<u64>()
            .context("invalid RELEASEGATE_GITHUB_APP_ID")?;
        if github_app_id == 0 {
            anyhow::bail!("RELEASEGATE_GITHUB_APP_ID must be positive");
        }
        let github_app_private_key_pem = required_secret("RELEASEGATE_GITHUB_APP_PRIVATE_KEY_PEM")?;
        let github_app_webhook_secret = required_secret("RELEASEGATE_GITHUB_APP_WEBHOOK_SECRET")?;
        let github_marketplace_webhook_secret =
            required_secret("RELEASEGATE_GITHUB_MARKETPLACE_WEBHOOK_SECRET")?;
        let control_token = required_secret("RELEASEGATE_CONTROL_TOKEN")?;
        let evaluator_token = required_secret("RELEASEGATE_EVALUATOR_TOKEN")?;
        let auditor_token = required_secret("RELEASEGATE_AUDITOR_TOKEN")?;
        let receipt_signing_private_key_pem = required_secret("RELEASEGATE_RECEIPT_PRIVATE_KEY_PEM")?;
        let receipt_signing_public_key_pem = env::var("RELEASEGATE_RECEIPT_PUBLIC_KEY_PEM")
            .context("missing required environment variable RELEASEGATE_RECEIPT_PUBLIC_KEY_PEM")?;
        if receipt_signing_public_key_pem.trim().is_empty() {
            anyhow::bail!("RELEASEGATE_RECEIPT_PUBLIC_KEY_PEM must not be empty");
        }
        let receipt_signing_key_id = env::var("RELEASEGATE_RECEIPT_KEY_ID")
            .context("missing required environment variable RELEASEGATE_RECEIPT_KEY_ID")?;
        validate_key_id(&receipt_signing_key_id)?;
        let delivery_lease_seconds = env::var("RELEASEGATE_DELIVERY_LEASE_SECONDS")
            .unwrap_or_else(|_| "120".to_owned())
            .parse::<i64>()
            .context("invalid RELEASEGATE_DELIVERY_LEASE_SECONDS")?;
        if !(30..=900).contains(&delivery_lease_seconds) {
            anyhow::bail!("RELEASEGATE_DELIVERY_LEASE_SECONDS must be between 30 and 900");
        }
        let check_lease_seconds = env::var("RELEASEGATE_CHECK_LEASE_SECONDS")
            .unwrap_or_else(|_| "120".to_owned())
            .parse::<i64>()
            .context("invalid RELEASEGATE_CHECK_LEASE_SECONDS")?;
        if !(30..=900).contains(&check_lease_seconds) {
            anyhow::bail!("RELEASEGATE_CHECK_LEASE_SECONDS must be between 30 and 900");
        }
        let bundle_host = env::var("RELEASEGATE_GITHUB_BUNDLE_HOST")
            .context("missing required environment variable RELEASEGATE_GITHUB_BUNDLE_HOST")?;
        validate_hostname(&bundle_host)?;
        Ok(Self {
            bind,
            database_url,
            github_app_id,
            github_app_private_key_pem,
            github_app_webhook_secret,
            github_marketplace_webhook_secret,
            control_token,
            evaluator_token,
            auditor_token,
            receipt_signing_private_key_pem,
            receipt_signing_public_key_pem,
            receipt_signing_key_id,
            delivery_lease_seconds,
            check_lease_seconds,
            bundle_host,
        })
    }
}

fn required_secret(name: &str) -> Result<Secret> {
    let value = env::var(name).with_context(|| format!("missing required environment variable {name}"))?;
    Secret::new(value).map_err(|reason| anyhow::anyhow!("{name}: {reason}"))
}

fn validate_hostname(host: &str) -> Result<()> {
    if host.is_empty()
        || host.len() > 253
        || host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        anyhow::bail!("RELEASEGATE_GITHUB_BUNDLE_HOST is not a valid DNS hostname");
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        anyhow::bail!("RELEASEGATE_RECEIPT_KEY_ID contains unsupported characters");
    }
    Ok(())
}
