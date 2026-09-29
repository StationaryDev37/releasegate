use std::{env, net::SocketAddr};

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub github_app_webhook_secret: String,
    pub github_marketplace_webhook_secret: String,
    pub ingest_token: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind = env::var("RELEASEGATE_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse()
            .context("invalid RELEASEGATE_BIND")?;
        let database_url = env::var("RELEASEGATE_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://releasegate.db?mode=rwc".to_owned());
        let github_app_webhook_secret = required("RELEASEGATE_GITHUB_APP_WEBHOOK_SECRET")?;
        let github_marketplace_webhook_secret = required("RELEASEGATE_GITHUB_MARKETPLACE_WEBHOOK_SECRET")?;
        let ingest_token = required("RELEASEGATE_INGEST_TOKEN")?;

        for (name, secret) in [
            ("RELEASEGATE_GITHUB_APP_WEBHOOK_SECRET", &github_app_webhook_secret),
            ("RELEASEGATE_GITHUB_MARKETPLACE_WEBHOOK_SECRET", &github_marketplace_webhook_secret),
            ("RELEASEGATE_INGEST_TOKEN", &ingest_token),
        ] {
            if secret.len() < 32 {
                anyhow::bail!("{name} must be at least 32 bytes");
            }
        }

        Ok(Self {
            bind,
            database_url,
            github_app_webhook_secret,
            github_marketplace_webhook_secret,
            ingest_token,
        })
    }
}

fn required(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required environment variable {name}"))
}
