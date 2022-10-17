extern crate keepass;

mod commandline_opts;

use async_recursion::async_recursion;
use clap::builder::Str;
use commandline_opts::CommandlineOpts;
use futures::executor::block_on;
use keepass::{Database, Entry, Error, Group, Node, NodeRef, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::fs::File;
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

#[derive(Debug, Deserialize, Serialize)]
struct KeepassSecret {
    title: String,
    user: String,
    pass: String,
    notes: String,
    url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts: CommandlineOpts = CommandlineOpts::parse_and_setup_logger();

    info!("migrating from keepass: {}", opts.keepass_file);
    info!("migrating to vault: {}", opts.vault_addr);

    let keepass_db = Database::open(
        &mut File::open(std::path::Path::new(&opts.keepass_file))?,
        Some(&opts.keepass_password),
        None,
    )?;

    let mut vault_client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&opts.vault_addr)
            .token(&opts.vault_token)
            .build()
            .unwrap(),
    )
    .unwrap();

    process_keepass_group(
        opts.path_prefix.as_str(),
        &keepass_db.root,
        &vault_client,
        &opts,
    )
    .await;

    Ok(())
}

#[async_recursion]
async fn process_keepass_group(
    path: &str,
    group: &Group,
    vault_client: &VaultClient,
    opts: &CommandlineOpts,
) {
    for i in &group.children {
        match i {
            Node::Group(g) => {
                let path = format!("{}/{}", path, g.name);
                process_keepass_group(path.as_str(), g, vault_client, opts).await
            }
            Node::Entry(n) => process_kepass_entry(path, n, vault_client, opts).await
        }
    }
}

async fn process_kepass_entry(
    path: &str,
    entry: &Entry,
    vault_client: &VaultClient,
    opts: &CommandlineOpts,
) {
    let title = entry.get_title().unwrap_or("undefined");
    let secret = KeepassSecret {
        title: entry.get_title().unwrap().to_string(),
        user: entry.get_username().unwrap().to_string(),
        pass: entry.get_password().unwrap().to_string(),
        notes: entry.get("Notes").unwrap_or("").to_string(),
        url: entry.get("URL").unwrap_or("").to_string(),
    };

    let path = path.replace(" ", "_").replace("\"", "_");
    let path = format!("{}/{}", path, title);
    let path = path.strip_prefix("/").unwrap_or(path.as_str());
    let path = path.strip_suffix("/").unwrap_or(path);

    info!("creating / updating secret {}", path);
    kv2::set(vault_client, opts.mount.as_str(), path, &secret).await;
}
