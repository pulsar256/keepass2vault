extern crate keepass;

mod commandline_opts;

use async_recursion::async_recursion;
use commandline_opts::CommandlineOpts;
use keepass::{Database, Entry, Group, Node};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

#[derive(Debug, Deserialize, Serialize)]
struct KeepassSecret {
    title: String,
    user: Option<String>,
    pass: Option<String>,
    additional_properties: HashMap<String, Option<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opts: CommandlineOpts = CommandlineOpts::parse_and_setup_logger();

    info!("migrating from keepass: {}", opts.keepass_file);
    info!("migrating to vault: {}", opts.vault_addr);

    let keepass_db = Database::open(
        &mut File::open(std::path::Path::new(&opts.keepass_file))?,
        Some(&opts.keepass_password),
        None,
    )?;

    let vault_client = VaultClient::new(
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
            Node::Entry(n) => process_keepass_entry(path, n, vault_client, opts).await,
        }
    }
}

async fn process_keepass_entry(
    path: &str,
    entry: &Entry,
    vault_client: &VaultClient,
    opts: &CommandlineOpts,
) {
    let mut additional_properties = HashMap::new();
    for key in entry.fields.keys() {
        let key = key.clone();
        if !["Title", "UserName", "Password"].contains(&key.as_str()) {
            additional_properties.insert(key.clone(), entry.get(&key).map(String::from));
        }
    }

    let secret = KeepassSecret {
        title: entry.get_title().unwrap_or_default().to_string(),
        user: entry.get_username().map(String::from),
        pass: entry.get_password().map(String::from),
        additional_properties,
    };

    let path = sanitize_path(
        format!(
            "{}/{}",
            path,
            sanitize_node_name(entry.get_title().unwrap_or("undefined"))
        )
        .as_str(),
    );

    info!("creating / updating secret {}", &path);
    match kv2::set(vault_client, opts.mount.as_str(), &path, &secret).await {
        Ok(_) => {}
        Err(client_error) => {
            error!("Could not set vault key {:?}", client_error)
        }
    }
}

fn sanitize_node_name(node_name: &str) -> String {
    node_name.replace(" ", "_").replace("\"", "_")
}

fn sanitize_path(path: &str) -> String {
    let path = sanitize_node_name(path);
    let path = path.strip_prefix("/").unwrap_or(path.as_str());
    path.strip_suffix("/").unwrap_or(path).to_string()
}
