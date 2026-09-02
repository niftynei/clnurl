use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use cln_plugin::Plugin;
use cln_rpc::model::{DatastoreMode, DatastoreRequest, DeldatastoreRequest, ListdatastoreRequest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::RwLock;

const DATASTORE_PREFIX: [&str; 2] = ["clnurl", "endpoints"];
const MAX_NAME_LEN: usize = 64;
const MAX_DESCRIPTION_LEN: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointConfig {
    pub(crate) description: String,
}

#[derive(Clone, Debug)]
struct StoredEndpoint {
    config: EndpointConfig,
    generation: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EndpointRegistry {
    endpoints: Arc<RwLock<HashMap<String, StoredEndpoint>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetEndpointParams {
    name: String,
    description: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveEndpointParams {
    name: String,
}

impl EndpointRegistry {
    pub(crate) async fn load(rpc_socket: &Path) -> Result<Self> {
        let mut rpc = cln_rpc::ClnRpc::new(rpc_socket).await?;
        let response = rpc
            .call_typed(ListdatastoreRequest {
                key: Some(datastore_prefix()),
            })
            .await
            .context("could not load LNURL endpoints from CLN datastore")?;
        let mut endpoints = HashMap::new();

        for entry in response.datastore {
            if entry.key.len() != DATASTORE_PREFIX.len() + 1
                || entry.key[..DATASTORE_PREFIX.len()] != datastore_prefix()
            {
                continue;
            }
            let name = entry.key[DATASTORE_PREFIX.len()].clone();
            validate_name(&name)
                .with_context(|| format!("invalid LNURL endpoint name in datastore: {name}"))?;
            let encoded = entry
                .string
                .ok_or_else(|| anyhow!("LNURL endpoint {name} datastore value is not a string"))?;
            let config: EndpointConfig = serde_json::from_str(&encoded)
                .with_context(|| format!("invalid LNURL endpoint configuration for {name}"))?;
            validate_description(&config.description)
                .with_context(|| format!("invalid LNURL endpoint description for {name}"))?;
            endpoints.insert(
                name,
                StoredEndpoint {
                    config,
                    generation: entry.generation,
                },
            );
        }

        Ok(Self {
            endpoints: Arc::new(RwLock::new(endpoints)),
        })
    }

    pub(crate) async fn get(&self, name: &str) -> Option<EndpointConfig> {
        self.endpoints
            .read()
            .await
            .get(name)
            .map(|stored| stored.config.clone())
    }

    async fn list(&self) -> Vec<(String, EndpointConfig)> {
        let endpoints = self.endpoints.read().await;
        let mut result: Vec<_> = endpoints
            .iter()
            .map(|(name, stored)| (name.clone(), stored.config.clone()))
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    #[cfg(test)]
    pub(crate) async fn insert_for_test(&self, name: &str, description: &str) {
        self.endpoints.write().await.insert(
            name.to_owned(),
            StoredEndpoint {
                config: EndpointConfig {
                    description: description.to_owned(),
                },
                generation: Some(0),
            },
        );
    }
}

pub(crate) async fn rpc_add(plugin: Plugin<EndpointRegistry>, params: Value) -> Result<Value> {
    let params: SetEndpointParams = serde_json::from_value(params)
        .context("expected named parameters: name and description")?;
    validate_name(&params.name)?;
    validate_description(&params.description)?;
    let config = EndpointConfig {
        description: params.description,
    };
    let mut rpc = connect_plugin_rpc(&plugin).await?;
    let response = rpc
        .call_typed(DatastoreRequest {
            key: datastore_key(&params.name),
            string: Some(serde_json::to_string(&config)?),
            hex: None,
            mode: Some(DatastoreMode::MUST_CREATE),
            generation: None,
        })
        .await
        .context("could not create LNURL endpoint")?;
    plugin.state().endpoints.write().await.insert(
        params.name.clone(),
        StoredEndpoint {
            config: config.clone(),
            generation: response.generation,
        },
    );
    Ok(endpoint_json(&params.name, &config))
}

pub(crate) async fn rpc_update(plugin: Plugin<EndpointRegistry>, params: Value) -> Result<Value> {
    let params: SetEndpointParams = serde_json::from_value(params)
        .context("expected named parameters: name and description")?;
    validate_name(&params.name)?;
    validate_description(&params.description)?;
    let generation = plugin
        .state()
        .endpoints
        .read()
        .await
        .get(&params.name)
        .ok_or_else(|| anyhow!("unknown LNURL endpoint: {}", params.name))?
        .generation;
    let config = EndpointConfig {
        description: params.description,
    };
    let mut rpc = connect_plugin_rpc(&plugin).await?;
    let response = rpc
        .call_typed(DatastoreRequest {
            key: datastore_key(&params.name),
            string: Some(serde_json::to_string(&config)?),
            hex: None,
            mode: Some(DatastoreMode::MUST_REPLACE),
            generation,
        })
        .await
        .context("could not update LNURL endpoint")?;
    plugin.state().endpoints.write().await.insert(
        params.name.clone(),
        StoredEndpoint {
            config: config.clone(),
            generation: response.generation,
        },
    );
    Ok(endpoint_json(&params.name, &config))
}

pub(crate) async fn rpc_remove(plugin: Plugin<EndpointRegistry>, params: Value) -> Result<Value> {
    let params: RemoveEndpointParams =
        serde_json::from_value(params).context("expected named parameter: name")?;
    validate_name(&params.name)?;
    let stored = plugin
        .state()
        .endpoints
        .read()
        .await
        .get(&params.name)
        .cloned()
        .ok_or_else(|| anyhow!("unknown LNURL endpoint: {}", params.name))?;
    let mut rpc = connect_plugin_rpc(&plugin).await?;
    rpc.call_typed(DeldatastoreRequest {
        key: datastore_key(&params.name),
        generation: stored.generation,
    })
    .await
    .context("could not remove LNURL endpoint")?;
    plugin.state().endpoints.write().await.remove(&params.name);
    Ok(endpoint_json(&params.name, &stored.config))
}

pub(crate) async fn rpc_list(plugin: Plugin<EndpointRegistry>, _params: Value) -> Result<Value> {
    let endpoints: Vec<_> = plugin
        .state()
        .list()
        .await
        .into_iter()
        .map(|(name, config)| endpoint_json(&name, &config))
        .collect();
    Ok(json!({ "endpoints": endpoints }))
}

async fn connect_plugin_rpc(plugin: &Plugin<EndpointRegistry>) -> Result<cln_rpc::ClnRpc> {
    let configuration = plugin.configuration();
    let rpc_socket = Path::new(&configuration.rpc_file);
    cln_rpc::ClnRpc::new(rpc_socket)
        .await
        .context("could not connect to CLN RPC")
}

fn datastore_prefix() -> Vec<String> {
    DATASTORE_PREFIX
        .iter()
        .map(|component| (*component).to_owned())
        .collect()
}

fn datastore_key(name: &str) -> Vec<String> {
    let mut key = datastore_prefix();
    key.push(name.to_owned());
    key
}

fn endpoint_json(name: &str, config: &EndpointConfig) -> Value {
    json!({
        "name": name,
        "description": config.description,
    })
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        bail!("endpoint name must contain between 1 and {MAX_NAME_LEN} characters");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte))
    {
        bail!("endpoint name may contain only lowercase a-z, digits, '-', '_', and '.'");
    }
    Ok(())
}

fn validate_description(description: &str) -> Result<()> {
    if description.is_empty() || description.len() > MAX_DESCRIPTION_LEN {
        bail!("endpoint description must contain between 1 and {MAX_DESCRIPTION_LEN} UTF-8 bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_endpoint_names() {
        for valid in ["alice", "podcast.tips", "hello_world", "pay-1", "_"] {
            validate_name(valid).unwrap();
        }
        for invalid in ["", "Alice", "a/b", "alice+tag", "alice@example.com"] {
            assert!(validate_name(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn validates_descriptions() {
        validate_description("Tips for Alice").unwrap();
        assert!(validate_description("").is_err());
        assert!(validate_description(&"x".repeat(MAX_DESCRIPTION_LEN + 1)).is_err());
    }
}
