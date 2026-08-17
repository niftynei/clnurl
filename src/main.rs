//! A mostly reverse-engineered implementation of LNURLPay following <https://bolt.fun/guide/web-services/lnurl/pay>
mod nostr_zap;

use std::collections::HashSet;
use std::str::FromStr;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use cln_plugin::options::{ConfigOption, Value};
use cln_rpc::model::InvoiceRequest;
use cln_rpc::primitives::{Amount, AmountOrAny};
use nostr::key::FromSkStr;
use nostr::prelude::FromBech32;
use nostr::secp256k1::XOnlyPublicKey;
use nostr::Keys;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{stdin, stdout};
use url::Url;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (shutdown_sender, _) = tokio::sync::broadcast::channel::<()>(1);
    let plugin_shutdown_sender = shutdown_sender.clone();
    let plugin = if let Some(plugin) = cln_plugin::Builder::new(stdin(), stdout())
        .option(ConfigOption::new(
            "clnurl_listen",
            Value::String("127.0.0.1:9876".into()),
            "Listen address for the LNURL web server",
        ))
        .option(ConfigOption::new(
            "clnurl_base_address",
            Value::String("http://localhost/".into()),
            "Base path under which the API endpoints are reachable, e.g. \
            https://example.com/lnurl_api means endpoints are reachable as \
            https://example.com/lnurl_api/lnurl and https://example.com/lnurl_api/invoice",
        ))
        .option(ConfigOption::new(
            "clnurl_min_sendable",
            Value::Integer(100),
            "Min millisatoshi amount clnurl is willing to receive, can not be less than 1 or more than `maxSendable",
        ))
        .option(ConfigOption::new(
            "clnurl_max_sendable",
            Value::Integer(100000000000),
            "Max millisatoshi amount clnurl is willing to receive",
        ))
        .option(ConfigOption::new(
            "clnurl_description",
            Value::String("Gimme money!".into()),
            "Description to be displayed in LNURL",
        ))
        .option(ConfigOption::new(
            "clnurl_nostr_pubkey",
            Value::OptString,
            "Nostr public key used to sign zap receipts (must match clnurl_nostr_secret)",
        ))
        .option(ConfigOption::new(
            "clnurl_nostr_secret",
            Value::OptString,
            "Dedicated Nostr secret key used to sign zap receipts (nsec or hex)",
        ))
        .option(ConfigOption::new(
            "clnurl_nostr_secret_path",
            Value::OptString,
            "Path to a file containing the dedicated Nostr zap-receipt secret key",
        ))
        .option(ConfigOption::new(
            "clnurl_nostr_relays",
            Value::String("".into()),
            "Comma-separated additional relays to publish zap receipts to",
        ))
        .option(ConfigOption::new(
            "clnurl_pay_index_path",
            Value::OptString,
            "File used to persist the last processed CLN pay index",
        ))
        .subscribe("shutdown", move |_, _| {
            let shutdown_sender_inner = plugin_shutdown_sender.clone();
            async move {
                let _ = shutdown_sender_inner.send(());
                Ok(())
            }
        })
        .dynamic()
        .start(())
        .await?
    {
        plugin
    } else {
        return Ok(());
    };

    let rpc_socket: PathBuf = plugin.configuration().rpc_file.parse()?;
    let listen_addr: SocketAddr = plugin
        .option("clnurl_listen")
        .expect("Option is defined")
        .as_str()
        .expect("Option is a string")
        .parse()?;

    let api_base_address: Url = plugin
        .option("clnurl_base_address")
        .expect("Option is defined")
        .as_str()
        .expect("Option is a string")
        .parse()?;

    let min_sendable = plugin
        .option("clnurl_min_sendable")
        .expect("Option is defined")
        .as_i64()
        .expect("Option is a string")
        .to_owned();

    let max_sendable = plugin
        .option("clnurl_max_sendable")
        .expect("Option is defined")
        .as_i64()
        .expect("Option is a string")
        .to_owned();

    let description = plugin
        .option("clnurl_description")
        .expect("Option is defined")
        .as_str()
        .expect("Option is a string")
        .to_owned();

    let configured_nostr_pubkey = match plugin.option("clnurl_nostr_pubkey") {
        Some(Value::String(pubkey)) => match XOnlyPublicKey::from_bech32(&pubkey) {
            Ok(pubkey) => Some(pubkey),
            Err(_) => Some(XOnlyPublicKey::from_str(&pubkey).expect("Invalid Zapper pubkey")),
        },
        Some(Value::OptString) => None,
        _ => {
            // Something unexpected happened
            None
        }
    };

    let inline_nostr_secret = match plugin.option("clnurl_nostr_secret") {
        Some(Value::String(secret)) => Some(secret),
        _ => None,
    };
    let nostr_secret_path = match plugin.option("clnurl_nostr_secret_path") {
        Some(Value::String(path)) => Some(PathBuf::from(path)),
        _ => None,
    };
    anyhow::ensure!(
        inline_nostr_secret.is_none() || nostr_secret_path.is_none(),
        "Configure only one of clnurl_nostr_secret and clnurl_nostr_secret_path"
    );
    let nostr_secret = match (inline_nostr_secret, nostr_secret_path) {
        (Some(secret), None) => Some(secret),
        (None, Some(path)) => Some(
            std::fs::read_to_string(&path)
                .map_err(|err| anyhow::anyhow!("Could not read {}: {err}", path.display()))?
                .trim()
                .to_owned(),
        ),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    let zapper_keys = match nostr_secret {
        Some(secret) => Some(
            Keys::from_sk_str(&secret)
                .map_err(|err| anyhow::anyhow!("Invalid Nostr zapper secret: {err}"))?,
        ),
        None => None,
    };

    let nostr_pubkey = match &zapper_keys {
        Some(keys) => {
            let derived = keys.public_key();
            if let Some(configured) = configured_nostr_pubkey {
                anyhow::ensure!(
                    configured == derived,
                    "clnurl_nostr_pubkey does not match clnurl_nostr_secret"
                );
            }
            Some(derived)
        }
        None => {
            if configured_nostr_pubkey.is_some() {
                log::warn!(
                    "clnurl_nostr_pubkey is configured without clnurl_nostr_secret; Nostr zap support is disabled"
                );
            }
            None
        }
    };

    let configured_relays = parse_configured_relays(
        plugin
            .option("clnurl_nostr_relays")
            .expect("Option is defined")
            .as_str()
            .expect("Option is a string"),
    )?;

    let pay_index_path = match plugin.option("clnurl_pay_index_path") {
        Some(Value::String(path)) => PathBuf::from(path),
        Some(Value::OptString) | None => rpc_socket.with_file_name("clnurl-zap-pay-index"),
        _ => rpc_socket.with_file_name("clnurl-zap-pay-index"),
    };

    let state = ClnurlState {
        rpc_socket,
        api_base_address,
        min_sendable: Amount::from_msat(min_sendable as u64),
        max_sendable: Amount::from_msat(max_sendable as u64),
        description,
        nostr_pubkey,
    };

    let lnurl_service = Router::new()
        .route("/lnurl", get(get_lnurl_struct))
        .route("/invoice", get(get_invoice))
        .with_state(state.clone());

    let publisher = zapper_keys.map(|keys| {
        let rpc_socket = state.rpc_socket.clone();
        let shutdown = shutdown_sender.subscribe();
        tokio::spawn(async move {
            if let Err(err) = nostr_zap::run_receipt_publisher(
                rpc_socket,
                keys,
                pay_index_path,
                configured_relays,
                shutdown,
            )
            .await
            {
                log::error!("Zap receipt publisher stopped: {err:#}");
            }
        })
    });

    let shutdown_future = async move {
        let mut shutdown_receiver = shutdown_sender.subscribe();
        let _ = shutdown_receiver.recv().await;
    };

    axum::Server::bind(&listen_addr)
        .serve(lnurl_service.into_make_service())
        .with_graceful_shutdown(shutdown_future)
        .await?;

    if let Some(publisher) = publisher {
        publisher.await?;
    }

    Ok(())
}

fn parse_configured_relays(value: &str) -> anyhow::Result<HashSet<String>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|relay| !relay.is_empty())
        .map(|relay| {
            let url = Url::parse(relay)?;
            anyhow::ensure!(
                matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some(),
                "Invalid clnurl_nostr_relays entry: {relay}"
            );
            Ok(relay.to_owned())
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ClnurlState {
    rpc_socket: PathBuf,
    api_base_address: Url,
    min_sendable: Amount,
    max_sendable: Amount,
    description: String,
    nostr_pubkey: Option<XOnlyPublicKey>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LnurlResponse {
    #[serde(with = "as_msat")]
    min_sendable: Amount,
    #[serde(with = "as_msat")]
    max_sendable: Amount,
    metadata: String,
    callback: Url,
    tag: LnurlTag,
    allows_nostr: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    nostr_pubkey: Option<XOnlyPublicKey>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
enum LnurlTag {
    PayRequest,
}

async fn get_lnurl_struct(
    State(state): State<ClnurlState>,
) -> Result<Json<LnurlResponse>, StatusCode> {
    Ok(Json(LnurlResponse {
        min_sendable: state.min_sendable,
        max_sendable: state.max_sendable,
        metadata: serde_json::to_string(&vec![vec!["text/plain".to_string(), state.description]])
            .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?,
        callback: state
            .api_base_address
            .join("invoice")
            .expect("Still a valid URL"),
        tag: LnurlTag::PayRequest,
        allows_nostr: state.nostr_pubkey.is_some(),
        nostr_pubkey: state.nostr_pubkey,
    }))
}

#[derive(Serialize, Deserialize)]
struct GetInvoiceParams {
    #[serde(with = "as_msat")]
    amount: Amount,
    nostr: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetInvoiceResponse {
    pr: String,
    // TODO: find out proper type
    success_action: Option<String>,
    // TODO: find out proper type
    routes: Vec<String>,
}

async fn get_invoice(
    Query(params): Query<GetInvoiceParams>,
    State(state): State<ClnurlState>,
) -> Result<Json<GetInvoiceResponse>, StatusCode> {
    if params.amount.msat() < state.min_sendable.msat()
        || params.amount.msat() > state.max_sendable.msat()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut cln_client = cln_rpc::ClnRpc::new(&state.rpc_socket)
        .await
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    let description = match &params.nostr {
        Some(d) => {
            let zapper_pubkey = state.nostr_pubkey.ok_or(StatusCode::BAD_REQUEST)?;
            nostr_zap::validate_zap_request(d, params.amount, zapper_pubkey).map_err(|err| {
                log::warn!("Rejected invalid zap request: {err:#}");
                StatusCode::BAD_REQUEST
            })?;
            d.clone()
        }
        None => serde_json::to_string(&vec![vec!["text/plain".to_string(), state.description]])
            .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?,
    };

    let cln_response = cln_client
        .call(cln_rpc::Request::Invoice(InvoiceRequest {
            amount_msat: AmountOrAny::Amount(params.amount),
            description,
            label: Uuid::new_v4().to_string(),
            expiry: None,
            fallbacks: None,
            preimage: None,
            exposeprivatechannels: None,
            cltv: None,
            deschashonly: Some(true),
        }))
        .await
        .map_err(|_e| StatusCode::INTERNAL_SERVER_ERROR)?;

    let invoice = match cln_response {
        cln_rpc::Response::Invoice(invoice_response) => invoice_response.bolt11,
        _ => panic!("CLN returned wrong response kind"),
    };

    Ok(Json(GetInvoiceResponse {
        pr: invoice,
        success_action: None,
        routes: vec![],
    }))
}

pub mod as_msat {
    use super::*;

    pub fn serialize<S>(amount: &Amount, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        amount.msat().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Amount, D::Error>
    where
        D: Deserializer<'de>,
    {
        let msat = u64::deserialize(deserializer)?;
        Ok(Amount::from_msat(msat))
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_lnurl_response_serialization() {
        let lnurl_response = LnurlResponse {
            min_sendable: Amount::from_msat(0),
            max_sendable: Amount::from_msat(1000000),
            metadata: serde_json::to_string(&vec![vec![
                "text/plain".to_string(),
                "Hello world".to_string(),
            ]])
            .unwrap(),
            callback: Url::from_str("http://example.com").unwrap(),
            tag: LnurlTag::PayRequest,
            allows_nostr: true,
            nostr_pubkey: Some(
                XOnlyPublicKey::from_str(
                    "9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31",
                )
                .unwrap(),
            ),
        };

        assert_eq!("{\"minSendable\":0,\"maxSendable\":1000000,\"metadata\":\"[[\\\"text/plain\\\",\\\"Hello world\\\"]]\",\"callback\":\"http://example.com/\",\"tag\":\"payRequest\",\"allowsNostr\":true,\"nostrPubkey\":\"9630f464cca6a5147aa8a35f0bcdd3ce485324e732fd39e09233b1d848238f31\"}", serde_json::to_string(&lnurl_response).unwrap());
    }
}
