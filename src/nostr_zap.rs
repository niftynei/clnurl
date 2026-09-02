use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use cln_rpc::model::{
    DatastoreMode, DatastoreRequest, ListdatastoreRequest, WaitanyinvoiceRequest,
    WaitanyinvoiceResponse, WaitanyinvoiceStatus,
};
use cln_rpc::primitives::Amount;
use futures::{stream::FuturesUnordered, SinkExt, StreamExt};
use log::{debug, info, warn};
use nostr::event::Event;
use nostr::{ClientMessage, EventId, Keys, Kind, Tag, Timestamp, UnsignedEvent};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use url::Url;

const MAX_RELAYS: usize = 20;
const RELAY_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_RELAY_TIMEOUT: Duration = Duration::from_secs(12);
const RECEIPT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);
const RELAY_ATTEMPTS: usize = 2;
const PAY_INDEX_DATASTORE_KEY: [&str; 3] = ["clnurl", "nostr", "pay_index"];

enum PublishError {
    Retryable(anyhow::Error),
    Permanent(anyhow::Error),
}

impl PublishError {
    fn error(&self) -> &anyhow::Error {
        match self {
            Self::Retryable(error) | Self::Permanent(error) => error,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedZapRequest {
    receipt_tags: Vec<Tag>,
    pub relays: HashSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Socks5Proxy {
    host: String,
    port: u16,
}

impl Socks5Proxy {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let url = Url::parse(value).context("invalid clnurl_nostr_proxy URL")?;
        if url.scheme() != "socks5h" {
            bail!("clnurl_nostr_proxy must use socks5h://");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("clnurl_nostr_proxy does not support credentials");
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            bail!("clnurl_nostr_proxy must contain only a host and port");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("clnurl_nostr_proxy has no host"))?;
        let port = url.port().unwrap_or(1080);
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    fn address(&self) -> (&str, u16) {
        (&self.host, self.port)
    }
}

pub(crate) fn validate_zap_request(
    json: &str,
    invoice_amount: Amount,
    zapper_pubkey: nostr::secp256k1::XOnlyPublicKey,
) -> Result<ValidatedZapRequest> {
    let event = Event::from_json(json).context("invalid zap request JSON")?;
    event.verify().context("invalid zap request signature")?;
    let expected_id = EventId::new(
        &event.pubkey,
        event.created_at,
        &event.kind,
        &event.tags,
        &event.content,
    );
    if event.id != expected_id {
        bail!("zap request event ID does not match its contents");
    }

    if event.kind != Kind::ZapRequest {
        bail!("nostr event is not a kind 9734 zap request");
    }

    let raw_tags: Vec<Vec<String>> = event.tags.iter().map(Tag::as_vec).collect();
    let p = exactly_one(&raw_tags, "p")?;
    at_most_one(&raw_tags, "e")?;
    at_most_one(&raw_tags, "a")?;
    at_most_one(&raw_tags, "k")?;
    at_most_one(&raw_tags, "amount")?;

    // Parsing these tags validates their public key, event ID, and address coordinate.
    let mut receipt_tags = vec![Tag::parse(p.clone()).context("invalid p tag")?];
    for name in ["e", "a", "k"] {
        if let Some(tag) = tags_named(&raw_tags, name).next() {
            receipt_tags
                .push(Tag::parse(tag.clone()).with_context(|| format!("invalid {name} tag"))?);
        }
    }

    if let Some(amount_tag) = tags_named(&raw_tags, "amount").next() {
        let amount = amount_tag
            .get(1)
            .ok_or_else(|| anyhow!("amount tag has no value"))?
            .parse::<u64>()
            .context("invalid amount tag")?;
        if amount != invoice_amount.msat() {
            bail!("zap request amount does not match invoice amount");
        }
    }

    let uppercase_p: Vec<&Vec<String>> = tags_named(&raw_tags, "P").collect();
    if uppercase_p.len() > 1 {
        bail!("zap request has more than one P tag");
    }
    if let Some(tag) = uppercase_p.first() {
        let value = tag.get(1).ok_or_else(|| anyhow!("P tag has no value"))?;
        if value != &zapper_pubkey.to_string() {
            bail!("zap request P tag does not match the zapper pubkey");
        }
    }

    let relay_tags: Vec<&Vec<String>> = tags_named(&raw_tags, "relays").collect();
    if relay_tags.len() != 1 {
        bail!("zap request must have exactly one relays tag");
    }
    let relay_values = relay_tags[0].iter().skip(1);
    let mut relays = HashSet::new();
    for relay in relay_values {
        validate_requested_relay(relay)?;
        relays.insert(relay.to_owned());
        if relays.len() > MAX_RELAYS {
            bail!("zap request has too many relays (maximum {MAX_RELAYS})");
        }
    }
    if relays.is_empty() {
        bail!("zap request relays tag is empty");
    }

    // P on a receipt identifies the zap sender. It is distinct from the optional
    // P tag accepted on anonymous zap requests above.
    receipt_tags.push(Tag::parse(vec!["P".to_owned(), event.pubkey.to_string()])?);

    Ok(ValidatedZapRequest {
        receipt_tags,
        relays,
    })
}

fn tags_named<'a>(tags: &'a [Vec<String>], name: &str) -> impl Iterator<Item = &'a Vec<String>> {
    let name = name.to_owned();
    tags.iter()
        .filter(move |tag| tag.first().map(String::as_str) == Some(name.as_str()))
}

fn exactly_one<'a>(tags: &'a [Vec<String>], name: &str) -> Result<&'a Vec<String>> {
    let matching: Vec<&Vec<String>> = tags_named(tags, name).collect();
    if matching.len() != 1 {
        bail!("zap request must have exactly one {name} tag");
    }
    Ok(matching[0])
}

fn at_most_one(tags: &[Vec<String>], name: &str) -> Result<()> {
    if tags_named(tags, name).count() > 1 {
        bail!("zap request has more than one {name} tag");
    }
    Ok(())
}

fn validate_requested_relay(relay: &str) -> Result<()> {
    let url = Url::parse(relay).context("invalid relay URL")?;
    if url.scheme() != "wss" {
        bail!("zap request relay must use wss://");
    }
    if url.host_str().is_none() || url.username() != "" || url.password().is_some() {
        bail!("invalid relay URL");
    }
    if let Some(host) = url.host_str() {
        if host.eq_ignore_ascii_case("localhost") {
            bail!("local relay URLs are not accepted from zap requests");
        }
        if let Ok(ip) = IpAddr::from_str(host) {
            if !is_public_ip(ip) {
                bail!("private relay addresses are not accepted from zap requests");
            }
        }
    }
    Ok(())
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0)
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

pub(crate) fn create_zap_receipt(
    keys: &Keys,
    request: ValidatedZapRequest,
    invoice: &WaitanyinvoiceResponse,
) -> Result<Event> {
    let bolt11 = invoice
        .bolt11
        .as_ref()
        .ok_or_else(|| anyhow!("paid zap invoice has no bolt11"))?;
    let paid_at = invoice
        .paid_at
        .ok_or_else(|| anyhow!("paid zap invoice has no paid_at timestamp"))?;

    let mut tags = request.receipt_tags;
    tags.push(Tag::Bolt11(bolt11.clone()));
    tags.push(Tag::Description(invoice.description.clone()));
    if let Some(preimage) = &invoice.payment_preimage {
        tags.push(Tag::Preimage(hex::encode(preimage.to_vec())));
    }

    let pubkey = keys.public_key();
    let created_at = Timestamp::from(paid_at);
    let kind = Kind::ZapReceipt;
    let content = String::new();
    let id = EventId::new(&pubkey, created_at, &kind, &tags, &content);
    Ok(UnsignedEvent {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
    }
    .sign(keys)?)
}

pub(crate) async fn run_receipt_publisher(
    rpc_socket: PathBuf,
    keys: Keys,
    legacy_pay_index_path: PathBuf,
    configured_relays: HashSet<String>,
    proxy: Option<Socks5Proxy>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let Some(mut rpc) = connect_cln(&rpc_socket, &mut shutdown).await else {
        return Ok(());
    };
    let mut last_pay_index = initialize_pay_index(&mut rpc, &legacy_pay_index_path).await?;

    loop {
        let response = tokio::select! {
            _ = shutdown.recv() => return Ok(()),
            response = rpc.call(cln_rpc::Request::WaitAnyInvoice(WaitanyinvoiceRequest {
                timeout: None,
                lastpay_index: Some(last_pay_index),
            })) => response,
        };

        let invoice: WaitanyinvoiceResponse = match response {
            Ok(response) => match response.try_into() {
                Ok(invoice) => invoice,
                Err(_) => {
                    warn!("CLN returned the wrong response to waitanyinvoice");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
            Err(err) => {
                warn!("Error waiting for a paid invoice: {err}");
                let Some(reconnected) = connect_cln(&rpc_socket, &mut shutdown).await else {
                    return Ok(());
                };
                rpc = reconnected;
                continue;
            }
        };

        let Some(pay_index) = invoice.pay_index else {
            debug!("Ignoring invoice without a pay index: {}", invoice.label);
            continue;
        };

        if matches!(invoice.status, WaitanyinvoiceStatus::PAID) {
            if let Some(amount) = invoice.amount_msat {
                match validate_zap_request(&invoice.description, amount, keys.public_key()) {
                    Ok(request) => {
                        let mut relays = configured_relays.clone();
                        relays.extend(request.relays.iter().cloned());
                        match create_zap_receipt(&keys, request, &invoice) {
                            Ok(receipt) => {
                                let published =
                                    publish_receipt(&relays, proxy.as_ref(), &receipt).await;
                                if published == 0 {
                                    warn!(
                                        "Zap receipt {} could not be sent to any relay",
                                        receipt.id.to_hex()
                                    );
                                } else {
                                    info!(
                                        "Published zap receipt {} to {published} relay(s)",
                                        receipt.id.to_hex()
                                    );
                                }
                            }
                            Err(err) => warn!(
                                "Could not create zap receipt for {}: {err:#}",
                                invoice.label
                            ),
                        }
                    }
                    Err(err) => {
                        debug!("Paid invoice {} is not a valid zap: {err:#}", invoice.label)
                    }
                }
            }
        }

        last_pay_index = pay_index;
        if let Err(err) = write_pay_index(&mut rpc, last_pay_index).await {
            warn!("Could not persist zap pay index: {err:#}");
        }
    }
}

async fn connect_cln(
    rpc_socket: &Path,
    shutdown: &mut broadcast::Receiver<()>,
) -> Option<cln_rpc::ClnRpc> {
    loop {
        match cln_rpc::ClnRpc::new(rpc_socket).await {
            Ok(rpc) => return Some(rpc),
            Err(err) => warn!("Could not connect zap receipt publisher to CLN: {err}"),
        }
        tokio::select! {
            _ = shutdown.recv() => return None,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
}

async fn publish_receipt(
    relays: &HashSet<String>,
    proxy: Option<&Socks5Proxy>,
    receipt: &Event,
) -> usize {
    let mut pending = relays
        .iter()
        .map(|relay| async move {
            (
                relay,
                publish_with_retry(relay.as_str(), proxy, receipt).await,
            )
        })
        .collect::<FuturesUnordered<_>>();
    let deadline = tokio::time::sleep(RECEIPT_PUBLISH_TIMEOUT);
    tokio::pin!(deadline);
    let mut published = 0;

    while !pending.is_empty() {
        tokio::select! {
            _ = &mut deadline => {
                warn!(
                    "Zap receipt {} publication deadline elapsed with {} relay(s) still pending",
                    receipt.id.to_hex(),
                    pending.len()
                );
                break;
            }
            result = pending.next() => {
                if let Some((relay, true)) = result {
                    published += 1;
                    info!(
                        "Published zap receipt {} to {relay}",
                        receipt.id.to_hex()
                    );
                }
            }
        }
    }

    published
}

async fn publish_with_retry(relay: &str, proxy: Option<&Socks5Proxy>, receipt: &Event) -> bool {
    for attempt in 1..=RELAY_ATTEMPTS {
        match publish_once(relay, proxy, receipt).await {
            Ok(()) => return true,
            Err(PublishError::Permanent(err)) => {
                warn!("Could not publish zap receipt to {relay}: {err:#}");
                return false;
            }
            Err(err) if attempt < RELAY_ATTEMPTS => {
                warn!(
                    "Could not publish zap receipt to {relay} (attempt {attempt}): {:#}",
                    err.error()
                );
                tokio::time::sleep(Duration::from_secs(attempt as u64)).await;
            }
            Err(err) => warn!(
                "Could not publish zap receipt to {relay}: {:#}",
                err.error()
            ),
        }
    }
    false
}

async fn publish_once(
    relay: &str,
    proxy: Option<&Socks5Proxy>,
    receipt: &Event,
) -> std::result::Result<(), PublishError> {
    if let Some(proxy) = proxy {
        let relay_url = Url::parse(relay)
            .context("invalid relay URL")
            .map_err(PublishError::Permanent)?;
        let relay_host = relay_url
            .host_str()
            .ok_or_else(|| PublishError::Permanent(anyhow!("relay URL has no host")))?;
        let relay_port = relay_url
            .port_or_known_default()
            .ok_or_else(|| PublishError::Permanent(anyhow!("relay URL has no port")))?;
        let connect = async {
            let stream = Socks5Stream::connect(proxy.address(), (relay_host, relay_port))
                .await
                .context("SOCKS5 proxy connection failed")?;
            tokio_tungstenite::client_async_tls(relay, stream)
                .await
                .context("relay TLS/WebSocket handshake failed")
        };
        let (socket, _) = tokio::time::timeout(PROXY_RELAY_TIMEOUT, connect)
            .await
            .context("relay connection through SOCKS5 proxy timed out")
            .and_then(|result| result)
            .map_err(PublishError::Retryable)?;
        publish_on_socket(socket, receipt).await
    } else {
        let connect = tokio_tungstenite::connect_async(relay);
        let (socket, _) = tokio::time::timeout(RELAY_TIMEOUT, connect)
            .await
            .context("relay connection timed out")
            .and_then(|result| result.map_err(anyhow::Error::from))
            .map_err(PublishError::Retryable)?;
        publish_on_socket(socket, receipt).await
    }
}

async fn publish_on_socket<S>(
    mut socket: WebSocketStream<S>,
    receipt: &Event,
) -> std::result::Result<(), PublishError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let message = ClientMessage::new_event(receipt.clone()).as_json();
    tokio::time::timeout(RELAY_TIMEOUT, socket.send(Message::Text(message)))
        .await
        .context("relay write timed out")
        .and_then(|result| result.map_err(anyhow::Error::from))
        .map_err(PublishError::Retryable)?;

    // NIP-20 OK responses are useful when available, but older relays may not
    // send one. Wait briefly, then treat a completed websocket write as success.
    if let Ok(Some(Ok(Message::Text(message)))) =
        tokio::time::timeout(Duration::from_secs(2), socket.next()).await
    {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
            if value.get(0).and_then(|v| v.as_str()) == Some("OK")
                && value.get(1).and_then(|v| v.as_str()) == Some(&receipt.id.to_hex())
                && value.get(2).and_then(|v| v.as_bool()) == Some(false)
            {
                return Err(PublishError::Permanent(anyhow!(
                    "relay rejected event: {}",
                    value
                        .get(3)
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown reason")
                )));
            }
        }
    }
    let _ = socket.close(None).await;
    Ok(())
}

fn pay_index_datastore_key() -> Vec<String> {
    PAY_INDEX_DATASTORE_KEY
        .iter()
        .map(|component| (*component).to_owned())
        .collect()
}

async fn read_pay_index(rpc: &mut cln_rpc::ClnRpc) -> Result<Option<u64>> {
    let response = rpc
        .call_typed(ListdatastoreRequest {
            key: Some(pay_index_datastore_key()),
        })
        .await
        .context("listdatastore failed")?;
    let Some(entry) = response.datastore.into_iter().next() else {
        return Ok(None);
    };
    let value = entry
        .string
        .ok_or_else(|| anyhow!("zap pay index datastore value is not a string"))?;
    Ok(Some(parse_pay_index(&value)?))
}

fn read_legacy_pay_index(path: &Path) -> Result<Option<u64>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("could not read {}", path.display())),
    };
    if bytes.len() != 8 {
        bail!("invalid legacy pay-index file length at {}", path.display());
    }
    Ok(Some(u64::from_be_bytes(
        bytes.try_into().expect("length checked"),
    )))
}

async fn initialize_pay_index(rpc: &mut cln_rpc::ClnRpc, legacy_path: &Path) -> Result<u64> {
    let stored_index = read_pay_index(rpc).await?;
    let legacy_index = read_legacy_pay_index(legacy_path)?;
    let index = match (stored_index, legacy_index) {
        (Some(stored), Some(legacy)) => stored.max(legacy),
        (Some(stored), None) => stored,
        (None, Some(legacy)) => legacy,
        (None, None) => {
            info!("No stored zap pay index; starting receipt scan at pay index 0");
            return Ok(0);
        }
    };

    if legacy_index.is_some() {
        if stored_index != Some(index) {
            write_pay_index(rpc, index).await?;
        }
        match fs::remove_file(legacy_path) {
            Ok(()) => info!(
                "Migrated zap pay index {index} to CLN datastore and removed {}",
                legacy_path.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => warn!(
                "Zap pay index is stored in CLN datastore, but could not remove {}: {err}",
                legacy_path.display()
            ),
        }
    }

    Ok(index)
}

async fn write_pay_index(rpc: &mut cln_rpc::ClnRpc, index: u64) -> Result<()> {
    rpc.call_typed(DatastoreRequest {
        key: pay_index_datastore_key(),
        string: Some(index.to_string()),
        hex: None,
        mode: Some(DatastoreMode::CREATE_OR_REPLACE),
        generation: None,
    })
    .await
    .context("datastore failed")?;
    Ok(())
}

fn parse_pay_index(value: &str) -> Result<u64> {
    value
        .parse()
        .context("zap pay index datastore value is not an integer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cln_rpc::primitives::{Secret, Sha256};
    use nostr::key::FromSkStr;
    use nostr::EventBuilder;

    const SENDER_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const ZAPPER_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const RECIPIENT: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    fn zap_request(amount: u64) -> String {
        let sender = Keys::from_sk_str(SENDER_SECRET).unwrap();
        let tags = vec![
            Tag::parse(vec!["p", RECIPIENT]).unwrap(),
            Tag::parse(vec![
                "e",
                "0000000000000000000000000000000000000000000000000000000000000004",
            ])
            .unwrap(),
            Tag::parse(vec!["a", &format!("30023:{RECIPIENT}:article")]).unwrap(),
            Tag::parse(vec!["k", "1"]).unwrap(),
            Tag::parse(vec!["amount", &amount.to_string()]).unwrap(),
            Tag::parse(vec!["relays", "wss://relay.example.com"]).unwrap(),
        ];
        EventBuilder::new(Kind::ZapRequest, "thanks", &tags)
            .to_event(&sender)
            .unwrap()
            .as_json()
    }

    fn paid_invoice(description: String, amount: u64) -> WaitanyinvoiceResponse {
        WaitanyinvoiceResponse {
            label: "zap".to_owned(),
            description,
            payment_hash: Sha256::from_str(
                "0000000000000000000000000000000000000000000000000000000000000005",
            )
            .unwrap(),
            status: WaitanyinvoiceStatus::PAID,
            expires_at: 1_700_000_000,
            amount_msat: Some(Amount::from_msat(amount)),
            bolt11: Some("lnbc1test".to_owned()),
            bolt12: None,
            pay_index: Some(7),
            amount_received_msat: Some(Amount::from_msat(amount)),
            paid_at: Some(1_700_000_000),
            payment_preimage: Some(Secret::try_from(vec![6; 32]).unwrap()),
        }
    }

    #[test]
    fn validates_and_builds_a_complete_deterministic_receipt() {
        let zapper = Keys::from_sk_str(ZAPPER_SECRET).unwrap();
        let description = zap_request(21_000);
        let request =
            validate_zap_request(&description, Amount::from_msat(21_000), zapper.public_key())
                .unwrap();
        let invoice = paid_invoice(description.clone(), 21_000);

        let first = create_zap_receipt(&zapper, request.clone(), &invoice).unwrap();
        let second = create_zap_receipt(&zapper, request, &invoice).unwrap();
        first.verify().unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(first.created_at.as_u64(), 1_700_000_000);

        let tags: Vec<Vec<String>> = first.tags.iter().map(Tag::as_vec).collect();
        for required in ["p", "P", "e", "a", "k", "bolt11", "description", "preimage"] {
            assert!(
                tags_named(&tags, required).next().is_some(),
                "missing {required}"
            );
        }
        assert_eq!(
            tags_named(&tags, "description").next().unwrap()[1],
            description
        );
    }

    #[test]
    fn rejects_wrong_amount_and_insecure_relays() {
        let zapper = Keys::from_sk_str(ZAPPER_SECRET).unwrap();
        assert!(validate_zap_request(
            &zap_request(21_000),
            Amount::from_msat(20_000),
            zapper.public_key(),
        )
        .is_err());

        let sender = Keys::from_sk_str(SENDER_SECRET).unwrap();
        let tags = vec![
            Tag::parse(vec!["p", RECIPIENT]).unwrap(),
            Tag::parse(vec!["relays", "ws://127.0.0.1:8080"]).unwrap(),
        ];
        let request = EventBuilder::new(Kind::ZapRequest, "", &tags)
            .to_event(&sender)
            .unwrap()
            .as_json();
        assert!(
            validate_zap_request(&request, Amount::from_msat(1_000), zapper.public_key(),).is_err()
        );
    }

    #[test]
    fn rejects_an_event_with_a_forged_id() {
        let zapper = Keys::from_sk_str(ZAPPER_SECRET).unwrap();
        let mut request: serde_json::Value = serde_json::from_str(&zap_request(21_000)).unwrap();
        request["id"] = serde_json::Value::String("00".repeat(32));
        assert!(validate_zap_request(
            &request.to_string(),
            Amount::from_msat(21_000),
            zapper.public_key(),
        )
        .is_err());
    }

    #[test]
    fn parses_socks5h_proxy_without_resolving_the_target_locally() {
        assert_eq!(
            Socks5Proxy::parse("socks5h://127.0.0.1:9050").unwrap(),
            Socks5Proxy {
                host: "127.0.0.1".to_owned(),
                port: 9050,
            }
        );
        assert_eq!(
            Socks5Proxy::parse("socks5h://localhost").unwrap().port,
            1080
        );
        assert!(Socks5Proxy::parse("socks5://127.0.0.1:9050").is_err());
        assert!(Socks5Proxy::parse("http://127.0.0.1:9050").is_err());
        assert!(Socks5Proxy::parse("socks5h://user:password@127.0.0.1:9050").is_err());
    }

    #[test]
    fn parses_datastore_pay_index() {
        assert_eq!(parse_pay_index("42").unwrap(), 42);
        assert!(parse_pay_index("not-an-index").is_err());
    }

    #[test]
    fn parses_legacy_pay_index() {
        let path = std::env::temp_dir().join(format!("clnurl-pay-index-{}", uuid::Uuid::new_v4()));
        fs::write(&path, 42_u64.to_be_bytes()).unwrap();
        assert_eq!(read_legacy_pay_index(&path).unwrap(), Some(42));
        fs::remove_file(path).unwrap();
    }
}
