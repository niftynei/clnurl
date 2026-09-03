# Core Lightning plugin for LNURL and LNAddress support

You can add the plugin by copying it to CLN's plugin directory or by adding the following line to your config file:

```
plugin=/path/to/clnurl
```

For nix-bitcoin based deployments that would be:

```nix
services.clightning = {
  enable = true;
  extraConfig = ''
    plugin=${clnurl}/bin/clnurl
    clnurl_base_address=https://example.com/lnurl_api/
  '';
}
```

where `clnurl` is defined as follows:

```nix
clnurl = (import
  (
    fetchTarball {
      url = "https://github.com/edolstra/flake-compat/archive/b4a34015c698c7793d592d66adbab377907a2be8.tar.gz";
      sha256 = "sha256:1qc703yg0babixi6wshn5wm2kgl5y1drcswgszh4xxzbrwkk9sv7";
    }
  )
  {
    src = fetchTarball {
      url = "https://github.com/elsirion/clnurl/archive/master.tar.gz";
      sha256 = "sha256:0wnvc2i135sqk2vw95wdv2dl34y0gnq3fw61vnsf6fr20610krv6";
    };
  }
).defaultNix.packages.x86_64-linux.default;
```

## Options
`clnurl` exposes the following config options that can be included in CLN's config file or as command line flags:
* `clnurl_base_address`: Specifies the base URL where the API will be hosted. `clnurl` assumes you are running it behind
  a reverse proxy, so even though it might be hosting the API under `http://localhost/lnurl` it might be reachable via
  `https://example.com/lnurl_api/lnurl`, in which case you'd have to specify `https://example.com/lnurl_api/` as base
  address. **You need to set this. It is also important that the reverse proxy uses HTTPS.**
* `clnurl_listen`: Internal listen address for the LNURL web server, defaults to `127.0.0.1:9876`
* `clnurl_min_sendable`: Min millisatoshi amount clnurl is willing to receive, can not be less than 1 or more than maxSendable. Defaults to `100`.
* `clnurl_max_sendable`: Max millisatoshi amount clnurl is willing to receive. Defaults to `100000000000`
* `clnurl_description`: Description used for the legacy, unnamed `/lnurl` endpoint. Defaults to `Gimme money!`. Named
  endpoints configured through the RPC interface have independent descriptions.
* `clnurl_nostr_secret_path`: Path to a file containing a dedicated Nostr secret key (`nsec` or hex) used to sign NIP-57
  zap receipts. This is the recommended way to configure the key; the file should be readable only by the CLN user.
* `clnurl_nostr_secret`: Inline dedicated Nostr secret key used to sign zap receipts. Do not use this in Nix configuration,
  since Nix strings are copied into the world-readable Nix store.
* `clnurl_nostr_pubkey`: Optional hex or `npub` public key corresponding to the configured secret. If present, startup fails
  when the keys do not match. The public key is derived automatically when this option is omitted.
* `clnurl_nostr_relays`: Optional comma-separated fallback relays. Receipts are always sent to the secure `wss://` relays
  requested by the zap sender as required by NIP-57.
* `clnurl_nostr_proxy`: Optional SOCKS5 proxy for relay connections, written as `socks5h://host:port`. Relay hostnames are
  resolved by the proxy. Authentication is not supported.
* `clnurl_pay_index_path`: Deprecated. If the legacy pay-index file exists, its value is migrated to CLN's datastore and
  the file is removed. The option remains temporarily so existing configurations can be migrated safely.

## Named LNURL endpoints

Named endpoints can be added, updated, removed, and listed while `clnurl` is running:

```text
lightning-cli clnurl-add name=alice description="Tips for Alice"
lightning-cli clnurl-update name=alice description="Alice's new description"
lightning-cli clnurl-list
lightning-cli clnurl-remove name=alice
```

Endpoint names may contain lowercase letters, digits, `-`, `_`, and `.`, and are limited to 64 characters. Descriptions
must be non-empty and are limited to 1024 UTF-8 bytes. Configurations are stored in CLN's datastore under
`clnurl/endpoints/<name>` and loaded when the plugin starts.

The public `/.well-known/lnurlp/<name>` route should be rewritten by the reverse proxy to `/lnurl/<name>`. The returned
metadata contains both the configured `text/plain` description and a LUD-16 `text/identifier` derived from the requested
host, such as `alice@example.com`. The invoice callback includes the endpoint name and the exact metadata advertised to the
wallet, so an in-flight payment continues to work if the endpoint's description is updated. Removing an endpoint disables
both discovery and invoice callbacks for that name. The reverse proxy must preserve the original `Host` header; NixOS'
`recommendedProxySettings` does this by default.

## Nostr zaps

Full NIP-57 support requires a dedicated signing key. For a normal installation, create a file containing only the `nsec`
or 64-character hex secret, restrict it to the CLN user, and configure:

```text
clnurl_nostr_secret_path=/run/keys/clnurl-nostr-secret
clnurl_nostr_relays=wss://relay.example.com
clnurl_nostr_proxy=socks5h://127.0.0.1:9050
```

The extra relay and proxy are optional. Every valid zap request must provide at least one `wss://` relay, and `clnurl`
publishes the receipt to those requested relays as well. `socks5h` keeps relay DNS resolution inside the proxy, which is
appropriate for a Tor-isolated CLN service that can only reach a local SOCKS port.

Relay publications run concurrently and are bounded to 30 seconds per receipt. Transient connection failures are retried
once, while explicit relay rejections are not retried. Successful relay URLs are logged as soon as they accept a receipt.

When a signing key is configured, `clnurl` advertises `allowsNostr` and its derived `nostrPubkey`, validates kind `9734`
requests, creates description-hash invoices, and watches CLN for settlement. A paid zap produces a signed kind `9735`
receipt containing the original request, BOLT11 invoice, target tags, and payment preimage. The receipt timestamp uses CLN's
`paid_at`, making its event ID stable if it is replayed after a restart.

The publisher stores its last examined CLN pay index in CLN's datastore under `clnurl/nostr/pay_index`. If that key does not
exist, it scans paid invoices from index zero. This backfills receipts for any valid zap invoices retained by CLN; relays
deduplicate them by their deterministic event IDs. Configuring only the legacy `clnurl_nostr_pubkey` no longer advertises
zap support, because a public key alone cannot sign the required receipts. On the first startup after upgrading, any valid
legacy pay-index file is copied into the datastore and deleted after the datastore write succeeds.

## Reverse proxying

```nix
services.nginx = {
  enable = true;
  recommendedProxySettings = true;
  recommendedTlsSettings = true;
  proxyTimeout = "1d";
  virtualHosts."example.com" = {
    enableACME = true;
    forceSSL = true;
    locations."/lnurl_api/" = {
      proxyPass = "http://127.0.0.1:9876/";
      extraConfig = ''
        add_header Access-Control-Allow-Origin *;
      '';

    };
    # Dynamically configured LN Address names are forwarded to /lnurl/<name>.
    locations."~ ^/\\.well-known/lnurlp/([a-z0-9._-]+)$" = {
      proxyPass = "http://127.0.0.1:9876";
      extraConfig = ''
        rewrite ^/\.well-known/lnurlp/([a-z0-9._-]+)$ /lnurl/$1 break;
        add_header Access-Control-Allow-Origin * always;
      '';
    };
  };
};

security.acme = {
  acceptTerms = true;
  defaults.email = "foo@bar.com";
};

```

## Contributing
I mostly `clnurl` it so I could play with the cool kids on nostr, PRs welcome, but I'm unlikely to fix bugs myself that
don't annoy me personally. Like the MIT license says: "provided as-is".

If you find `clnurl` useful or just want to test it out in the wild feel free to throw me some sats :P

| Format     | Encoding                                                                                            |
|------------|-----------------------------------------------------------------------------------------------------|
| LNURL QR   | <img src="https://raw.githubusercontent.com/elsirion/clnurl/master/elsirion_lnurl.png" width="200"> |
| LNURL      | `lnurl1dp68gurn8ghj7cn5vvknytnnd9exjmmw9e5k7tmvde6hymzlv9cxjtmvde6hymq64r0pl`                       |
| LN Address | `elsirion@sirion.io`                                                                                |
