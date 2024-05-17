# This is a fork

This repo contains a fork of the [original hyper-reverse-proxy
codebase][upstream], adding to it a few improvements:

- Fix to a bug where the `Host` header was getting overwritten on the upstream
  HTTP request.

- Upgraded hyper version to 1.x (and fixes related to that upgrade)

- Logging cleanup

Plus more as time goes on.

[upstream]: https://github.com/felipenoris/hyper-reverse-proxy

# hyper-reverse-proxy

[![License][license-img]](LICENSE)
[![docs][docs-img]][docs-url]
[![version][version-img]][version-url]

[license-img]: https://img.shields.io/crates/l/hyper-reverse-proxy.svg
[docs-img]: https://docs.rs/hyper-reverse-proxy/badge.svg
[docs-url]: https://docs.rs/hyper-reverse-proxy
[version-img]: https://img.shields.io/crates/v/hyper-reverse-proxy.svg
[version-url]: https://crates.io/crates/hyper-reverse-proxy

A simple reverse proxy, to be used with [Hyper].

The implementation ensures that [Hop-by-hop headers] are stripped correctly in both directions,
and adds the client's IP address to a comma-space-separated list of forwarding addresses in the
`X-Forwarded-For` header.

The implementation is based on Go's [`httputil.ReverseProxy`].

[Hyper]: http://hyper.rs/
[Hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
[`httputil.ReverseProxy`]: https://golang.org/pkg/net/http/httputil/#ReverseProxy

# Example

Run the example by cloning this repository and running:

```shell
cargo run --example simple
```

The example will set up a reverse proxy listening on `127.0.0.1:8000`, and will proxy these calls:

* `http://service1.localhost:8000` will be proxied to `http://127.0.0.1:13901`

* `http://service2.localhost:8000` will be proxied to `http://127.0.0.1:13902`

* All other URLs will display request information.
