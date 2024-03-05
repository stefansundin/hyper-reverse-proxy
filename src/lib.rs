#![doc = include_str!("../README.md")]

#[macro_use]
extern crate tracing;

use http_body_util::{BodyExt, Empty};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::http::header::{InvalidHeaderValue, ToStrError};
use hyper::http::uri::InvalidUri;
use hyper::{body::Incoming, Error, Request, Response, StatusCode};
use hyper_util::client::legacy::{connect::Connect, Client, Error as LegacyError};
use hyper_util::rt::tokio::TokioIo;
use lazy_static::lazy_static;
use std::net::{IpAddr, SocketAddr};
use tokio::io::copy_bidirectional;

lazy_static! {
    static ref TE_HEADER: HeaderName = HeaderName::from_static("te");
    static ref CONNECTION_HEADER: HeaderName = HeaderName::from_static("connection");
    static ref UPGRADE_HEADER: HeaderName = HeaderName::from_static("upgrade");
    static ref TRAILER_HEADER: HeaderName = HeaderName::from_static("trailer");
    static ref TRAILERS_HEADER: HeaderName = HeaderName::from_static("trailers");
    // A list of the headers, using hypers actual HeaderName comparison
    static ref HOP_HEADERS: [HeaderName; 9] = [
        CONNECTION_HEADER.clone(),
        TE_HEADER.clone(),
        TRAILER_HEADER.clone(),
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        HeaderName::from_static("proxy-authenticate"),
        HeaderName::from_static("proxy-authorization"),
        HeaderName::from_static("transfer-encoding"),
        HeaderName::from_static("upgrade"),
    ];

    static ref X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
}

#[derive(Debug)]
pub enum ProxyError {
    InvalidUri(InvalidUri),
    LegacyHyperError(LegacyError),
    HyperError(Error),
    ForwardHeaderError,
    UpgradeError(String),
    UpstreamError(String),
}

impl From<LegacyError> for ProxyError {
    fn from(err: LegacyError) -> ProxyError {
        ProxyError::LegacyHyperError(err)
    }
}

impl From<Error> for ProxyError {
    fn from(err: Error) -> ProxyError {
        ProxyError::HyperError(err)
    }
}

impl From<InvalidUri> for ProxyError {
    fn from(err: InvalidUri) -> ProxyError {
        ProxyError::InvalidUri(err)
    }
}

impl From<ToStrError> for ProxyError {
    fn from(_err: ToStrError) -> ProxyError {
        ProxyError::ForwardHeaderError
    }
}

impl From<InvalidHeaderValue> for ProxyError {
    fn from(_err: InvalidHeaderValue) -> ProxyError {
        ProxyError::ForwardHeaderError
    }
}

fn remove_hop_headers(headers: &mut HeaderMap) {
    debug!("Removing hop headers");

    for header in &*HOP_HEADERS {
        headers.remove(header);
    }
}

fn get_upgrade_type(headers: &HeaderMap) -> Option<String> {
    #[allow(clippy::blocks_in_conditions)]
    if headers
        .get(&*CONNECTION_HEADER)
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(',')
                .any(|e| e.trim() == *UPGRADE_HEADER)
        })
        .unwrap_or(false)
    {
        if let Some(upgrade_value) = headers.get(&*UPGRADE_HEADER) {
            debug!(
                "Found upgrade header with value: {}",
                upgrade_value.to_str().unwrap().to_owned()
            );

            return Some(upgrade_value.to_str().unwrap().to_owned());
        }
    }

    None
}

fn remove_connection_headers(headers: &mut HeaderMap) {
    if headers.get(&*CONNECTION_HEADER).is_some() {
        debug!("Removing connection headers");

        let value = headers.get(&*CONNECTION_HEADER).cloned().unwrap();

        for name in value.to_str().unwrap().split(',') {
            if !name.trim().is_empty() {
                headers.remove(name.trim());
            }
        }
    }
}

fn create_proxied_response<B>(mut response: Response<B>) -> Response<B> {
    debug!("Creating proxied response");

    remove_hop_headers(response.headers_mut());
    remove_connection_headers(response.headers_mut());

    response
}

fn create_forward_uri<B>(forward_url: &str, req: &Request<B>) -> String {
    debug!("Building forward uri");

    let split_url = forward_url.split('?').collect::<Vec<&str>>();

    let mut base_url: &str = split_url.first().unwrap_or(&"");
    let forward_url_query: &str = split_url.get(1).unwrap_or(&"");

    let path2 = req.uri().path();

    if base_url.ends_with('/') {
        let mut path1_chars = base_url.chars();
        path1_chars.next_back();

        base_url = path1_chars.as_str();
    }

    let total_length = base_url.len()
        + path2.len()
        + 1
        + forward_url_query.len()
        + req.uri().query().map(|e| e.len()).unwrap_or(0);

    debug!("Creating url with capacity to {}", total_length);

    let mut url = String::with_capacity(total_length);

    url.push_str(base_url);
    url.push_str(path2);

    if !forward_url_query.is_empty() || req.uri().query().map(|e| !e.is_empty()).unwrap_or(false) {
        debug!("Adding query parts to url");
        url.push('?');
        url.push_str(forward_url_query);

        if forward_url_query.is_empty() {
            debug!("Using request query");

            url.push_str(req.uri().query().unwrap_or(""));
        } else {
            debug!("Merging request and forward_url query");

            let request_query_items = req.uri().query().unwrap_or("").split('&').map(|el| {
                let parts = el.split('=').collect::<Vec<&str>>();
                (parts[0], if parts.len() > 1 { parts[1] } else { "" })
            });

            let forward_query_items = forward_url_query
                .split('&')
                .map(|el| {
                    let parts = el.split('=').collect::<Vec<&str>>();
                    parts[0]
                })
                .collect::<Vec<_>>();

            for (key, value) in request_query_items {
                if !forward_query_items.iter().any(|e| e == &key) {
                    url.push('&');
                    url.push_str(key);
                    url.push('=');
                    url.push_str(value);
                }
            }

            if url.ends_with('&') {
                let mut parts = url.chars();
                parts.next_back();

                url = parts.as_str().to_string();
            }
        }
    }

    debug!("Built forwarding url from request: {}", url);

    url.parse().unwrap()
}

fn create_proxied_request<B>(
    client_ip: IpAddr,
    mut request: Request<B>,
    upgrade_type: Option<&String>,
) -> Result<Request<B>, ProxyError> {
    debug!("Creating proxied request");

    let contains_te_trailers_value = request
        .headers()
        .get(&*TE_HEADER)
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .split(',')
                .any(|e| e.trim() == *TRAILERS_HEADER)
        })
        .unwrap_or(false);

    debug!("Setting headers of proxied request");

    remove_hop_headers(request.headers_mut());
    remove_connection_headers(request.headers_mut());

    if contains_te_trailers_value {
        debug!("Setting up trailer headers");

        request
            .headers_mut()
            .insert(&*TE_HEADER, HeaderValue::from_static("trailers"));
    }

    if let Some(value) = upgrade_type {
        debug!("Repopulate upgrade headers");

        request
            .headers_mut()
            .insert(&*UPGRADE_HEADER, value.parse().unwrap());
        request
            .headers_mut()
            .insert(&*CONNECTION_HEADER, HeaderValue::from_static("UPGRADE"));
    }

    // Add forwarding information in the headers
    match request.headers_mut().entry(&*X_FORWARDED_FOR) {
        hyper::header::Entry::Vacant(entry) => {
            debug!("X-Forwarded-for header was vacant");
            entry.insert(client_ip.to_string().parse()?);
        }

        hyper::header::Entry::Occupied(entry) => {
            debug!("X-Forwarded-for header was occupied");
            let client_ip_str = client_ip.to_string();
            let mut addr =
                String::with_capacity(entry.get().as_bytes().len() + 2 + client_ip_str.len());

            addr.push_str(std::str::from_utf8(entry.get().as_bytes()).unwrap());
            addr.push(',');
            addr.push(' ');
            addr.push_str(&client_ip_str);
        }
    }

    debug!("Created proxied request");

    Ok(request)
}

fn get_upstream_addr(forward_uri: &hyper::Uri) -> Result<SocketAddr, ProxyError> {
    let host = forward_uri.host().ok_or(ProxyError::UpstreamError(
        "forward_uri has no host".to_string(),
    ))?;
    let port = forward_uri.port_u16().ok_or(ProxyError::UpstreamError(
        "forward_uri has no port".to_string(),
    ))?;
    Ok(SocketAddr::new(
        host.parse().map_err(|_| {
            ProxyError::UpstreamError("forward_uri host must be an IP address".to_string())
        })?,
        port,
    ))
}

type ResponseBody = http_body_util::combinators::UnsyncBoxBody<hyper::body::Bytes, std::io::Error>;

pub async fn call<'a, T: Connect + Clone + Send + Sync + 'static>(
    client_ip: IpAddr,
    forward_uri: &str,
    mut request: Request<Incoming>,
    client: &'a Client<T, Incoming>,
) -> Result<Response<ResponseBody>, ProxyError> {
    debug!(
        "Received proxy call from {} to {}, client: {}",
        request.uri().to_string(),
        forward_uri,
        client_ip
    );

    let request_upgrade_type = get_upgrade_type(request.headers());

    let request_uri: hyper::Uri = create_forward_uri(forward_uri, &request).parse()?;
    *request.uri_mut() = request_uri.clone();

    let request = create_proxied_request(client_ip, request, request_upgrade_type.as_ref())?;

    if request_upgrade_type.is_none() {
        let response = client.request(request).await?;

        debug!("Responding to call with response");
        return Ok(create_proxied_response(
            response.map(|body| body.map_err(std::io::Error::other).boxed_unsync()),
        ));
    }

    let (request_parts, request_body) = request.into_parts();
    let upstream_request =
        Request::from_parts(request_parts.clone(), Empty::<hyper::body::Bytes>::new());
    let mut downstream_request = Request::from_parts(request_parts, request_body);

    let (mut upstream_conn, downstream_response) = {
        let upstream_addr = get_upstream_addr(&request_uri)?;
        let conn = TokioIo::new(
            tokio::net::TcpStream::connect(upstream_addr)
                .await
                .map_err(|e| ProxyError::UpstreamError(e.to_string()))?,
        );
        let (mut sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.with_upgrades().await {
                warn!("Upgrading connection failed: {:?}", err);
            }
        });

        let response = sender.send_request(upstream_request).await?;

        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(ProxyError::UpgradeError(
                "Server did not response with Switching Protocols status".to_string(),
            ));
        };

        let (response_parts, response_body) = response.into_parts();
        let upstream_response = Response::from_parts(response_parts.clone(), response_body);
        let downstream_response = Response::from_parts(response_parts, Empty::new());

        (
            TokioIo::new(hyper::upgrade::on(upstream_response).await?),
            downstream_response,
        )
    };

    tokio::task::spawn(async move {
        let mut downstream_conn = match hyper::upgrade::on(&mut downstream_request).await {
            Ok(upgraded) => TokioIo::new(upgraded),
            Err(e) => {
                warn!("Failed to upgrade request: {e}");
                return;
            }
        };

        if let Err(e) = copy_bidirectional(&mut downstream_conn, &mut upstream_conn).await {
            warn!("Bidirectional copy failed: {e}");
        }
    });

    Ok(downstream_response.map(|body| body.map_err(std::io::Error::other).boxed_unsync()))
}

pub struct ReverseProxy<T: Connect + Clone + Send + Sync + 'static> {
    client: Client<T, Incoming>,
}

impl<T: Connect + Clone + Send + Sync + 'static> ReverseProxy<T> {
    pub fn new(client: Client<T, Incoming>) -> Self {
        Self { client }
    }

    pub async fn call(
        &self,
        client_ip: IpAddr,
        forward_uri: &str,
        request: Request<Incoming>,
    ) -> Result<Response<ResponseBody>, ProxyError> {
        call::<T>(client_ip, forward_uri, request, &self.client).await
    }
}

#[cfg(feature = "__bench")]
pub mod benches {
    pub fn hop_headers() -> &'static [crate::HeaderName] {
        &*super::HOP_HEADERS
    }

    pub fn create_proxied_response<T>(response: crate::Response<T>) {
        super::create_proxied_response(response);
    }

    pub fn create_forward_uri<B>(forward_url: &str, req: &crate::Request<B>) {
        super::create_forward_uri(forward_url, req);
    }

    pub fn create_proxied_request<B>(
        client_ip: crate::IpAddr,
        forward_url: &str,
        request: crate::Request<B>,
        upgrade_type: Option<&String>,
    ) {
        super::create_proxied_request(client_ip, forward_url, request, upgrade_type).unwrap();
    }
}
