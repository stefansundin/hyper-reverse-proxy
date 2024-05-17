use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;

use hyper_reverse_proxy::ReverseProxy;
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;

type Connector = HttpsConnector<HttpConnector>;
type ResponseBody = UnsyncBoxBody<Bytes, std::io::Error>;

lazy_static::lazy_static! {
    static ref PROXY_CLIENT: ReverseProxy<Connector> = {
      let connector: Connector = Connector::builder()
          .with_tls_config(
              rustls::ClientConfig::builder()
                  .with_native_roots()
                  .expect("with_native_roots")
                  .with_no_client_auth(),
          )
          .https_or_http()
          .enable_http1()
          .build();
      ReverseProxy::new(
          hyper_util::client::legacy::Builder::new(TokioExecutor::new())
              .pool_idle_timeout(Duration::from_secs(3))
              .pool_timer(TokioTimer::new())
              .build::<_, Incoming>(connector),
      )
    };
}

async fn handle(
    client_ip: IpAddr,
    req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok());
    if host.is_some_and(|host| host.starts_with("service1.localhost")) {
        match PROXY_CLIENT
            .call(client_ip, "http://127.0.0.1:13901", req)
            .await
        {
            Ok(response) => Ok(response),
            Err(_error) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(UnsyncBoxBody::new(
                    Empty::<Bytes>::new().map_err(io::Error::other),
                ))
                .unwrap()),
        }
    } else if host.is_some_and(|host| host.starts_with("service2.localhost")) {
        match PROXY_CLIENT
            .call(client_ip, "http://127.0.0.1:13902", req)
            .await
        {
            Ok(response) => Ok(response),
            Err(_error) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(UnsyncBoxBody::new(
                    Empty::<Bytes>::new().map_err(io::Error::other),
                ))
                .unwrap()),
        }
    } else {
        let body_str = format!("{:?}", req);
        Ok(Response::new(UnsyncBoxBody::new(
            Full::new(Bytes::from(body_str)).map_err(io::Error::other),
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_addr = "127.0.0.1:8000";
    let addr: SocketAddr = bind_addr.parse().expect("Could not parse ip:port.");

    // We create a TcpListener and bind it to the address
    let listener = TcpListener::bind(addr).await?;

    println!(
        "Access service1 on http://service1.localhost:{}",
        addr.port()
    );
    println!(
        "Access service2 on http://service2.localhost:{}",
        addr.port()
    );

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let client_ip = remote_addr.ip();

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(move |req| handle(client_ip, req)))
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}
