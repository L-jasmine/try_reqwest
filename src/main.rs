//! Simple HTTPS GET client based on hyper-rustls
//!
//! First parameter is the mandatory URL to GET.
//! Second parameter is an optional path to CA store.
use hyper::{body::to_bytes, client, Body, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use std::str::FromStr;
use std::{env, io};

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

async fn hyper_client() -> io::Result<()> {
    println!("hyper client start");
    // First parameter is target URL (mandatory).
    let url = match env::args().nth(1) {
        Some(ref url) => Uri::from_str(url).map_err(|e| error(format!("{}", e)))?,
        None => {
            println!("Usage: client <url> <ca_store>");
            return Ok(());
        }
    };

    // Prepare the TLS client config
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    // Build the hyper client from the HTTPS connector.
    println!("hyper client build");
    let client: client::Client<_, hyper::Body> = client::Client::builder().build(https);
    println!("hyper client build ok");

    // Prepare a chain of futures which sends a GET request, inspects
    // the returned headers, collects the whole body and prints it to
    // stdout.
    let fut = async move {
        println!("hyper client get");

        let res = client
            .get(url)
            .await
            .map_err(|e| error(format!("Could not get: {:?}", e)))?;
        println!("hyper client get ok");

        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body: Body = res.into_body();
        let body = to_bytes(body)
            .await
            .map_err(|e| error(format!("Could not get body: {:?}", e)))?;
        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}

async fn run_tokio_echo_server() -> io::Result<()> {
    let addr = "0.0.0.0:8000";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("listen {listener:?}");

    loop {
        println!("accept");
        let (mut socket, _) = listener.accept().await.unwrap();
        println!("accept ok");
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];

            loop {
                println!("start read");
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(5),
                    socket.read(&mut buf),
                )
                .await
                {
                    Err(_) => {
                        if socket.write_all(b"timeout\r\n").await.is_err() {
                            eprintln!("failed to write to socket;");
                        }
                    }
                    // Return or break, depending on the error
                    Ok(Err(e)) => {
                        eprintln!("failed to read from socket; err = {:?}", e);
                        break;
                    }
                    Ok(Ok(n)) => {
                        if n == 0 {
                            break;
                        }

                        // Write the data back
                        if socket.write_all(&buf[0..n]).await.is_err() {
                            eprintln!("failed to write to socket;");
                            break;
                        }
                    }
                }
            }
        });
    }
}

async fn reqwest_client() -> io::Result<()> {
    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url> <ca_store>");
            return Ok(());
        }
    };

    let req = reqwest::get(url).await.unwrap();
    let r = req.text().await.unwrap();
    println!("{r}");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let join = tokio::spawn(async {
        println!("wait 60s");
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        println!("wake")
    });
    // run_tokio_echo_server().await
    // hyper_client().await?;
    reqwest_client().await?;
    join.await.unwrap();
    Ok(())
}
