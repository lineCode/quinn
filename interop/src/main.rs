#![feature(await_macro, async_await, futures_api)]
use std::net::ToSocketAddrs;
use std::str;
use std::sync::{Arc, Mutex};

use futures::TryFutureExt;
use structopt::StructOpt;
use tokio::runtime::current_thread::Runtime;

use failure::{format_err, Error, ResultExt};
use slog::{o, Drain, Logger};

type Result<T> = std::result::Result<T, Error>;

#[derive(StructOpt, Debug)]
#[structopt(name = "interop")]
struct Opt {
    host: String,
    #[structopt(default_value = "4433")]
    port: u16,
    #[structopt(default_value = "4434")]
    retry_port: u16,

    /// Enable key logging
    #[structopt(long = "keylog")]
    keylog: bool,
}

fn main() {
    let opt = Opt::from_args();
    let code = {
        let decorator = slog_term::PlainSyncDecorator::new(std::io::stderr());
        let drain = slog_term::FullFormat::new(decorator)
            .use_original_order()
            .build()
            .fuse();
        if let Err(e) = run(Logger::root(drain, o!()), opt) {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

struct State {
    saw_cert: bool,
}

fn run(log: Logger, options: Opt) -> Result<()> {
    let remote = format!("{}:{}", options.host, options.port)
        .to_socket_addrs()?
        .next()
        .ok_or(format_err!("couldn't resolve to an address"))?;

    let mut runtime = Runtime::new()?;

    let state = Arc::new(Mutex::new(State { saw_cert: false }));

    let mut builder = quinn::Endpoint::new();
    let mut tls_config = rustls::ClientConfig::new();
    tls_config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(InteropVerifier(state.clone())));
    tls_config.alpn_protocols = vec![str::from_utf8(quinn::ALPN_QUIC_HTTP).unwrap().into()];
    if options.keylog {
        tls_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }
    let client_config = quinn::ClientConfig {
        tls_config: Arc::new(tls_config),
    };

    builder.logger(log.clone());
    let (endpoint, driver, _) = builder.bind("[::]:0")?;
    runtime.spawn(driver.map_err(|e| panic!("IO error: {}", e)).compat());

    let mut handshake = false;
    let mut stream_data = false;
    let mut close = false;
    let mut resumption = false;
    let mut key_update = false;
    let result: Result<()> = runtime.block_on(
        Box::pin(
            async {
                let conn = endpoint.connect_with(&client_config, &remote, &options.host)?;
                let (conn, _) = await!(conn.establish()).context("failed to connect")?;
                println!("connected");
                assert!(state.lock().unwrap().saw_cert);
                handshake = true;
                let stream = await!(conn.open_bi()).context("failed to open stream")?;
                let data = await!(get(stream)).context("request failed")?;
                println!("read {} bytes, closing", data.len());
                stream_data = true;
                await!(conn.close(0, b"done"));
                close = true;

                println!("attempting resumption");
                state.lock().unwrap().saw_cert = false;
                let conn = endpoint.connect_with(&client_config, &remote, &options.host)?;
                let (conn, _) = await!(conn.establish()).context("failed to connect")?;
                resumption = !state.lock().unwrap().saw_cert;
                println!("updating keys");
                conn.force_key_update();
                let stream = await!(conn.open_bi()).context("failed to open stream")?;
                await!(get(stream)).context("request failed")?;
                key_update = true;
                await!(conn.close(0, b"done"));
                Ok(())
            },
        )
        .compat(),
    );
    if let Err(e) = result {
        println!("failure: {}", e);
    }

    let mut retry = false;
    {
        println!("connecting to retry port");
        let remote = format!("{}:{}", options.host, options.retry_port)
            .to_socket_addrs()?
            .next()
            .ok_or(format_err!("couldn't resolve to an address"))?;
        let result: Result<()> = runtime.block_on(
            Box::pin(
                async {
                    let conn = endpoint.connect_with(&client_config, &remote, &options.host)?;
                    let (conn, _) = await!(conn.establish()).context("failed to connect")?;
                    retry = true;
                    await!(conn.close(0, b"done"));
                    Ok(())
                },
            )
            .compat(),
        );
        if let Err(e) = result {
            println!("failure: {}", e);
        }
    }

    if handshake {
        print!("VH");
    }
    if stream_data {
        print!("D");
    }
    if close {
        print!("C");
    }
    if resumption {
        print!("R");
    }
    if retry {
        print!("S");
    }
    if key_update {
        print!("U");
    }

    println!("");

    Ok(())
}

async fn get(mut stream: quinn::BiStream) -> Result<Box<[u8]>> {
    await!(stream.send.write_all(b"GET /index.html\r\n")).context("writing request")?;
    await!(stream.send.finish()).context("finishing stream")?;
    Ok(await!(stream.recv.read_to_end(usize::max_value())).context("reading response")?)
}

struct InteropVerifier(Arc<Mutex<State>>);
impl rustls::ServerCertVerifier for InteropVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        self.0.lock().unwrap().saw_cert = true;
        Ok(rustls::ServerCertVerified::assertion())
    }
}
