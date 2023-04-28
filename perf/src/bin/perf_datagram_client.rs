use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use quinn::TokioRuntime;
use tracing::{error, info};

use perf::{bind_socket, noprotection::NoProtectionClientConfig};
#[cfg(feature = "json-output")]
use std::path::PathBuf;
use hdrhistogram::Histogram;

/// Connects to a QUIC perf server and maintains a specified pattern of requests until interrupted
#[derive(Parser)]
#[clap(name = "client")]
struct Opt {
    /// Host to connect to
    #[clap(default_value = "localhost:4433")]
    host: String,
    /// Override DNS resolution for host
    #[clap(long)]
    ip: Option<IpAddr>,
    /// The time to run in seconds
    #[clap(long, default_value = "10")]
    duration: u64,
    /// The interval in seconds at which stats are reported
    #[clap(long, default_value = "1")]
    interval: u64,
    /// Send buffer size in bytes
    #[clap(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[clap(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Specify the local socket address
    #[clap(long)]
    local_addr: Option<SocketAddr>,
    /// Whether to print connection statistics
    #[clap(long)]
    conn_stats: bool,
    /// File path to output JSON statistics to. If the file is '-', stdout will be used
    #[cfg(feature = "json-output")]
    #[clap(long)]
    json: Option<PathBuf>,
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,
    /// UDP payload size that the network must be capable of carrying
    #[clap(long, default_value = "1200")]
    initial_max_udp_payload_size: u16,
    /// Disable packet encryption/decryption (for debugging purpose)
    #[clap(long = "no-protection")]
    no_protection: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let mut host_parts = opt.host.split(':');
    let host_name = host_parts.next().unwrap();
    let host_port = host_parts
        .next()
        .map_or(Ok(443), |x| x.parse())
        .context("parsing port")?;
    let addr = match opt.ip {
        None => tokio::net::lookup_host(&opt.host)
            .await
            .context("resolving host")?
            .next()
            .unwrap(),
        Some(ip) => SocketAddr::new(ip, host_port),
    };

    info!("connecting to {} at {}", host_name, addr);

    let bind_addr = opt.local_addr.unwrap_or_else(|| {
        let unspec = if addr.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        SocketAddr::new(unspec, 0)
    });

    info!("local addr {:?}", bind_addr);

    let socket = bind_socket(bind_addr, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::Endpoint::new(Default::default(), None, socket, Arc::new(TokioRuntime))?;

    let mut crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(perf::PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if opt.keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut transport = quinn::TransportConfig::default();
    #[cfg(any(windows, os = "linux"))]
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport.initial_mtu(opt.initial_max_udp_payload_size);
    transport.min_mtu(1452);
    transport.datagram_send_buffer_size(100 * 1024 * 1024);

    let mut cfg = if opt.no_protection {
        quinn::ClientConfig::new(Arc::new(NoProtectionClientConfig::new(Arc::new(crypto))))
    } else {
        quinn::ClientConfig::new(Arc::new(crypto))
    };
    cfg.transport_config(Arc::new(transport));

    let connection = endpoint
        .connect_with(cfg, addr, host_name)?
        .await
        .context("connecting")?;

    info!("established");

    let datagram_size = connection.max_datagram_size().unwrap();
    assert_eq!(datagram_size, 1414);

    let drive_fut = async {
        tokio::try_join!(
            drive_datagram(
                connection.clone(),
                datagram_size,
            ),
        )
    };


    let stats_fut = async {
        let interval_duration = Duration::from_secs(opt.interval);

        let mut total_packets_sent = 0;
        let mut total_packets_recvd = 0;
        let mut upload_throughput = Histogram::<u64>::new(3).unwrap();
        let mut download_throughput = Histogram::<u64>::new(3).unwrap();

        loop {
            tokio::time::sleep(interval_duration).await;
            {
                let current_stats = connection.stats();

                let packets_sent_in_interval = current_stats.frame_tx.datagram - total_packets_sent;
                let bytes_sent_in_interval = packets_sent_in_interval * datagram_size as u64;
                upload_throughput.record(bytes_sent_in_interval).unwrap();

                let packets_recvd_in_interval = current_stats.frame_rx.datagram - total_packets_recvd;
                let bytes_recvd_in_interval = packets_recvd_in_interval * datagram_size as u64;
                download_throughput.record(bytes_recvd_in_interval).unwrap();

                total_packets_sent = current_stats.frame_tx.datagram;
                total_packets_recvd = current_stats.frame_rx.datagram;

                let print_metric = |label: &'static str, get_metric: fn(&Histogram<u64>) -> u64| {
                    println!(
                        " {} │ {:11.2} MiB/s │ {:13.2} MiB/s",
                        label,
                        get_metric(&upload_throughput) as f64 / 1024.0 / 1024.0,
                        get_metric(&download_throughput) as f64 / 1024.0 / 1024.0,
                    );
                };

                println!();
                println!("      | Upload Throughput | Download Throughput");
                println!("──────┼───────────────────┼────────────────────");

                print_metric("AVG ", |hist| hist.mean() as u64);
                print_metric("P0  ", |hist| hist.value_at_quantile(0.00));
                print_metric("P10 ", |hist| hist.value_at_quantile(0.10));
                print_metric("P50 ", |hist| hist.value_at_quantile(0.50));
                print_metric("P90 ", |hist| hist.value_at_quantile(0.90));
                print_metric("P100", |hist| hist.value_at_quantile(1.00));
            }
        }
    };

    tokio::select! {
        _ = drive_fut => {}
        _ = stats_fut => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutting down");
            connection.close(0u32.into(), b"interrupted");
        }
        // Add a small duration so the final interval can be reported
        _ = tokio::time::sleep(Duration::from_secs(opt.duration) + Duration::from_millis(200)) => {
            info!("shutting down");

            println!("{:?}", connection.stats());

            connection.close(0u32.into(), b"done");
        }
    }

    endpoint.wait_idle().await;

    Ok(())
}

async fn drive_datagram(connection: quinn::Connection, datagram_size: usize) -> Result<()> {
    // Since all datagrams contain the same data, they can all use the same shared buffer
    let data = Bytes::from(vec![42; datagram_size]);

    loop {
        // Make sure the outgoing datagram buffer is always full, so we are sending at the maximum
        // possible rate allowed by congestion control
        let space = connection.datagram_send_buffer_space();
        let mut sent = 0;
        while sent + datagram_size <= space {
            sent += datagram_size;
            connection.send_datagram(data.clone()).context("send_datagram")?;
        }

        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
