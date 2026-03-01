//! HTTP/HTTPS proxy server implementation.

use crate::config::ConfigManager;
use crate::rule_engine::{Rule, RuleEngine};
use crate::upstream::{connect_via_upstream, http_proxy_request, parse_proxy_url};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// The proxy server.
pub struct ProxyServer {
    rule_engine: Arc<RuleEngine>,
    config_mgr: Arc<ConfigManager>,
    port: u16,
}

impl ProxyServer {
    pub fn new(rule_engine: Arc<RuleEngine>, config_mgr: Arc<ConfigManager>, port: u16) -> Self {
        Self {
            rule_engine,
            config_mgr,
            port,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port)).await?;

        let upstream = self.config_mgr.get().upstream_proxy;
        println!();
        println!("========================================");
        println!("  SimpleProxy server started");
        println!("  Listening on: http://127.0.0.1:{}", self.port);
        if let Some(ref up) = upstream {
            println!("  Upstream proxy: {}", up);
        }
        println!("========================================");
        println!();
        println!(
            "Tip: Set your browser/system HTTP proxy to 127.0.0.1:{}",
            self.port
        );
        println!();

        loop {
            let (stream, addr) = listener.accept().await?;
            debug!("Connection from {}", addr);

            let engine = Arc::clone(&self.rule_engine);
            let cfg = Arc::clone(&self.config_mgr);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, engine, cfg).await {
                    debug!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single client connection.
async fn handle_connection(
    mut stream: TcpStream,
    engine: Arc<RuleEngine>,
    config_mgr: Arc<ConfigManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read the initial request data
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request_data = &buf[..n];

    // Parse the first line
    let request_str = String::from_utf8_lossy(request_data);
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        send_error(&mut stream, 400, "Bad Request").await?;
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];

    // Handle CONNECT method (HTTPS tunneling)
    if method == "CONNECT" {
        return handle_connect(stream, url, &engine, &config_mgr).await;
    }

    // Build full URL
    let full_url = if url.starts_with("http") {
        url.to_string()
    } else {
        // Extract Host header
        let host = extract_header(&request_str, "Host").unwrap_or_default();
        format!("http://{}{}", host, url)
    };

    // Parse all headers from the request
    let (headers, body) = parse_request(&request_str, request_data);

    // Check rules
    if let Some(rule) = engine.match_url(&full_url) {
        info!("[Intercept] {} => {}", rule.r#type.to_uppercase(), full_url);
        match rule.r#type.as_str() {
            "redirect" => handle_redirect(&mut stream, &rule).await?,
            "replace" => handle_replace(&mut stream, &rule, &engine).await?,
            "block" => handle_block(&mut stream, &rule).await?,
            "proxy" => handle_proxy_forward(&mut stream, &rule, method, &headers, &body).await?,
            "forward" => {
                handle_forward_via_proxy(&mut stream, &rule, &full_url, method, &headers, &body)
                    .await?
            }
            _ => {
                warn!("Unknown rule type: {}, skipping", rule.r#type);
                forward_request(&mut stream, &full_url, method, &headers, &body, &config_mgr)
                    .await?;
            }
        }
    } else {
        // No rule matched - transparent forwarding
        forward_request(&mut stream, &full_url, method, &headers, &body, &config_mgr).await?;
    }

    Ok(())
}

/// Extract a header value from raw request text.
fn extract_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    let lower_name = name.to_lowercase();
    for line in request.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_lowercase() == lower_name {
                return Some(value.trim());
            }
        }
    }
    None
}

/// Parse request headers and body from raw request data.
fn parse_request(request_str: &str, raw: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let mut headers = Vec::new();

    for line in request_str.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    // Find body
    let body = if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        raw[pos + 4..].to_vec()
    } else {
        Vec::new()
    };

    (headers, body)
}

/// Send an error response.
async fn send_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason_phrase(status),
        message.len(),
        message
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Send a complete HTTP response.
async fn send_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut response = format!("HTTP/1.1 {} {}\r\n", status, reason_phrase(status));
    for (key, value) in headers {
        response.push_str(&format!("{}: {}\r\n", key, value));
    }
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("Connection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Unknown",
    }
}

// ─── Rule handlers ───────────────────────────────────

/// Handle redirect rule.
async fn handle_redirect(
    stream: &mut TcpStream,
    rule: &Rule,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = rule.status_code.unwrap_or(302);
    let target = rule.target.as_deref().unwrap_or("/");
    let response = format!(
        "HTTP/1.1 {} {}\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        status,
        reason_phrase(status),
        target
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Handle replace rule.
async fn handle_replace(
    stream: &mut TcpStream,
    rule: &Rule,
    engine: &RuleEngine,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = rule.status_code.unwrap_or(200);
    let body = if rule.file.is_some() {
        match engine.read_local_file(rule) {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to read local file: {}", e);
                send_error(stream, 500, "SimpleProxy: failed to read local file").await?;
                return Ok(());
            }
        }
    } else {
        rule.body.as_deref().unwrap_or("").as_bytes().to_vec()
    };

    let content_type = rule
        .content_type
        .as_deref()
        .unwrap_or("text/plain")
        .to_string();

    let headers = vec![
        ("Content-Type".to_string(), content_type),
        ("X-Intercepted-By".to_string(), "SimpleProxy".to_string()),
    ];

    send_response(stream, status, &headers, &body).await?;
    Ok(())
}

/// Handle block rule.
async fn handle_block(
    stream: &mut TcpStream,
    rule: &Rule,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let status = rule.status_code.unwrap_or(403);
    let body = rule
        .body
        .as_deref()
        .unwrap_or("Blocked by SimpleProxy")
        .as_bytes();

    let headers = vec![
        ("Content-Type".to_string(), "text/plain".to_string()),
        ("X-Intercepted-By".to_string(), "SimpleProxy".to_string()),
    ];

    send_response(stream, status, &headers, body).await?;
    Ok(())
}

/// Handle proxy forward rule (forward to a different target URL with optional header injection).
async fn handle_proxy_forward(
    stream: &mut TcpStream,
    rule: &Rule,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_url = rule.target.as_deref().unwrap_or("");
    let parsed: url::Url = target_url.parse()?;

    let host = parsed.host_str().unwrap_or("localhost");
    let port = parsed
        .port()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let path = if parsed.query().is_some() {
        format!("{}?{}", parsed.path(), parsed.query().unwrap())
    } else {
        parsed.path().to_string()
    };

    let addr = format!("{}:{}", host, port);
    let mut target_stream = TcpStream::connect(&addr).await?;

    // Build request with injected headers
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

    // Copy original headers, replacing Host
    for (key, value) in headers {
        if key.to_lowercase() == "host" {
            request.push_str(&format!("Host: {}\r\n", parsed.authority()));
        } else {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
    }

    // Inject custom headers from rule
    if let Some(ref custom_headers) = rule.headers {
        for (key, value) in custom_headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
    }

    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");

    target_stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        target_stream.write_all(body).await?;
    }

    // Relay response
    relay_response(&mut target_stream, stream).await?;
    Ok(())
}

/// Handle forward via upstream proxy rule.
async fn handle_forward_via_proxy(
    stream: &mut TcpStream,
    rule: &Rule,
    full_url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let upstream_url = match &rule.upstream_proxy {
        Some(url) => url.clone(),
        None => {
            error!("forward rule missing upstreamProxy field");
            send_error(
                stream,
                500,
                "SimpleProxy: forward rule missing upstreamProxy",
            )
            .await?;
            return Ok(());
        }
    };

    let proxy_info = parse_proxy_url(&upstream_url)?;

    if proxy_info.protocol == "socks5" {
        let parsed: url::Url = full_url.parse()?;
        let host = parsed.host_str().unwrap_or("localhost");
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

        let mut tunnel = connect_via_upstream(&upstream_url, host, port).await?;
        let path = if parsed.query().is_some() {
            format!("{}?{}", parsed.path(), parsed.query().unwrap())
        } else {
            parsed.path().to_string()
        };

        // Send raw HTTP request through tunnel
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
        for (key, value) in headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
        request.push_str("Connection: close\r\n\r\n");
        tunnel.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            tunnel.write_all(body).await?;
        }

        relay_response(&mut tunnel, stream).await?;
    } else {
        let (status, resp_headers, resp_body) =
            http_proxy_request(&proxy_info, full_url, method, headers, body).await?;

        let h: Vec<(String, String)> = resp_headers;
        send_response(stream, status, &h, &resp_body).await?;
    }

    Ok(())
}

// ─── Transparent forwarding ──────────────────────────

/// Forward a request to the target (optionally through an upstream proxy).
async fn forward_request(
    client_stream: &mut TcpStream,
    full_url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    config_mgr: &ConfigManager,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let upstream_proxy = config_mgr.get().upstream_proxy;

    if let Some(ref upstream_url) = upstream_proxy {
        let proxy_info = parse_proxy_url(upstream_url)?;

        if proxy_info.protocol == "socks5" {
            let parsed: url::Url = full_url.parse()?;
            let host = parsed.host_str().unwrap_or("localhost");
            let port = parsed
                .port()
                .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

            let mut tunnel = connect_via_upstream(upstream_url, host, port).await?;
            let path = if parsed.query().is_some() {
                format!("{}?{}", parsed.path(), parsed.query().unwrap())
            } else {
                parsed.path().to_string()
            };

            let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
            for (key, value) in headers {
                request.push_str(&format!("{}: {}\r\n", key, value));
            }
            request.push_str("Connection: close\r\n\r\n");
            tunnel.write_all(request.as_bytes()).await?;
            if !body.is_empty() {
                tunnel.write_all(body).await?;
            }

            relay_response(&mut tunnel, client_stream).await?;
        } else {
            let (status, resp_headers, resp_body) =
                http_proxy_request(&proxy_info, full_url, method, headers, body).await?;

            send_response(client_stream, status, &resp_headers, &resp_body).await?;
        }
    } else {
        // Direct connection
        let parsed: url::Url = full_url.parse()?;
        let host = parsed.host_str().unwrap_or("localhost");
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
        let path = if parsed.query().is_some() {
            format!("{}?{}", parsed.path(), parsed.query().unwrap())
        } else {
            parsed.path().to_string()
        };

        let addr = format!("{}:{}", host, port);
        let mut target_stream = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to connect to {}: {}", addr, e);
                send_error(client_stream, 502, "SimpleProxy: upstream connection error").await?;
                return Ok(());
            }
        };

        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
        for (key, value) in headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }
        request.push_str("Connection: close\r\n\r\n");
        target_stream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            target_stream.write_all(body).await?;
        }

        relay_response(&mut target_stream, client_stream).await?;
    }

    Ok(())
}

/// Relay raw TCP response from source to destination.
async fn relay_response(
    source: &mut TcpStream,
    dest: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 8192];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dest.write_all(&buf[..n]).await?;
    }
    Ok(())
}

// ─── HTTPS CONNECT tunnel ────────────────────────────

/// Handle HTTPS CONNECT tunneling.
async fn handle_connect(
    mut client_stream: TcpStream,
    target: &str,
    _engine: &RuleEngine,
    config_mgr: &ConfigManager,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (hostname, port) = parse_connect_target(target);
    let upstream_proxy = config_mgr.get().upstream_proxy;

    if let Some(ref upstream_url) = upstream_proxy {
        // Connect through upstream proxy
        match connect_via_upstream(upstream_url, &hostname, port).await {
            Ok(server_stream) => {
                client_stream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: SimpleProxy\r\n\r\n",
                    )
                    .await?;

                // Bidirectional relay
                let (mut client_read, mut client_write) = client_stream.into_split();
                let (mut server_read, mut server_write) = server_stream.into_split();

                let c2s = tokio::io::copy(&mut client_read, &mut server_write);
                let s2c = tokio::io::copy(&mut server_read, &mut client_write);

                let _ = tokio::try_join!(c2s, s2c);
            }
            Err(e) => {
                error!("CONNECT upstream error {}:{} - {}", hostname, port, e);
                client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
            }
        }
    } else {
        // Direct tunnel
        match TcpStream::connect(format!("{}:{}", hostname, port)).await {
            Ok(server_stream) => {
                client_stream
                    .write_all(
                        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: SimpleProxy\r\n\r\n",
                    )
                    .await?;

                let (mut client_read, mut client_write) = client_stream.into_split();
                let (mut server_read, mut server_write) = server_stream.into_split();

                let c2s = tokio::io::copy(&mut client_read, &mut server_write);
                let s2c = tokio::io::copy(&mut server_read, &mut client_write);

                let _ = tokio::try_join!(c2s, s2c);
            }
            Err(e) => {
                error!("CONNECT error {}:{} - {}", hostname, port, e);
                client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
            }
        }
    }

    Ok(())
}

/// Parse CONNECT target "host:port" string.
fn parse_connect_target(target: &str) -> (String, u16) {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str.parse::<u16>().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (target.to_string(), 443)
    }
}
