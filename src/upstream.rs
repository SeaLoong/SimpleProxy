//! Upstream proxy connector - supports HTTP and SOCKS5 upstream proxies.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

/// Parsed proxy URL info.
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    pub protocol: String, // "http" or "socks5"
    pub hostname: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

/// Proxy authentication credentials.
#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// Parse a proxy URL string into a ProxyInfo struct.
/// Supports: http://host:port, http://user:pass@host:port,
///           socks5://host:port, socks5://user:pass@host:port
pub fn parse_proxy_url(
    proxy_url: &str,
) -> Result<ProxyInfo, Box<dyn std::error::Error + Send + Sync>> {
    // Handle socks5:// by temporarily replacing with http:// for URL parsing
    let (protocol, parse_url) = if let Some(stripped) = proxy_url.strip_prefix("socks5://") {
        ("socks5".to_string(), format!("http://{}", stripped))
    } else {
        ("http".to_string(), proxy_url.to_string())
    };

    let url: url::Url = parse_url
        .parse()
        .map_err(|e| format!("Invalid proxy URL '{}': {}", proxy_url, e))?;

    let hostname = url.host_str().unwrap_or("127.0.0.1").to_string();
    let default_port = if protocol == "socks5" { 1080 } else { 8080 };
    let port = url.port().unwrap_or(default_port);

    let auth = if !url.username().is_empty() {
        Some(ProxyAuth {
            username: percent_encoding::percent_decode_str(url.username())
                .decode_utf8_lossy()
                .to_string(),
            password: percent_encoding::percent_decode_str(url.password().unwrap_or(""))
                .decode_utf8_lossy()
                .to_string(),
        })
    } else {
        None
    };

    Ok(ProxyInfo {
        protocol,
        hostname,
        port,
        auth,
    })
}

/// Connect to a target through an upstream proxy (HTTP CONNECT or SOCKS5).
pub async fn connect_via_upstream(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let info = parse_proxy_url(proxy_url)?;
    match info.protocol.as_str() {
        "socks5" => socks5_connect(&info, target_host, target_port).await,
        _ => http_proxy_connect(&info, target_host, target_port).await,
    }
}

/// Connect to a target through an upstream proxy, using a **pre-connected**
/// `TcpStream` to the proxy server.
///
/// This is used by the TUN proxy module where the TCP socket needs special
/// options (e.g., `IP_UNICAST_IF`) to bypass TUN routing before connecting
/// to the proxy server.
pub async fn connect_via_upstream_with_stream(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
    stream: TcpStream,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let info = parse_proxy_url(proxy_url)?;
    match info.protocol.as_str() {
        "socks5" => socks5_handshake(stream, &info, target_host, target_port).await,
        _ => http_connect_handshake(stream, &info, target_host, target_port).await,
    }
}

/// Establish an HTTP CONNECT tunnel through an HTTP proxy.
pub async fn http_proxy_connect(
    proxy_info: &ProxyInfo,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", proxy_info.hostname, proxy_info.port);
    let stream = TcpStream::connect(&addr).await?;
    http_connect_handshake(stream, proxy_info, target_host, target_port).await
}

/// Perform the HTTP CONNECT handshake on an already-connected stream.
async fn http_connect_handshake(
    mut stream: TcpStream,
    proxy_info: &ProxyInfo,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let mut connect_req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
        target_host, target_port, target_host, target_port
    );

    if let Some(ref auth) = proxy_info.auth {
        use base64::Engine;
        let cred = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        connect_req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
    }

    connect_req.push_str("\r\n");

    stream.write_all(connect_req.as_bytes()).await?;

    // Read response
    let mut response = Vec::new();
    let mut buf = [0u8; 1];
    loop {
        stream.read_exact(&mut buf).await?;
        response.push(buf[0]);
        if response.len() >= 4 && &response[response.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if response.len() > 8192 {
            return Err("HTTP CONNECT response too large".into());
        }
    }

    let response_str = String::from_utf8_lossy(&response);
    if !response_str.contains("200") {
        return Err(format!("HTTP CONNECT failed: {}", response_str.trim()).into());
    }

    debug!(
        "HTTP CONNECT tunnel established to {}:{}",
        target_host, target_port
    );
    Ok(stream)
}

/// Send an HTTP request through an HTTP proxy (full URL as path).
pub async fn http_proxy_request(
    proxy_info: &ProxyInfo,
    full_url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", proxy_info.hostname, proxy_info.port);
    let mut stream = TcpStream::connect(&addr).await?;

    // Build request
    let mut request = format!("{} {} HTTP/1.1\r\n", method, full_url);

    for (key, value) in headers {
        // Skip hop-by-hop headers
        let lower = key.to_lowercase();
        if lower == "proxy-connection" || lower == "proxy-authorization" {
            continue;
        }
        request.push_str(&format!("{}: {}\r\n", key, value));
    }

    if let Some(ref auth) = proxy_info.auth {
        use base64::Engine;
        let cred = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", auth.username, auth.password));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
    }

    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }

    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }

    // Read response (simplified)
    let mut response_data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response_data.extend_from_slice(&buf[..n]);
    }

    // Parse status line and headers
    let header_end = response_data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(response_data.len());

    let header_str = String::from_utf8_lossy(&response_data[..header_end]);
    let mut lines = header_str.lines();

    let status_line = lines.next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    let mut resp_headers = Vec::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            resp_headers.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    let body_start = if header_end + 4 <= response_data.len() {
        header_end + 4
    } else {
        response_data.len()
    };
    let resp_body = response_data[body_start..].to_vec();

    Ok((status_code, resp_headers, resp_body))
}

/// Establish a TCP connection through a SOCKS5 proxy.
pub async fn socks5_connect(
    proxy_info: &ProxyInfo,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", proxy_info.hostname, proxy_info.port);
    let stream = TcpStream::connect(&addr).await?;
    socks5_handshake(stream, proxy_info, target_host, target_port).await
}

/// Perform the SOCKS5 handshake on an already-connected stream.
async fn socks5_handshake(
    mut stream: TcpStream,
    proxy_info: &ProxyInfo,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, Box<dyn std::error::Error + Send + Sync>> {
    // Step 1: Send greeting
    let has_auth = proxy_info.auth.is_some();
    if has_auth {
        // Support no-auth (0x00) and username/password (0x02)
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        // Only no-auth (0x00)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    // Step 2: Read server's chosen auth method
    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;

    if auth_resp[0] != 0x05 {
        return Err("SOCKS5: Invalid server response".into());
    }

    match auth_resp[1] {
        0x00 => {
            // No authentication needed
        }
        0x02 => {
            // Username/password authentication
            if let Some(ref auth) = proxy_info.auth {
                let u_bytes = auth.username.as_bytes();
                let p_bytes = auth.password.as_bytes();
                let mut auth_buf = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
                auth_buf.push(0x01); // Sub-negotiation version
                auth_buf.push(u_bytes.len() as u8);
                auth_buf.extend_from_slice(u_bytes);
                auth_buf.push(p_bytes.len() as u8);
                auth_buf.extend_from_slice(p_bytes);
                stream.write_all(&auth_buf).await?;

                let mut auth_result = [0u8; 2];
                stream.read_exact(&mut auth_result).await?;
                if auth_result[1] != 0x00 {
                    return Err("SOCKS5: Authentication failed".into());
                }
            } else {
                return Err("SOCKS5: Server requires authentication but none provided".into());
            }
        }
        method => {
            return Err(format!("SOCKS5: Unsupported auth method 0x{:02x}", method).into());
        }
    }

    // Step 3: Send connect request (DOMAINNAME type)
    let host_bytes = target_host.as_bytes();
    let mut connect_req = Vec::with_capacity(4 + 1 + host_bytes.len() + 2);
    connect_req.push(0x05); // VER
    connect_req.push(0x01); // CMD: CONNECT
    connect_req.push(0x00); // RSV
    connect_req.push(0x03); // ATYP: DOMAINNAME
    connect_req.push(host_bytes.len() as u8);
    connect_req.extend_from_slice(host_bytes);
    connect_req.push((target_port >> 8) as u8);
    connect_req.push((target_port & 0xff) as u8);
    stream.write_all(&connect_req).await?;

    // Step 4: Read connect response
    let mut connect_resp = [0u8; 4];
    stream.read_exact(&mut connect_resp).await?;

    if connect_resp[0] != 0x05 || connect_resp[1] != 0x00 {
        return Err(format!(
            "SOCKS5: Connect failed, error code: 0x{:02x}",
            connect_resp[1]
        )
        .into());
    }

    // Read remaining address bytes based on address type
    match connect_resp[3] {
        0x01 => {
            // IPv4: 4 bytes + 2 port
            let mut addr_buf = [0u8; 6];
            stream.read_exact(&mut addr_buf).await?;
        }
        0x03 => {
            // Domain: 1 byte len + domain + 2 port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize + 2];
            stream.read_exact(&mut domain_buf).await?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 port
            let mut addr_buf = [0u8; 18];
            stream.read_exact(&mut addr_buf).await?;
        }
        _ => {
            return Err("SOCKS5: Unknown address type in response".into());
        }
    }

    debug!(
        "SOCKS5 tunnel established to {}:{}",
        target_host, target_port
    );
    Ok(stream)
}
