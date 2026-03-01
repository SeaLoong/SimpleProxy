//! Integration tests for SimpleProxy
//!
//! Tests the proxy server's rule matching and request handling:
//! - Redirect rules
//! - Content replace rules
//! - Block rules
//! - Transparent forwarding (via upstream proxy)
//! - Forward rules (via specified upstream proxy)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

const PROXY_PORT: u16 = 18888;
const UPSTREAM_PROXY_PORT: u16 = 18889;
const TEST_SERVER_PORT: u16 = 19999;

/// Send an HTTP request through the proxy
fn http_request_via_proxy(
    url: &str,
    proxy_port: u16,
) -> Result<(u16, std::collections::HashMap<String, String>, String), String> {
    let parsed: url::Url = url.parse().map_err(|e: url::ParseError| e.to_string())?;
    let host = parsed.host_str().unwrap_or("127.0.0.1");

    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", proxy_port)).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url, host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Parse status code
    let status_code: u16 = response_str
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Parse headers
    let mut headers = std::collections::HashMap::new();
    let mut in_headers = false;
    let mut body_start = 0;
    for (i, line) in response_str.lines().enumerate() {
        if i == 0 {
            in_headers = true;
            continue;
        }
        if in_headers {
            if line.is_empty() || line == "\r" {
                // Find actual byte position of body
                if let Some(pos) = response_str.find("\r\n\r\n") {
                    body_start = pos + 4;
                }
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(
                    key.trim().to_lowercase().to_string(),
                    value.trim().to_string(),
                );
            }
        }
    }

    let body = if body_start < response_str.len() {
        response_str[body_start..].to_string()
    } else {
        String::new()
    };

    Ok((status_code, headers, body))
}

/// Start a simple test HTTP server
fn start_test_server() -> TcpListener {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", TEST_SERVER_PORT)).unwrap();
    listener
        .set_nonblocking(false)
        .expect("Cannot set blocking");

    let listener_clone = listener.try_clone().unwrap();

    std::thread::spawn(move || {
        for stream in listener_clone.incoming() {
            match stream {
                Ok(mut stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);

                    let path = request
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/");

                    let (status, content_type, body) = match path {
                        "/new-page" => ("200 OK", "text/html", "Redirected!"),
                        "/api/data" => ("200 OK", "application/json", r#"{"original": true}"#),
                        "/forward-test" => ("200 OK", "text/plain", "forward-ok"),
                        _ => ("200 OK", "text/plain", "OK"),
                    };

                    let response = format!(
                        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        content_type,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                }
                Err(_) => break,
            }
        }
    });

    listener
}

/// Start a simple upstream proxy server
fn start_upstream_proxy() -> (TcpListener, Arc<AtomicU32>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", UPSTREAM_PROXY_PORT)).unwrap();
    let request_count = Arc::new(AtomicU32::new(0));
    let count_clone = Arc::clone(&request_count);

    let listener_clone = listener.try_clone().unwrap();

    std::thread::spawn(move || {
        for stream in listener_clone.incoming() {
            match stream {
                Ok(mut client_stream) => {
                    count_clone.fetch_add(1, Ordering::SeqCst);
                    client_stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();

                    let mut buf = [0u8; 4096];
                    let n = client_stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);

                    // Extract the target URL from the request line
                    let url = request
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("");

                    if let Ok(parsed) = url::Url::parse(url) {
                        let host = parsed.host_str().unwrap_or("127.0.0.1");
                        let port = parsed.port().unwrap_or(80);
                        let path = parsed.path();

                        // Forward to actual target
                        if let Ok(mut target_stream) =
                            TcpStream::connect(format!("{}:{}", host, port))
                        {
                            target_stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let req = format!(
                                "GET {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
                                path, host, port
                            );
                            let _ = target_stream.write_all(req.as_bytes());

                            let mut resp_buf = Vec::new();
                            let _ = target_stream.read_to_end(&mut resp_buf);

                            let resp_str = String::from_utf8_lossy(&resp_buf);

                            // Inject X-Upstream-Proxy header
                            if let Some(header_end) = resp_str.find("\r\n\r\n") {
                                let headers_part = &resp_str[..header_end];
                                let body_part = &resp_buf[header_end + 4..];

                                let new_resp =
                                    format!("{}\r\nX-Upstream-Proxy: true\r\n\r\n", headers_part);
                                let _ = client_stream.write_all(new_resp.as_bytes());
                                let _ = client_stream.write_all(body_part);
                            } else {
                                let _ = client_stream.write_all(&resp_buf);
                            }
                        } else {
                            let error_resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 21\r\n\r\nupstream proxy error!";
                            let _ = client_stream.write_all(error_resp.as_bytes());
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    (listener, request_count)
}

/// Write test rules to a temporary file (pure array format)
fn write_test_rules(path: &PathBuf) {
    let rules = serde_json::json!([
        {
            "comment": "Redirect test",
            "match": format!("http://127.0.0.1:{}/old-page", TEST_SERVER_PORT),
            "type": "redirect",
            "target": format!("http://127.0.0.1:{}/new-page", TEST_SERVER_PORT),
            "statusCode": 302,
            "enabled": true
        },
        {
            "comment": "Replace test",
            "match": format!("http://127.0.0.1:{}/api/data", TEST_SERVER_PORT),
            "type": "replace",
            "contentType": "application/json",
            "body": "{\"intercepted\": true}",
            "statusCode": 200,
            "enabled": true
        },
        {
            "comment": "Block test",
            "match": format!("http://127.0.0.1:{}/blocked", TEST_SERVER_PORT),
            "type": "block",
            "statusCode": 403,
            "body": "Blocked!",
            "enabled": true
        },
        {
            "comment": "Forward test",
            "match": format!("http://127.0.0.1:{}/forward-test", TEST_SERVER_PORT),
            "type": "forward",
            "upstreamProxy": format!("http://127.0.0.1:{}", UPSTREAM_PROXY_PORT),
            "enabled": true
        }
    ]);

    std::fs::write(path, serde_json::to_string_pretty(&rules).unwrap()).unwrap();
}

/// Write test config file
fn write_test_config(path: &Path, rules_path: &Path) {
    let config = serde_json::json!({
        "port": PROXY_PORT,
        "rulesFile": rules_path.to_string_lossy(),
        "webPort": 19876,
        "autoOpenBrowser": false,
        "systemProxy": false,
        "upstreamProxy": format!("http://127.0.0.1:{}", UPSTREAM_PROXY_PORT)
    });
    std::fs::write(path, serde_json::to_string_pretty(&config).unwrap()).unwrap();
}

/// Start the proxy server as a child process
fn start_proxy_server(config_path: &Path) -> std::process::Child {
    let exe = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("simple-proxy.exe");

    // Fallback: try the debug build path
    let exe = if exe.exists() {
        exe
    } else {
        // Try looking in target/debug
        PathBuf::from(env!("CARGO_BIN_EXE_simple-proxy"))
    };

    std::process::Command::new(exe)
        .args(["--config", &config_path.to_string_lossy()])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start proxy server")
}

#[test]
fn test_proxy_rules() {
    // Prepare test files
    let test_dir = std::env::temp_dir().join("simple-proxy-test");
    let _ = std::fs::create_dir_all(&test_dir);
    let rules_path = test_dir.join("test_rules.json");
    let config_path = test_dir.join("test_config.json");
    write_test_rules(&rules_path);
    write_test_config(&config_path, &rules_path);

    // Start servers
    let _test_server = start_test_server();
    let (_upstream_server, _upstream_count) = start_upstream_proxy();

    // Start proxy
    let mut proxy = start_proxy_server(&config_path);
    std::thread::sleep(Duration::from_secs(2));

    let mut passed = 0;
    let mut failed = 0;

    macro_rules! assert_test {
        ($name:expr, $condition:expr) => {
            if $condition {
                println!("  ✓ {}", $name);
                passed += 1;
            } else {
                eprintln!("  ✗ {}", $name);
                failed += 1;
            }
        };
    }

    // 1) Redirect test
    println!("【Redirect Test】");
    match http_request_via_proxy(
        &format!("http://127.0.0.1:{}/old-page", TEST_SERVER_PORT),
        PROXY_PORT,
    ) {
        Ok((status, headers, _body)) => {
            assert_test!("Status should be 302", status == 302);
            assert_test!(
                "Location should point to /new-page",
                headers
                    .get("location")
                    .map(|l| l.contains("/new-page"))
                    .unwrap_or(false)
            );
        }
        Err(e) => {
            eprintln!("  ✗ Redirect test failed: {}", e);
            failed += 2;
        }
    }

    // 2) Replace test
    println!("【Content Replace Test】");
    match http_request_via_proxy(
        &format!("http://127.0.0.1:{}/api/data", TEST_SERVER_PORT),
        PROXY_PORT,
    ) {
        Ok((status, _headers, body)) => {
            assert_test!("Status should be 200", status == 200);
            assert_test!(
                "Body should contain intercepted content",
                body.contains("intercepted")
            );
        }
        Err(e) => {
            eprintln!("  ✗ Replace test failed: {}", e);
            failed += 2;
        }
    }

    // 3) Block test
    println!("【Block Test】");
    match http_request_via_proxy(
        &format!("http://127.0.0.1:{}/blocked", TEST_SERVER_PORT),
        PROXY_PORT,
    ) {
        Ok((status, _headers, body)) => {
            assert_test!("Status should be 403", status == 403);
            assert_test!("Body should contain 'Blocked'", body.contains("Blocked"));
        }
        Err(e) => {
            eprintln!("  ✗ Block test failed: {}", e);
            failed += 2;
        }
    }

    // 4) Transparent forwarding (via upstream proxy)
    println!("【Transparent Forward (via upstream) Test】");
    match http_request_via_proxy(
        &format!("http://127.0.0.1:{}/new-page", TEST_SERVER_PORT),
        PROXY_PORT,
    ) {
        Ok((status, headers, body)) => {
            assert_test!("Status should be 200", status == 200);
            assert_test!(
                "Body should come from upstream",
                body.contains("Redirected")
            );
            assert_test!(
                "Should have X-Upstream-Proxy header",
                headers
                    .get("x-upstream-proxy")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            );
        }
        Err(e) => {
            eprintln!("  ✗ Transparent forward test failed: {}", e);
            failed += 3;
        }
    }

    // 5) Forward rule test
    println!("【Forward Rule Test】");
    match http_request_via_proxy(
        &format!("http://127.0.0.1:{}/forward-test", TEST_SERVER_PORT),
        PROXY_PORT,
    ) {
        Ok((status, headers, body)) => {
            assert_test!("Status should be 200", status == 200);
            assert_test!(
                "Body should contain forward-ok",
                body.contains("forward-ok")
            );
            assert_test!(
                "Should have X-Upstream-Proxy header",
                headers
                    .get("x-upstream-proxy")
                    .map(|v| v == "true")
                    .unwrap_or(false)
            );
        }
        Err(e) => {
            eprintln!("  ✗ Forward rule test failed: {}", e);
            failed += 3;
        }
    }

    // Cleanup
    let _ = proxy.kill();
    let _ = proxy.wait();
    let _ = std::fs::remove_file(&rules_path);
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_dir(&test_dir);

    println!();
    println!("========================================");
    println!("  Passed: {}  Failed: {}", passed, failed);
    println!("========================================");

    assert!(failed == 0, "{} tests failed", failed);
}

#[test]
fn test_rule_engine_matching() {
    let test_dir = std::env::temp_dir().join("simple-proxy-rule-test");
    let _ = std::fs::create_dir_all(&test_dir);
    let rules_path = test_dir.join("rules.json");

    let rules = serde_json::json!([
        {
            "match": "http://example.com/exact",
            "type": "block",
            "enabled": true
        },
        {
            "match": "^https?://regex\\.example\\.com/.*",
            "isRegex": true,
            "type": "redirect",
            "target": "http://other.com",
            "enabled": true
        },
        {
            "match": "http://disabled.com",
            "type": "block",
            "enabled": false
        }
    ]);

    std::fs::write(&rules_path, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

    let engine = simple_proxy::rule_engine::RuleEngine::new(&rules_path).unwrap();

    // Exact match
    let result = engine.match_url("http://example.com/exact");
    assert!(result.is_some(), "Should match exact URL");
    assert_eq!(result.unwrap().r#type, "block");

    // Regex match
    let result = engine.match_url("http://regex.example.com/some/path");
    assert!(result.is_some(), "Should match regex URL");
    assert_eq!(result.unwrap().r#type, "redirect");

    // No match
    let result = engine.match_url("http://nomatch.com");
    assert!(result.is_none(), "Should not match unknown URL");

    // Disabled rule should not match
    let result = engine.match_url("http://disabled.com");
    assert!(result.is_none(), "Disabled rule should not match");

    // Cleanup
    let _ = std::fs::remove_file(&rules_path);
    let _ = std::fs::remove_dir(&test_dir);
}
