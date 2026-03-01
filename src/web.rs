//! Web control panel – serves a dashboard UI and JSON API for managing
//! proxy configuration and rules at runtime.

use crate::config::ConfigManager;
use crate::rule_engine::{Rule, RuleEngine};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info};

/// Start the web dashboard server.
pub async fn start_web_server(
    config_mgr: Arc<ConfigManager>,
    rule_engine: Arc<RuleEngine>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("[Web] Dashboard listening on http://127.0.0.1:{}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = Arc::clone(&config_mgr);
        let eng = Arc::clone(&rule_engine);
        tokio::spawn(async move {
            if let Err(e) = handle_web_request(stream, cfg, eng).await {
                error!("[Web] Request error: {}", e);
            }
        });
    }
}

/// Handle a single HTTP request on the web dashboard.
async fn handle_web_request(
    mut stream: tokio::net::TcpStream,
    config_mgr: Arc<ConfigManager>,
    rule_engine: Arc<RuleEngine>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]).to_string();
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Extract request body
    let body = if let Some(pos) = request.find("\r\n\r\n") {
        &request[pos + 4..]
    } else {
        ""
    };

    match (method, path) {
        // ── Dashboard HTML ──
        ("GET", "/") | ("GET", "/index.html") => {
            send_html(&mut stream, DASHBOARD_HTML).await?;
        }

        // ── Config API ──
        ("GET", "/api/config") => {
            let cfg = config_mgr.get();
            let json = serde_json::to_string_pretty(&cfg)?;
            send_json(&mut stream, 200, &json).await?;
        }
        ("PUT", "/api/config") => match serde_json::from_str(body) {
            Ok(new_cfg) => {
                if let Err(e) = config_mgr.update(new_cfg) {
                    send_json(&mut stream, 500, &format!(r#"{{"error":"{}"}}"#, e)).await?;
                } else {
                    send_json(&mut stream, 200, r#"{"ok":true}"#).await?;
                }
            }
            Err(e) => {
                send_json(&mut stream, 400, &format!(r#"{{"error":"{}"}}"#, e)).await?;
            }
        },

        // ── Rules API ──
        ("GET", "/api/rules") => {
            let rules = rule_engine.get_rules();
            let json = serde_json::to_string_pretty(&rules)?;
            send_json(&mut stream, 200, &json).await?;
        }
        ("PUT", "/api/rules") => {
            let rules: Result<Vec<Rule>, _> = serde_json::from_str(body);
            match rules {
                Ok(new_rules) => {
                    if let Err(e) = rule_engine.set_rules(new_rules) {
                        send_json(&mut stream, 500, &format!(r#"{{"error":"{}"}}"#, e)).await?;
                    } else {
                        send_json(&mut stream, 200, r#"{"ok":true}"#).await?;
                    }
                }
                Err(e) => {
                    send_json(&mut stream, 400, &format!(r#"{{"error":"{}"}}"#, e)).await?;
                }
            }
        }

        // ── 404 ──
        _ => {
            send_json(&mut stream, 404, r#"{"error":"not found"}"#).await?;
        }
    }

    Ok(())
}

async fn send_html(
    stream: &mut tokio::net::TcpStream,
    html: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn send_json(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    json: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, reason, json.len(), json
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

// ─── Embedded dashboard HTML ─────────────────────────

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SimpleProxy Dashboard</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--accent2:#818cf8;--danger:#f87171;--success:#4ade80;--warn:#fbbf24}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.container{max-width:960px;margin:0 auto;padding:24px}
h1{font-size:1.8rem;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:10px}
h1 span{color:var(--accent)}
.subtitle{color:var(--muted);margin-bottom:28px;font-size:.95rem}
h2{font-size:1.15rem;font-weight:600;margin-bottom:14px;color:var(--accent2)}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:20px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px 18px}
label{font-size:.85rem;color:var(--muted);display:block;margin-bottom:4px}
input[type=text],input[type=number]{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem}
input:focus{outline:none;border-color:var(--accent)}
.checkbox-row{display:flex;align-items:center;gap:8px;padding-top:22px}
.checkbox-row input[type=checkbox]{width:18px;height:18px;accent-color:var(--accent)}
.checkbox-row label{margin:0;color:var(--text);font-size:.9rem}
.btn{padding:8px 18px;border:none;border-radius:6px;font-size:.9rem;font-weight:500;cursor:pointer;transition:all .15s}
.btn-primary{background:var(--accent);color:#0f172a}
.btn-primary:hover{opacity:.85}
.btn-danger{background:var(--danger);color:#0f172a}
.btn-danger:hover{opacity:.85}
.btn-success{background:var(--success);color:#0f172a}
.btn-success:hover{opacity:.85}
.btn-sm{padding:5px 12px;font-size:.82rem}
.actions{display:flex;gap:8px;margin-top:14px}
.toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;font-size:.9rem;color:#0f172a;font-weight:500;opacity:0;transition:opacity .3s;z-index:999;pointer-events:none}
.toast.show{opacity:1}
.toast.ok{background:var(--success)}
.toast.err{background:var(--danger)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border);font-size:.8rem;text-transform:uppercase;letter-spacing:.5px}
td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:hover td{background:rgba(56,189,248,.04)}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78rem;font-weight:600;text-transform:uppercase}
.badge-redirect{background:#7c3aed22;color:#a78bfa}
.badge-replace{background:#0891b222;color:#22d3ee}
.badge-block{background:#dc262622;color:var(--danger)}
.badge-proxy{background:#16a34a22;color:var(--success)}
.badge-forward{background:#ca8a0422;color:var(--warn)}
.enabled-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px}
.dot-on{background:var(--success)}
.dot-off{background:var(--danger)}
.match-text{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'Cascadia Code',Consolas,monospace;font-size:.82rem}
.no-rules{text-align:center;color:var(--muted);padding:30px}
/* rule edit modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100;justify-content:center;align-items:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;width:520px;max-height:85vh;overflow-y:auto}
.modal h3{margin-bottom:16px;font-size:1.1rem}
.modal .form-grid{grid-template-columns:1fr 1fr}
.modal .actions{justify-content:flex-end}
select{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem}
textarea{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem;resize:vertical;min-height:60px;font-family:inherit}
.full-span{grid-column:1/-1}
</style>
</head>
<body>
<div class="container">
<h1>⚡ <span>SimpleProxy</span> Dashboard</h1>
<p class="subtitle">Manage proxy configuration and URL interception rules</p>

<!-- Config Card -->
<div class="card" id="configCard">
<h2>⚙ Configuration</h2>
<div class="form-grid">
  <div><label>Proxy Port</label><input id="cfgPort" type="number"></div>
  <div><label>Rules File</label><input id="cfgRulesFile" type="text"></div>
  <div><label>Web Dashboard Port</label><input id="cfgWebPort" type="number"></div>
  <div><label>Upstream Proxy</label><input id="cfgUpstream" type="text" placeholder="e.g. http://host:port or socks5://host:port"></div>
  <div class="checkbox-row"><input id="cfgAutoOpen" type="checkbox"><label for="cfgAutoOpen">Auto-open browser on start</label></div>
  <div class="checkbox-row"><input id="cfgSysProxy" type="checkbox"><label for="cfgSysProxy">Set system proxy</label></div>
</div>
<div class="actions"><button class="btn btn-primary" onclick="saveConfig()">Save Configuration</button></div>
</div>

<!-- Rules Card -->
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
  <h2 style="margin:0">📋 Rules</h2>
  <button class="btn btn-success btn-sm" onclick="openAddRule()">+ Add Rule</button>
</div>
<table>
<thead><tr><th></th><th>Match</th><th>Type</th><th>Comment</th><th>Actions</th></tr></thead>
<tbody id="rulesBody"></tbody>
</table>
<div id="noRules" class="no-rules" style="display:none">No rules configured</div>
</div>
</div>

<!-- Rule Edit Modal -->
<div class="modal-overlay" id="ruleModal">
<div class="modal">
<h3 id="modalTitle">Add Rule</h3>
<div class="form-grid">
  <div class="full-span"><label>Match Pattern</label><input id="ruleMatch" type="text" placeholder="URL or regex pattern"></div>
  <div><label>Type</label>
    <select id="ruleType"><option value="redirect">redirect</option><option value="replace">replace</option><option value="block">block</option><option value="proxy">proxy</option><option value="forward">forward</option></select>
  </div>
  <div class="checkbox-row"><input id="ruleIsRegex" type="checkbox"><label for="ruleIsRegex">Is Regex</label></div>
  <div class="full-span"><label>Target URL</label><input id="ruleTarget" type="text" placeholder="(for redirect / proxy)"></div>
  <div><label>Status Code</label><input id="ruleStatus" type="number" placeholder="e.g. 302"></div>
  <div><label>Content-Type</label><input id="ruleContentType" type="text" placeholder="(for replace)"></div>
  <div class="full-span"><label>Body</label><textarea id="ruleBody" placeholder="Response body (for replace / block)"></textarea></div>
  <div class="full-span"><label>File</label><input id="ruleFile" type="text" placeholder="Local file path (for replace)"></div>
  <div class="full-span"><label>Upstream Proxy</label><input id="ruleUpstream" type="text" placeholder="(for forward type)"></div>
  <div class="full-span"><label>Comment</label><input id="ruleComment" type="text"></div>
  <div class="checkbox-row"><input id="ruleEnabled" type="checkbox" checked><label for="ruleEnabled">Enabled</label></div>
</div>
<div class="actions">
  <button class="btn" style="background:var(--border);color:var(--text)" onclick="closeModal()">Cancel</button>
  <button class="btn btn-primary" onclick="saveRule()">Save</button>
</div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
let config={};
let rules=[];
let editIndex=-1; // -1 = add, >=0 = edit

async function loadConfig(){
  try{const r=await fetch('/api/config');config=await r.json();renderConfig();}catch(e){toast('Failed to load config','err');}
}
async function loadRules(){
  try{const r=await fetch('/api/rules');rules=await r.json();renderRules();}catch(e){toast('Failed to load rules','err');}
}

function renderConfig(){
  document.getElementById('cfgPort').value=config.port||8888;
  document.getElementById('cfgRulesFile').value=config.rulesFile||'rules.json';
  document.getElementById('cfgWebPort').value=config.webPort||9000;
  document.getElementById('cfgUpstream').value=config.upstreamProxy||'';
  document.getElementById('cfgAutoOpen').checked=!!config.autoOpenBrowser;
  document.getElementById('cfgSysProxy').checked=!!config.systemProxy;
}

async function saveConfig(){
  const c={
    port:parseInt(document.getElementById('cfgPort').value)||8888,
    rulesFile:document.getElementById('cfgRulesFile').value||'rules.json',
    webPort:parseInt(document.getElementById('cfgWebPort').value)||9000,
    upstreamProxy:document.getElementById('cfgUpstream').value||null,
    autoOpenBrowser:document.getElementById('cfgAutoOpen').checked,
    systemProxy:document.getElementById('cfgSysProxy').checked
  };
  try{
    const r=await fetch('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(c)});
    if(r.ok){toast('Configuration saved','ok');config=c;}else{const e=await r.json();toast(e.error||'Save failed','err');}
  }catch(e){toast('Network error','err');}
}

function badgeClass(t){return 'badge badge-'+(t||'proxy');}

function renderRules(){
  const tbody=document.getElementById('rulesBody');
  const noRules=document.getElementById('noRules');
  if(!rules.length){tbody.innerHTML='';noRules.style.display='';return;}
  noRules.style.display='none';
  tbody.innerHTML=rules.map((r,i)=>`<tr>
    <td><span class="enabled-dot ${r.enabled!==false?'dot-on':'dot-off'}"></span></td>
    <td class="match-text" title="${esc(r.match)}">${esc(r.match)}</td>
    <td><span class="${badgeClass(r.type)}">${esc(r.type)}</span></td>
    <td style="color:var(--muted)">${esc(r.comment||'')}</td>
    <td>
      <button class="btn btn-primary btn-sm" onclick="openEditRule(${i})">Edit</button>
      <button class="btn btn-danger btn-sm" onclick="deleteRule(${i})">Del</button>
    </td>
  </tr>`).join('');
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function openAddRule(){editIndex=-1;document.getElementById('modalTitle').textContent='Add Rule';clearModal();document.getElementById('ruleEnabled').checked=true;document.getElementById('ruleModal').classList.add('open');}

function openEditRule(i){
  editIndex=i;const r=rules[i];
  document.getElementById('modalTitle').textContent='Edit Rule';
  document.getElementById('ruleMatch').value=r.match||'';
  document.getElementById('ruleType').value=r.type||'redirect';
  document.getElementById('ruleIsRegex').checked=!!r.isRegex;
  document.getElementById('ruleTarget').value=r.target||'';
  document.getElementById('ruleStatus').value=r.statusCode||'';
  document.getElementById('ruleContentType').value=r.contentType||'';
  document.getElementById('ruleBody').value=r.body||'';
  document.getElementById('ruleFile').value=r.file||'';
  document.getElementById('ruleUpstream').value=r.upstreamProxy||'';
  document.getElementById('ruleComment').value=r.comment||'';
  document.getElementById('ruleEnabled').checked=r.enabled!==false;
  document.getElementById('ruleModal').classList.add('open');
}

function clearModal(){
  ['ruleMatch','ruleTarget','ruleStatus','ruleContentType','ruleBody','ruleFile','ruleUpstream','ruleComment'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('ruleIsRegex').checked=false;
  document.getElementById('ruleType').value='redirect';
}

function closeModal(){document.getElementById('ruleModal').classList.remove('open');}

async function saveRule(){
  const r={match:document.getElementById('ruleMatch').value,type:document.getElementById('ruleType').value,enabled:document.getElementById('ruleEnabled').checked};
  if(document.getElementById('ruleIsRegex').checked)r.isRegex=true;
  const target=document.getElementById('ruleTarget').value;if(target)r.target=target;
  const sc=parseInt(document.getElementById('ruleStatus').value);if(sc)r.statusCode=sc;
  const ct=document.getElementById('ruleContentType').value;if(ct)r.contentType=ct;
  const body=document.getElementById('ruleBody').value;if(body)r.body=body;
  const file=document.getElementById('ruleFile').value;if(file)r.file=file;
  const up=document.getElementById('ruleUpstream').value;if(up)r.upstreamProxy=up;
  const comment=document.getElementById('ruleComment').value;if(comment)r.comment=comment;

  if(!r.match){toast('Match pattern is required','err');return;}

  if(editIndex>=0)rules[editIndex]=r;else rules.push(r);
  await pushRules();
  closeModal();
}

async function deleteRule(i){
  rules.splice(i,1);
  await pushRules();
}

async function pushRules(){
  try{
    const r=await fetch('/api/rules',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(rules)});
    if(r.ok){toast('Rules saved','ok');renderRules();}else{const e=await r.json();toast(e.error||'Save failed','err');}
  }catch(e){toast('Network error','err');}
}

function toast(msg,type){
  const el=document.getElementById('toast');el.textContent=msg;el.className='toast show '+type;
  setTimeout(()=>el.classList.remove('show'),2500);
}

loadConfig();loadRules();
</script>
</body>
</html>
"##;
