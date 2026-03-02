//! Web control panel – serves a dashboard UI and JSON API for managing
//! proxy configuration and rules at runtime.

use crate::cert::CertManager;
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
    cert_mgr: Arc<CertManager>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    info!("[Web] Dashboard listening on http://127.0.0.1:{}", port);

    loop {
        let (stream, _) = listener.accept().await?;
        let cfg = Arc::clone(&config_mgr);
        let eng = Arc::clone(&rule_engine);
        let crt = Arc::clone(&cert_mgr);
        tokio::spawn(async move {
            if let Err(e) = handle_web_request(stream, cfg, eng, crt).await {
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
    cert_mgr: Arc<CertManager>,
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

        // ── Certificate API ──
        ("GET", "/api/cert/status") => {
            let json = cert_mgr.cert_status_json();
            send_json(&mut stream, 200, &json).await?;
        }
        ("GET", "/api/cert/download") => {
            let pem = cert_mgr.ca_cert_pem();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-pem-file\r\nContent-Disposition: attachment; filename=\"SimpleProxy-CA.crt\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                pem.len(),
                pem
            );
            stream.write_all(resp.as_bytes()).await?;
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
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--accent2:#818cf8;--danger:#f87171;--success:#4ade80;--warn:#fbbf24;--info:#60a5fa}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6}
.container{max-width:960px;margin:0 auto;padding:24px}
h1{font-size:1.8rem;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:10px}
h1 span{color:var(--accent)}
.header-row{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}
.subtitle{color:var(--muted);font-size:.95rem;margin:0}
.lang-btn{background:var(--card);border:1px solid var(--border);color:var(--muted);padding:4px 12px;border-radius:6px;cursor:pointer;font-size:.82rem;transition:all .15s}
.lang-btn:hover{border-color:var(--accent);color:var(--accent)}
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
.btn-warn{background:var(--warn);color:#0f172a}
.btn-warn:hover{opacity:.85}
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
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100;justify-content:center;align-items:center}
.modal-overlay.open{display:flex}
.modal{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;width:520px;max-height:85vh;overflow-y:auto}
.modal h3{margin-bottom:16px;font-size:1.1rem}
.modal .form-grid{grid-template-columns:1fr 1fr}
.modal .actions{justify-content:flex-end}
select{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem}
textarea{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.9rem;resize:vertical;min-height:60px;font-family:inherit}
.full-span{grid-column:1/-1}
.cert-banner{display:flex;align-items:center;gap:14px;padding:14px 18px;border-radius:10px;margin-bottom:20px;font-size:.9rem}
.cert-ok{background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.25)}
.cert-warn{background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.25)}
.cert-icon{font-size:1.4rem;flex-shrink:0}
.cert-info{flex:1}
.cert-info strong{display:block;margin-bottom:2px}
.cert-info small{color:var(--muted);font-size:.82rem}
.cert-actions{display:flex;gap:8px;flex-shrink:0}
.field-row{transition:all .2s}
.field-hidden{display:none !important}
</style>
</head>
<body>
<div class="container">
<h1>⚡ <span>SimpleProxy</span> Dashboard</h1>
<div class="header-row">
  <p class="subtitle" data-i18n="subtitle"></p>
  <button class="lang-btn" id="langToggle" onclick="toggleLang()"></button>
</div>

<!-- Certificate Status Banner -->
<div class="cert-banner cert-warn" id="certBanner" style="display:none">
  <div class="cert-icon" id="certIcon">⚠️</div>
  <div class="cert-info">
    <strong id="certTitle"></strong>
    <small id="certDetail"></small>
  </div>
  <div class="cert-actions" id="certActions"></div>
</div>

<!-- Config Card -->
<div class="card" id="configCard">
<h2>⚙ <span data-i18n="config_title"></span></h2>
<div class="form-grid">
  <div><label data-i18n="proxy_port"></label><input id="cfgPort" type="number"></div>
  <div><label data-i18n="rules_file"></label><input id="cfgRulesFile" type="text"></div>
  <div><label data-i18n="web_port"></label><input id="cfgWebPort" type="number"></div>
  <div><label data-i18n="upstream_proxy"></label><input id="cfgUpstream" type="text" data-ph="upstream_ph"></div>
  <div class="checkbox-row"><input id="cfgAutoOpen" type="checkbox"><label for="cfgAutoOpen" data-i18n="auto_open"></label></div>
  <div class="checkbox-row"><input id="cfgSysProxy" type="checkbox"><label for="cfgSysProxy" data-i18n="sys_proxy"></label></div>
</div>
<div class="actions"><button class="btn btn-primary" onclick="saveConfig()" data-i18n="save_config"></button></div>
</div>

<!-- Rules Card -->
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
  <h2 style="margin:0">📋 <span data-i18n="rules_title"></span></h2>
  <button class="btn btn-success btn-sm" onclick="openAddRule()" data-i18n="add_rule"></button>
</div>
<table>
<thead><tr><th></th><th data-i18n="th_match"></th><th data-i18n="th_type"></th><th data-i18n="th_comment"></th><th data-i18n="th_actions"></th></tr></thead>
<tbody id="rulesBody"></tbody>
</table>
<div id="noRules" class="no-rules" style="display:none" data-i18n="no_rules"></div>
</div>
</div>

<!-- Rule Edit Modal -->
<div class="modal-overlay" id="ruleModal">
<div class="modal">
<h3 id="modalTitle"></h3>
<div class="form-grid">
  <div class="full-span"><label data-i18n="lbl_comment"></label><input id="ruleComment" type="text" data-ph="ph_comment"></div>
  <div class="full-span"><label data-i18n="lbl_match"></label><input id="ruleMatch" type="text" data-ph="ph_match"></div>
  <div><label data-i18n="lbl_type"></label>
    <select id="ruleType" onchange="onTypeChange()"><option value="redirect">redirect</option><option value="replace">replace</option><option value="block">block</option><option value="proxy">proxy</option><option value="forward">forward</option></select>
  </div>
  <div class="checkbox-row"><input id="ruleIsRegex" type="checkbox"><label for="ruleIsRegex" data-i18n="lbl_is_regex"></label></div>
  <div class="full-span field-row" id="rowTarget"><label data-i18n="lbl_target"></label><input id="ruleTarget" type="text" data-ph="ph_target"></div>
  <div class="field-row" id="rowStatus"><label data-i18n="lbl_status"></label><input id="ruleStatus" type="number" data-ph="ph_status"></div>
  <div class="field-row" id="rowContentType"><label data-i18n="lbl_content_type"></label><input id="ruleContentType" type="text" data-ph="ph_content_type"></div>
  <div class="full-span field-row" id="rowBody"><label data-i18n="lbl_body"></label><textarea id="ruleBody" data-ph="ph_body"></textarea></div>
  <div class="full-span field-row" id="rowFile"><label data-i18n="lbl_file"></label><input id="ruleFile" type="text" data-ph="ph_file"></div>
  <div class="full-span field-row" id="rowUpstream"><label data-i18n="lbl_upstream"></label><input id="ruleUpstream" type="text" data-ph="ph_upstream"></div>
  <div class="full-span field-row" id="rowHeaders"><label data-i18n="lbl_headers"></label><textarea id="ruleHeaders" data-ph="ph_headers" style="min-height:40px"></textarea></div>
  <div class="checkbox-row"><input id="ruleEnabled" type="checkbox" checked><label for="ruleEnabled" data-i18n="lbl_enabled"></label></div>
</div>
<div class="actions">
  <button class="btn" style="background:var(--border);color:var(--text)" onclick="closeModal()" data-i18n="btn_cancel"></button>
  <button class="btn btn-primary" onclick="saveRule()" data-i18n="btn_save"></button>
</div>
</div>
</div>

<div class="toast" id="toast"></div>

<script>
/* ── i18n ── */
const I18N={
en:{
  subtitle:'Manage proxy configuration and URL interception rules',
  config_title:'Configuration',
  proxy_port:'Proxy Port',rules_file:'Rules File',web_port:'Web Dashboard Port',
  upstream_proxy:'Upstream Proxy',upstream_ph:'e.g. http://host:port or socks5://host:port',
  auto_open:'Auto-open browser on start',sys_proxy:'Set system proxy',
  save_config:'Save Configuration',
  rules_title:'Rules',add_rule:'+ Add Rule',
  th_match:'Match',th_type:'Type',th_comment:'Comment',th_actions:'Actions',
  no_rules:'No rules configured',
  btn_edit:'Edit',btn_del:'Del',btn_cancel:'Cancel',btn_save:'Save',
  modal_add:'Add Rule',modal_edit:'Edit Rule',
  lbl_comment:'Comment',ph_comment:'Description of this rule',
  lbl_match:'Match Pattern',ph_match:'URL or regex pattern',
  lbl_type:'Type',lbl_is_regex:'Is Regex',
  lbl_target:'Target URL',ph_target:'https://example.com/new-path',
  lbl_status:'Status Code',ph_status:'e.g. 302',
  lbl_content_type:'Content-Type',ph_content_type:'application/json',
  lbl_body:'Body',ph_body:'Response body content',
  lbl_file:'File',ph_file:'./path/to/local/file',
  lbl_upstream:'Upstream Proxy',ph_upstream:'http://proxy:port or socks5://proxy:port',
  lbl_headers:'Custom Headers (JSON)',ph_headers:'{"X-Custom":"value"}',
  lbl_enabled:'Enabled',
  cert_ok_title:'CA Certificate is trusted',
  cert_ok_detail:'HTTPS interception is fully functional. The SimpleProxy CA is installed in the system trust store.',
  cert_warn_title:'CA Certificate is NOT trusted',
  cert_warn_detail:'HTTPS interception rules will cause browser security warnings. Install the CA certificate to enable seamless interception.',
  cert_download:'Download CA',cert_recheck:'Re-check',
  msg_config_saved:'Configuration saved',msg_rules_saved:'Rules saved',
  msg_save_failed:'Save failed',msg_net_err:'Network error',
  msg_load_config_err:'Failed to load config',msg_load_rules_err:'Failed to load rules',
  msg_match_required:'Match pattern is required',msg_json_invalid:'Headers must be valid JSON',
  lang_label:'中文',
  hint_redirect_proxy:'redirect / proxy',hint_replace:'replace',hint_replace_block:'replace / block',
  hint_forward:'forward',hint_proxy_forward:'proxy / forward'
},
zh:{
  subtitle:'管理代理配置和 URL 拦截规则',
  config_title:'配置',
  proxy_port:'代理端口',rules_file:'规则文件',web_port:'面板端口',
  upstream_proxy:'上游代理',upstream_ph:'例如 http://host:port 或 socks5://host:port',
  auto_open:'启动时自动打开浏览器',sys_proxy:'设置系统代理',
  save_config:'保存配置',
  rules_title:'规则',add_rule:'+ 添加规则',
  th_match:'匹配',th_type:'类型',th_comment:'备注',th_actions:'操作',
  no_rules:'暂无规则',
  btn_edit:'编辑',btn_del:'删除',btn_cancel:'取消',btn_save:'保存',
  modal_add:'添加规则',modal_edit:'编辑规则',
  lbl_comment:'备注',ph_comment:'规则说明',
  lbl_match:'匹配模式',ph_match:'URL 或正则表达式',
  lbl_type:'类型',lbl_is_regex:'正则匹配',
  lbl_target:'目标 URL',ph_target:'https://example.com/new-path',
  lbl_status:'状态码',ph_status:'例如 302',
  lbl_content_type:'Content-Type',ph_content_type:'application/json',
  lbl_body:'响应体',ph_body:'响应内容',
  lbl_file:'文件路径',ph_file:'./path/to/local/file',
  lbl_upstream:'上游代理',ph_upstream:'http://proxy:port 或 socks5://proxy:port',
  lbl_headers:'自定义请求头 (JSON)',ph_headers:'{"X-Custom":"value"}',
  lbl_enabled:'启用',
  cert_ok_title:'CA 证书已受信任',
  cert_ok_detail:'HTTPS 拦截功能正常。SimpleProxy CA 已安装在系统信任存储中。',
  cert_warn_title:'CA 证书未受信任',
  cert_warn_detail:'HTTPS 拦截规则会导致浏览器安全警告。请安装 CA 证书以启用无缝拦截。',
  cert_download:'下载证书',cert_recheck:'重新检查',
  msg_config_saved:'配置已保存',msg_rules_saved:'规则已保存',
  msg_save_failed:'保存失败',msg_net_err:'网络错误',
  msg_load_config_err:'加载配置失败',msg_load_rules_err:'加载规则失败',
  msg_match_required:'匹配模式不能为空',msg_json_invalid:'请求头必须是有效的 JSON',
  lang_label:'EN',
  hint_redirect_proxy:'redirect / proxy',hint_replace:'replace',hint_replace_block:'replace / block',
  hint_forward:'forward',hint_proxy_forward:'proxy / forward'
}
};

let curLang=(navigator.language||'en').startsWith('zh')?'zh':'en';
try{const s=localStorage.getItem('sp_lang');if(s&&I18N[s])curLang=s;}catch(e){}

function T(key){return (I18N[curLang]&&I18N[curLang][key])||I18N.en[key]||key;}

function applyI18n(){
  document.querySelectorAll('[data-i18n]').forEach(el=>{
    el.textContent=T(el.dataset.i18n);
  });
  document.querySelectorAll('[data-ph]').forEach(el=>{
    el.placeholder=T(el.dataset.ph);
  });
  document.getElementById('langToggle').textContent=T('lang_label');
  document.documentElement.lang=curLang==='zh'?'zh-CN':'en';
  /* re-render dynamic content */
  renderRules();
  loadCertStatus();
}

function toggleLang(){
  curLang=curLang==='en'?'zh':'en';
  try{localStorage.setItem('sp_lang',curLang);}catch(e){}
  applyI18n();
}

/* ── Data ── */
let config={};
let rules=[];
let editIndex=-1;

/* ── Field visibility per rule type ── */
const typeFields={
  redirect: ['rowTarget','rowStatus'],
  replace:  ['rowStatus','rowContentType','rowBody','rowFile'],
  block:    ['rowStatus','rowBody'],
  proxy:    ['rowTarget','rowHeaders'],
  forward:  ['rowUpstream','rowHeaders']
};
const allFieldRows=['rowTarget','rowStatus','rowContentType','rowBody','rowFile','rowUpstream','rowHeaders'];

function onTypeChange(){
  const t=document.getElementById('ruleType').value;
  const visible=typeFields[t]||[];
  allFieldRows.forEach(id=>{
    const el=document.getElementById(id);
    if(el) el.classList.toggle('field-hidden',!visible.includes(id));
  });
}

/* ── Certificate status ── */
async function loadCertStatus(){
  try{
    const r=await fetch('/api/cert/status');
    const s=await r.json();
    const banner=document.getElementById('certBanner');
    const icon=document.getElementById('certIcon');
    const title=document.getElementById('certTitle');
    const detail=document.getElementById('certDetail');
    const actions=document.getElementById('certActions');
    banner.style.display='flex';
    if(s.trusted){
      banner.className='cert-banner cert-ok';
      icon.textContent='✅';
      title.textContent=T('cert_ok_title');
      detail.textContent=T('cert_ok_detail');
      actions.innerHTML='<button class="btn btn-sm btn-primary" onclick="downloadCert()">'+T('cert_download')+'</button>';
    }else{
      banner.className='cert-banner cert-warn';
      icon.textContent='⚠️';
      title.textContent=T('cert_warn_title');
      detail.textContent=T('cert_warn_detail');
      actions.innerHTML='<button class="btn btn-sm btn-warn" onclick="downloadCert()">'+T('cert_download')+'</button> <button class="btn btn-sm btn-primary" onclick="refreshCert()">'+T('cert_recheck')+'</button>';
    }
  }catch(e){
    document.getElementById('certBanner').style.display='none';
  }
}
function downloadCert(){window.location.href='/api/cert/download';}
function refreshCert(){loadCertStatus();}

/* ── Config ── */
async function loadConfig(){
  try{const r=await fetch('/api/config');config=await r.json();renderConfig();}catch(e){toast(T('msg_load_config_err'),'err');}
}
async function loadRules(){
  try{const r=await fetch('/api/rules');rules=await r.json();renderRules();}catch(e){toast(T('msg_load_rules_err'),'err');}
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
    if(r.ok){toast(T('msg_config_saved'),'ok');config=c;}else{const e=await r.json();toast(e.error||T('msg_save_failed'),'err');}
  }catch(e){toast(T('msg_net_err'),'err');}
}

/* ── Rules ── */
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
      <button class="btn btn-primary btn-sm" onclick="openEditRule(${i})">${T('btn_edit')}</button>
      <button class="btn btn-danger btn-sm" onclick="deleteRule(${i})">${T('btn_del')}</button>
    </td>
  </tr>`).join('');
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function openAddRule(){
  editIndex=-1;
  document.getElementById('modalTitle').textContent=T('modal_add');
  clearModal();
  document.getElementById('ruleEnabled').checked=true;
  document.getElementById('ruleType').value='redirect';
  onTypeChange();
  document.getElementById('ruleModal').classList.add('open');
}

function openEditRule(i){
  editIndex=i;const r=rules[i];
  document.getElementById('modalTitle').textContent=T('modal_edit');
  document.getElementById('ruleMatch').value=r.match||'';
  document.getElementById('ruleType').value=r.type||'redirect';
  document.getElementById('ruleIsRegex').checked=!!r.isRegex;
  document.getElementById('ruleTarget').value=r.target||'';
  document.getElementById('ruleStatus').value=r.statusCode||'';
  document.getElementById('ruleContentType').value=r.contentType||'';
  document.getElementById('ruleBody').value=r.body||'';
  document.getElementById('ruleFile').value=r.file||'';
  document.getElementById('ruleUpstream').value=r.upstreamProxy||'';
  document.getElementById('ruleHeaders').value=r.headers?JSON.stringify(r.headers):'';
  document.getElementById('ruleComment').value=r.comment||'';
  document.getElementById('ruleEnabled').checked=r.enabled!==false;
  onTypeChange();
  document.getElementById('ruleModal').classList.add('open');
}

function clearModal(){
  ['ruleMatch','ruleTarget','ruleStatus','ruleContentType','ruleBody','ruleFile','ruleUpstream','ruleComment','ruleHeaders'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('ruleIsRegex').checked=false;
  document.getElementById('ruleType').value='redirect';
}

function closeModal(){document.getElementById('ruleModal').classList.remove('open');}

async function saveRule(){
  const r={match:document.getElementById('ruleMatch').value,type:document.getElementById('ruleType').value,enabled:document.getElementById('ruleEnabled').checked};
  if(document.getElementById('ruleIsRegex').checked)r.isRegex=true;
  const t=r.type;
  const visible=typeFields[t]||[];
  if(visible.includes('rowTarget')){const v=document.getElementById('ruleTarget').value;if(v)r.target=v;}
  if(visible.includes('rowStatus')){const v=parseInt(document.getElementById('ruleStatus').value);if(v)r.statusCode=v;}
  if(visible.includes('rowContentType')){const v=document.getElementById('ruleContentType').value;if(v)r.contentType=v;}
  if(visible.includes('rowBody')){const v=document.getElementById('ruleBody').value;if(v)r.body=v;}
  if(visible.includes('rowFile')){const v=document.getElementById('ruleFile').value;if(v)r.file=v;}
  if(visible.includes('rowUpstream')){const v=document.getElementById('ruleUpstream').value;if(v)r.upstreamProxy=v;}
  if(visible.includes('rowHeaders')){
    const v=document.getElementById('ruleHeaders').value.trim();
    if(v){try{r.headers=JSON.parse(v);}catch(e){toast(T('msg_json_invalid'),'err');return;}}
  }
  const comment=document.getElementById('ruleComment').value;if(comment)r.comment=comment;

  if(!r.match){toast(T('msg_match_required'),'err');return;}

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
    if(r.ok){toast(T('msg_rules_saved'),'ok');renderRules();}else{const e=await r.json();toast(e.error||T('msg_save_failed'),'err');}
  }catch(e){toast(T('msg_net_err'),'err');}
}

function toast(msg,type){
  const el=document.getElementById('toast');el.textContent=msg;el.className='toast show '+type;
  setTimeout(()=>el.classList.remove('show'),2500);
}

loadConfig();loadRules();applyI18n();
</script>
</body>
</html>
"##;
