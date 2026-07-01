//! MVP daemon: opens `/dev/diag`, configures maximal capture via
//! `diag-core`, and serves a minimal status/control UI. MIT-licensed,
//! independent of the vendored GPL daemon in `daemon/` — see
//! spec/diag-protocol.md.

mod device;
mod pcap_export;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use diag_core::{archive, envelope, hdlc, legacy_signalling, log, mask, nas, rrc};
use serde::Serialize;
use tokio::sync::Mutex;

use device::DiagDevice;

struct CaptureState {
    archive: Option<archive::ArchiveWriter<std::fs::File>>,
    bytes_captured: u64,
    messages_captured: u64,
    recording: bool,
    /// Running tally since daemon start, independent of recording
    /// start/stop — "what's this device actually emitting," not scoped
    /// to a single recording session.
    log_type_counts: HashMap<u16, u64>,
}

struct AppState {
    capture: Mutex<CaptureState>,
    data_dir: PathBuf,
}

#[derive(Serialize)]
struct Status {
    recording: bool,
    bytes_captured: u64,
    messages_captured: u64,
}

#[derive(Serialize)]
struct CaptureFile {
    name: String,
    size_bytes: u64,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let device_path = args.next().unwrap_or_else(|| "/dev/diag".to_string());
    let data_dir = PathBuf::from(args.next().unwrap_or_else(|| ".".to_string()));
    let port: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(8080);

    std::fs::create_dir_all(&data_dir)?;

    eprintln!("opening {device_path}...");
    let mut dev = DiagDevice::open(&device_path).await?;
    eprintln!("configuring maximal capture mask...");
    configure_maximal_mask(&mut dev).await?;
    eprintln!("mask configured, starting capture loop.");

    let state = Arc::new(AppState {
        capture: Mutex::new(CaptureState {
            archive: None,
            bytes_captured: 0,
            messages_captured: 0,
            recording: false,
            log_type_counts: HashMap::new(),
        }),
        data_dir,
    });

    let capture_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = capture_loop(dev, capture_state).await {
            eprintln!("capture loop exited with error: {e}");
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/start", post(start_recording))
        .route("/api/stop", post(stop_recording))
        .route("/api/captures", get(list_captures))
        .route("/api/captures/{name}", get(download_capture))
        .route("/api/captures/{name}/pcap", get(export_pcap))
        .route("/api/log-types", get(log_types))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    eprintln!("serving on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Retrieves available log-code ranges, then enables every code in every
/// range — maximal capture (spec §6), not a curated allowlist.
async fn configure_maximal_mask(dev: &mut DiagDevice) -> io::Result<()> {
    send_request(dev, &mask::retrieve_id_ranges_request_bytes()).await?;
    let log_mask_sizes = loop {
        if let Some(resp) = next_response(dev, mask::parse_retrieve_id_ranges_response).await? {
            break resp.log_mask_sizes;
        }
    };

    for (log_type, &bitsize) in log_mask_sizes.iter().enumerate() {
        if bitsize == 0 {
            continue;
        }
        let req = mask::set_all_bits_mask_request_bytes(log_type as u32, bitsize);
        send_request(dev, &req).await?;
        loop {
            if next_response(dev, mask::parse_set_mask_response).await?.is_some() {
                break;
            }
        }
        eprintln!("enabled logging for log type {log_type} ({bitsize} codes)");
    }

    Ok(())
}

async fn send_request(dev: &mut DiagDevice, body: &[u8]) -> io::Result<()> {
    let framed = hdlc::encode(body);
    let container = envelope::build_request_container_bytes(&framed, None);
    dev.write_raw(&container).await
}

/// Reads one buffer's worth of data and tries to find a response of the
/// shape `parse` recognizes among its messages. Log messages interleaved
/// during config are routine and silently skipped (`parse` returns `None`
/// for them) — this returns `Ok(None)` for "keep reading," not an error.
async fn next_response<T>(
    dev: &mut DiagDevice,
    parse: impl Fn(&[u8]) -> Option<T>,
) -> io::Result<Option<T>> {
    let raw = dev.read_raw().await?;
    let Ok(parsed) = envelope::parse_container(raw) else {
        return Ok(None);
    };
    for blob in &parsed.messages {
        let Ok(payload) = hdlc::decapsulate_one(blob) else {
            continue;
        };
        if let Some(result) = parse(&payload) {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

async fn capture_loop(mut dev: DiagDevice, state: Arc<AppState>) -> io::Result<()> {
    loop {
        let raw = dev.read_raw().await?;
        let Ok(parsed) = envelope::parse_container(raw) else {
            continue;
        };
        if !parsed.is_user_space() {
            continue;
        }

        let mut cap = state.capture.lock().await;
        for blob in &parsed.messages {
            let Ok(payload) = hdlc::decapsulate_one(blob) else {
                continue;
            };
            // log::parse rejects non-Log (Response) messages too, so this
            // also does what mask::is_log_message used to gate on here.
            let Ok((header, _)) = log::parse(&payload) else {
                continue;
            };
            cap.messages_captured += 1;
            cap.bytes_captured += payload.len() as u64;
            *cap.log_type_counts.entry(header.log_type).or_insert(0) += 1;
            if let Some(archive) = cap.archive.as_mut()
                && let Err(e) = archive.write_raw(&payload)
            {
                eprintln!("archive write failed: {e}");
            }
        }
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn status(State(state): State<Arc<AppState>>) -> Json<Status> {
    let cap = state.capture.lock().await;
    Json(Status {
        recording: cap.recording,
        bytes_captured: cap.bytes_captured,
        messages_captured: cap.messages_captured,
    })
}

#[derive(Serialize)]
struct LogTypeCount {
    /// Hex string (e.g. "0xb0c0") — plain observability data.
    log_type: String,
    count: u64,
    /// Whether *a* decoder exists for this log_type in diag-core — not a
    /// claim about how confident that decoder is. `ip_traffic`'s decoder
    /// exists and is included here despite being explicitly flagged
    /// uncertain in its own module docs; this field answers "is there
    /// code that attempts this," not "should you trust the result."
    decoder_available: bool,
}

fn has_decoder(log_type: u16) -> bool {
    log_type == 0xB0C0 // rrc::decode
        || log_type == rrc::NR_RRC_OTA
        || nas::is_nas_log_type(log_type)
        || log_type == nas::UMTS_NAS_OTA
        || legacy_signalling::is_legacy_signalling_log_type(log_type)
        || log_type == 0x11EB // ip_traffic::decode
}

/// Running distribution of log_types seen since the daemon started,
/// independent of recording start/stop — real observability without
/// requiring a decoder for every type seen (most still don't have one).
async fn log_types(State(state): State<Arc<AppState>>) -> Json<Vec<LogTypeCount>> {
    let cap = state.capture.lock().await;
    let mut counts: Vec<LogTypeCount> = cap
        .log_type_counts
        .iter()
        .map(|(log_type, count)| LogTypeCount {
            log_type: format!("{log_type:#06x}"),
            count: *count,
            decoder_available: has_decoder(*log_type),
        })
        .collect();
    counts.sort_by(|a, b| b.count.cmp(&a.count));
    Json(counts)
}

async fn start_recording(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut cap = state.capture.lock().await;
    if cap.recording {
        return (StatusCode::OK, "already recording");
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = state.data_dir.join(format!("capture-{secs}.raw.gz"));
    match std::fs::File::create(&path) {
        Ok(file) => {
            cap.archive = Some(archive::ArchiveWriter::new(file));
            cap.recording = true;
            cap.bytes_captured = 0;
            cap.messages_captured = 0;
            (StatusCode::OK, "recording started")
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "failed to create archive file"),
    }
}

async fn stop_recording(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut cap = state.capture.lock().await;
    if let Some(archive) = cap.archive.take()
        && let Err(e) = archive.close()
    {
        eprintln!("failed to close archive: {e}");
    }
    cap.recording = false;
    (StatusCode::OK, "recording stopped")
}

async fn list_captures(State(state): State<Arc<AppState>>) -> Json<Vec<CaptureFile>> {
    let mut files = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&state.data_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Ok(metadata) = entry.metadata().await else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            files.push(CaptureFile {
                name: entry.file_name().to_string_lossy().into_owned(),
                size_bytes: metadata.len(),
            });
        }
    }
    // filenames are capture-<unix-seconds>.raw.gz, so lexical order is
    // chronological - newest first is more useful for a status page.
    files.sort_by(|a, b| b.name.cmp(&a.name));
    Json(files)
}

/// Streams a capture file back for download. `name` is matched exactly
/// against an entry in `data_dir` — no path traversal, no arbitrary reads
/// (rejects anything containing a separator or `..` before even touching
/// the filesystem, on top of that).
async fn download_capture(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = state.data_dir.join(&name);
    let data = tokio::fs::read(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let headers = [
        (CONTENT_TYPE, "application/gzip".to_string()),
        (CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
    ];
    Ok((headers, data))
}

/// Converts a capture to pcap on the fly (RRC OTA + plain NAS only —
/// matches the pre-clean-room daemon's export scope, see
/// `pcap_export`'s module docs) and streams it back. Works on a capture
/// that's still being actively recorded to, same as `download_capture`.
async fn export_pcap(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = state.data_dir.join(&name);
    let file = std::fs::File::open(&path).map_err(|_| StatusCode::NOT_FOUND)?;
    let mut reader = archive::ArchiveReader::new(file);
    let raw = reader
        .read_all()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let pcap_bytes = pcap_export::convert(&raw);

    let pcap_name = format!("{name}.pcap");
    let headers = [
        (CONTENT_TYPE, "application/vnd.tcpdump.pcap".to_string()),
        (CONTENT_DISPOSITION, format!("attachment; filename=\"{pcap_name}\"")),
    ];
    Ok((headers, pcap_bytes))
}

const INDEX_HTML: &str = r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>DIAG Capture</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem; }
  .status { font-size: 1.5rem; margin: 1rem 0; font-weight: 600; }
  .recording { color: #c0392b; }
  .stopped { color: #7f8c8d; }
  button { font-size: 1rem; padding: 0.5rem 1.5rem; margin-right: 0.5rem; cursor: pointer; }
  dl { display: grid; grid-template-columns: auto 1fr; gap: 0.25rem 1rem; margin-top: 1.5rem; }
  dt { font-weight: 600; }
  h2 { margin-top: 2rem; font-size: 1.1rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #ddd; font-size: 0.9rem; }
  .empty { color: #7f8c8d; font-size: 0.9rem; }
</style>
</head>
<body>
<h1>DIAG Capture</h1>
<div class="status" id="status">loading...</div>
<button onclick="act('/api/start')">Start</button>
<button onclick="act('/api/stop')">Stop</button>
<dl>
  <dt>Messages captured</dt><dd id="messages">-</dd>
  <dt>Bytes captured</dt><dd id="bytes">-</dd>
</dl>

<h2>Captures</h2>
<table id="captures-table">
  <thead><tr><th>File</th><th>Size</th><th></th></tr></thead>
  <tbody id="captures-body"></tbody>
</table>
<div class="empty" id="captures-empty" style="display:none">No captures yet.</div>

<h2>Log types seen (since daemon start)</h2>
<table id="log-types-table">
  <thead><tr><th>log_type</th><th>Count</th><th>Decoded</th></tr></thead>
  <tbody id="log-types-body"></tbody>
</table>
<div class="empty" id="log-types-empty" style="display:none">Nothing seen yet.</div>

<script>
async function refresh() {
  const r = await fetch('/api/status');
  const s = await r.json();
  const el = document.getElementById('status');
  el.textContent = s.recording ? 'Recording' : 'Stopped';
  el.className = 'status ' + (s.recording ? 'recording' : 'stopped');
  document.getElementById('messages').textContent = s.messages_captured;
  document.getElementById('bytes').textContent = s.bytes_captured;
}
async function refreshCaptures() {
  const r = await fetch('/api/captures');
  const files = await r.json();
  const body = document.getElementById('captures-body');
  const empty = document.getElementById('captures-empty');
  body.innerHTML = '';
  empty.style.display = files.length === 0 ? 'block' : 'none';
  for (const f of files) {
    const tr = document.createElement('tr');
    const kb = (f.size_bytes / 1024).toFixed(1);
    const href = '/api/captures/' + encodeURIComponent(f.name);
    tr.innerHTML = '<td>' + f.name + '</td><td>' + kb + ' KB</td>'
      + '<td><a href="' + href + '" download>Raw</a> &middot; '
      + '<a href="' + href + '/pcap" download>pcap</a></td>';
    body.appendChild(tr);
  }
}
async function refreshLogTypes() {
  const r = await fetch('/api/log-types');
  const types = await r.json();
  const body = document.getElementById('log-types-body');
  const empty = document.getElementById('log-types-empty');
  body.innerHTML = '';
  empty.style.display = types.length === 0 ? 'block' : 'none';
  for (const t of types) {
    const tr = document.createElement('tr');
    const decoded = t.decoder_available ? '&check;' : '&mdash;';
    tr.innerHTML = '<td>' + t.log_type + '</td><td>' + t.count + '</td><td>' + decoded + '</td>';
    body.appendChild(tr);
  }
}
async function act(path) {
  await fetch(path, { method: 'POST' });
  refresh();
  refreshCaptures();
}
refresh();
refreshCaptures();
refreshLogTypes();
setInterval(refresh, 2000);
setInterval(refreshCaptures, 5000);
setInterval(refreshLogTypes, 3000);
</script>
</body>
</html>
"#;
