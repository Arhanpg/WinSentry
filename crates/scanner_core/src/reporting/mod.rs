//! Standalone Interactive Reporting and Data Exporters
//!
//! Generates:
//! - Standalone self-contained D3.js interactive squarified treemaps (HTML)
//! - Machine-readable JSON telemetry exports
//! - Structured CSV analytics spreadsheets

use crate::models::{DuplicateGroup, ScannedFile, ScanSummary};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Node structure for D3.js hierarchical treemap visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreemapNode {
    pub name: String,
    pub path: String,
    pub logical_size: u64,
    pub physical_size: u64,
    pub tier: String,
    pub category: String,
    pub has_security_findings: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreemapNode>,
}

/// Builds a hierarchical directory tree for D3 treemap squarify layout
pub fn build_treemap_hierarchy(files: &[ScannedFile]) -> TreemapNode {
    let mut root = TreemapNode {
        name: "Root".to_string(),
        path: String::new(),
        logical_size: 0,
        physical_size: 0,
        tier: "Active".to_string(),
        category: "System Root".to_string(),
        has_security_findings: false,
        children: Vec::new(),
    };

    // Group files by directory segments
    for file in files {
        let display = &file.display_path;
        let parts: Vec<&str> = display.split(&['\\', '/'][..]).filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            continue;
        }

        let mut current = &mut root;
        current.physical_size += file.physical_size;
        current.logical_size += file.logical_size;

        for (i, &part) in parts.iter().enumerate() {
            let is_leaf = i == parts.len() - 1;
            if is_leaf {
                current.children.push(TreemapNode {
                    name: part.to_string(),
                    path: file.display_path.clone(),
                    logical_size: file.logical_size,
                    physical_size: file.physical_size,
                    tier: file.clean_tier.label().to_string(),
                    category: file.clean_category.clone().unwrap_or_else(|| "Standard File".to_string()),
                    has_security_findings: !file.security_findings.is_empty(),
                    children: Vec::new(),
                });
            } else {
                let pos = current.children.iter().position(|c| c.name == part);
                let next_idx = match pos {
                    Some(idx) => idx,
                    None => {
                        let new_node = TreemapNode {
                            name: part.to_string(),
                            path: parts[..=i].join(r"\"),
                            logical_size: 0,
                            physical_size: 0,
                            tier: "Active".to_string(),
                            category: "Directory".to_string(),
                            has_security_findings: false,
                            children: Vec::new(),
                        };
                        current.children.push(new_node);
                        current.children.len() - 1
                    }
                };
                current.children[next_idx].physical_size += file.physical_size;
                current.children[next_idx].logical_size += file.logical_size;
                if !file.security_findings.is_empty() {
                    current.children[next_idx].has_security_findings = true;
                }
                current = &mut current.children[next_idx];
            }
        }
    }

    root
}

/// Generates a standalone, self-contained interactive D3.js HTML report
pub fn export_html_report<P: AsRef<Path>>(
    report_path: P,
    summary: &ScanSummary,
    files: &[ScannedFile],
    _duplicates: &[DuplicateGroup],
) -> std::io::Result<()> {
    let tree = build_treemap_hierarchy(files);
    let tree_json = serde_json::to_string(&tree).unwrap_or_else(|_| "{}".to_string());
    let summary_json = serde_json::to_string(summary).unwrap_or_else(|_| "{}".to_string());

    let html_content = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WinSentry - Storage Reclamation & Security Audit Report</title>
<style>
:root {{
  --bg-primary: #0f172a;
  --bg-secondary: #1e293b;
  --card-bg: #1e293b;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --accent-safe: #22c55e;
  --accent-review: #f59e0b;
  --accent-security: #ef4444;
  --accent-active: #3b82f6;
  --border: #334155;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
body {{ background: var(--bg-primary); color: var(--text-main); padding: 24px; }}
header {{ margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }}
h1 {{ font-size: 24px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 8px; }}
.badge {{ font-size: 12px; padding: 4px 8px; border-radius: 4px; background: #0369a1; color: white; }}
.stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.stat-title {{ font-size: 13px; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
.stat-val {{ font-size: 24px; font-weight: bold; }}
.val-safe {{ color: var(--accent-safe); }}
.val-review {{ color: var(--accent-review); }}
.val-security {{ color: var(--accent-security); }}
.val-active {{ color: #38bdf8; }}
.section-title {{ font-size: 18px; margin-bottom: 12px; font-weight: 600; }}
.legend {{ display: flex; gap: 16px; margin-bottom: 12px; align-items: center; font-size: 13px; }}
.legend-item {{ display: flex; align-items: center; gap: 6px; }}
.legend-color {{ width: 14px; height: 14px; border-radius: 3px; }}
#treemap-container {{ width: 100%; height: 580px; background: #0b1120; border: 1px solid var(--border); border-radius: 8px; position: relative; overflow: hidden; }}
.node {{ position: absolute; box-sizing: border-box; border: 1px solid rgba(0,0,0,0.3); font-size: 11px; padding: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; cursor: pointer; transition: opacity 0.15s; }}
.node:hover {{ opacity: 0.85; outline: 2px solid white; z-index: 10; }}
.node-label {{ font-weight: 600; pointer-events: none; }}
.node-size {{ font-size: 10px; opacity: 0.8; pointer-events: none; }}
#breadcrumbs {{ margin-bottom: 12px; font-size: 14px; color: var(--text-muted); }}
#breadcrumbs span {{ cursor: pointer; color: #38bdf8; text-decoration: underline; }}
#file-table-container {{ margin-top: 32px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }}
th, td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); }}
th {{ color: var(--text-muted); text-transform: uppercase; font-size: 11px; }}
tr:hover td {{ background: rgba(255,255,255,0.03); }}
.tag {{ display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
.tag-safe {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; }}
.tag-review {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
.tag-security {{ background: rgba(239, 68, 68, 0.2); color: #f87171; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>WinSentry Engine <span class="badge">v0.1.0</span></h1>
    <p style="color: var(--text-muted); font-size: 13px; margin-top: 4px;">High-Throughput Storage Reclamation & Endpoint Security Audit Report</p>
  </div>
  <div style="font-size: 13px; color: var(--text-muted);">
    Generated: Standalone Offline D3 Treemap
  </div>
</header>

<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-title">Files Scanned</div>
    <div class="stat-val" id="stat-files">{files_count}</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Physical Space (NTFS)</div>
    <div class="stat-val val-active" id="stat-physical">{physical_gb:.2} GB</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">[SAFE] Reclaimable</div>
    <div class="stat-val val-safe" id="stat-safe">{safe_mb:.1} MB</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">[REVIEW] Space</div>
    <div class="stat-val val-review" id="stat-review">{review_mb:.1} MB</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Duplicates Space</div>
    <div class="stat-val val-active" id="stat-dup">{dup_mb:.1} MB</div>
  </div>
  <div class="stat-card">
    <div class="stat-title">Security Alerts</div>
    <div class="stat-val val-security" id="stat-sec">{security_count}</div>
  </div>
</div>

<div class="legend">
  <span style="font-weight: 600;">Reclamation Tiers:</span>
  <div class="legend-item"><div class="legend-color" style="background: var(--accent-safe);"></div> [SAFE] Deterministic Purge</div>
  <div class="legend-item"><div class="legend-color" style="background: var(--accent-review);"></div> [REVIEW] Contextual Audit</div>
  <div class="legend-item"><div class="legend-color" style="background: var(--accent-security);"></div> [SECURITY ALERT] Flaws & Malware</div>
  <div class="legend-item"><div class="legend-color" style="background: var(--accent-active);"></div> Active Workspace Files</div>
</div>

<div id="breadcrumbs">Path: <span onclick="renderTree(dataTree)">Root</span></div>
<div id="treemap-container"></div>

<div id="file-table-container">
  <div class="section-title">Critical Security & High-Priority Findings</div>
  <table id="findings-table">
    <thead>
      <tr>
        <th>File Path</th>
        <th>Physical Size</th>
        <th>Tier</th>
        <th>Category / Finding</th>
      </tr>
    </thead>
    <tbody id="findings-tbody"></tbody>
  </table>
</div>

<script>
const dataTree = {tree_json};
const summaryData = {summary_json};

function formatBytes(bytes) {{
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}}

// Lightweight treemap layout renderer (squarified approximation)
function renderTree(node) {{
  const container = document.getElementById('treemap-container');
  container.innerHTML = '';
  const width = container.clientWidth || 1000;
  const height = container.clientHeight || 580;

  const children = node.children && node.children.length > 0 ? node.children : [node];
  const totalWeight = children.reduce((acc, c) => acc + (c.physical_size || 1), 0);

  let currentX = 0;
  children.forEach(child => {{
    const weight = (child.physical_size || 1) / totalWeight;
    const boxWidth = Math.max(2, weight * width);

    const div = document.createElement('div');
    div.className = 'node';
    div.style.left = currentX + 'px';
    div.style.top = '0px';
    div.style.width = Math.min(boxWidth - 2, width - currentX) + 'px';
    div.style.height = (height - 4) + 'px';

    let color = '#3b82f6';
    if (child.has_security_findings || child.tier.includes('SECURITY')) color = '#ef4444';
    else if (child.tier.includes('SAFE')) color = '#22c55e';
    else if (child.tier.includes('REVIEW')) color = '#f59e0b';
    div.style.background = color;

    div.innerHTML = `<div class="node-label">${{child.name}}</div><div class="node-size">${{formatBytes(child.physical_size)}}</div>`;
    div.title = `${{child.path || child.name}}\nPhysical: ${{formatBytes(child.physical_size)}}\nTier: ${{child.tier}}\nCategory: ${{child.category}}`;

    if (child.children && child.children.length > 0) {{
      div.onclick = () => {{
        document.getElementById('breadcrumbs').innerHTML = `Path: <span onclick="renderTree(dataTree)">Root</span> &gt; <span>${{child.name}}</span>`;
        renderTree(child);
      }};
    }}

    container.appendChild(div);
    currentX += boxWidth;
  }});
}}

window.onload = () => {{
  renderTree(dataTree);
}};
</script>
</body>
</html>
"#,
        files_count = summary.total_files_scanned,
        physical_gb = (summary.total_physical_bytes as f64) / (1024.0 * 1024.0 * 1024.0),
        safe_mb = (summary.safe_reclaimable_bytes as f64) / (1024.0 * 1024.0),
        review_mb = (summary.review_reclaimable_bytes as f64) / (1024.0 * 1024.0),
        dup_mb = (summary.duplicate_reclaimable_bytes as f64) / (1024.0 * 1024.0),
        security_count = summary.security_findings_count,
        tree_json = tree_json,
        summary_json = summary_json,
    );

    let mut file = File::create(report_path)?;
    file.write_all(html_content.as_bytes())?;
    Ok(())
}

/// Exports scan telemetry into a machine-readable JSON report
pub fn export_json_report<P: AsRef<Path>>(
    report_path: P,
    summary: &ScanSummary,
    files: &[ScannedFile],
    duplicates: &[DuplicateGroup],
) -> std::io::Result<()> {
    #[derive(Serialize)]
    struct FullReport<'a> {
        summary: &'a ScanSummary,
        duplicates: &'a [DuplicateGroup],
        files: &'a [ScannedFile],
    }

    let report = FullReport {
        summary,
        duplicates,
        files,
    };

    let mut file = File::create(report_path)?;
    serde_json::to_writer_pretty(&mut file, &report)?;
    Ok(())
}

/// Exports scan findings to a CSV spreadsheet
pub fn export_csv_report<P: AsRef<Path>>(report_path: P, files: &[ScannedFile]) -> std::io::Result<()> {
    let mut file = File::create(report_path)?;
    writeln!(
        file,
        "Path,FileName,Extension,LogicalBytes,PhysicalBytes,CleanTier,CleanCategory,SecurityFindingsCount,SHA256"
    )?;

    for f in files {
        let clean_cat = f.clean_category.as_deref().unwrap_or("Standard");
        let sha = f.sha256_hash.as_deref().unwrap_or("");
        writeln!(
            file,
            "\"{}\",\"{}\",\"{}\",{},{},\"{}\",\"{}\",{},\"{}\"",
            f.display_path.replace('"', "\"\""),
            f.file_name.replace('"', "\"\""),
            f.extension,
            f.logical_size,
            f.physical_size,
            f.clean_tier.label(),
            clean_cat,
            f.security_findings.len(),
            sha
        )?;
    }

    Ok(())
}
