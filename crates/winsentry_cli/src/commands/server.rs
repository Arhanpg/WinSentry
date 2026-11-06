//! Interactive Local Web Dashboard & GUI Server
//!
//! Provides a zero-dependency local web dashboard on http://127.0.0.1:7878
//! allowing users to trigger scans, inspect interactive D3 treemaps,
//! review security findings, and execute safe remediations.

use crate::commands::scan::{execute_full_scan, ScanOutputOptions};
use scanner_core::models::ScanConfig;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

pub fn start_dashboard_server(port: u16) -> std::io::Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)?;

    println!("============================================================");
    println!(" WinSentry Interactive Web Dashboard Server");
    println!("============================================================");
    println!(" Listening at: http://{}", addr);
    println!(" Open http://{} in your web browser.", addr);
    println!(" Press Ctrl+C in this terminal to stop the server.");
    println!("============================================================");

    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            let _ = handle_connection(&mut s);
        }
    }

    Ok(())
}

fn handle_connection(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buffer = [0u8; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let first_line = request.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    if path == "/" || path == "/index.html" {
        send_html_response(stream, include_str!("../dashboard.html"))
    } else if path.starts_with("/api/scan") {
        // Run scan on current directory
        let targets = vec![PathBuf::from(".")];
        let config = ScanConfig::default();
        let output_opts = ScanOutputOptions {
            html_report: None,
            json_report: None,
            csv_report: None,
        };

        let (files, summary) = execute_full_scan(&targets, &config, &output_opts);

        #[derive(serde::Serialize)]
        struct ApiResponse<'a> {
            summary: &'a scanner_core::models::ScanSummary,
            files_count: usize,
        }

        let resp = ApiResponse {
            summary: &summary,
            files_count: files.len(),
        };

        let json = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".to_string());
        send_json_response(stream, &json)
    } else {
        send_not_found(stream)
    }
}

fn send_html_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn send_json_response(stream: &mut TcpStream, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn send_not_found(stream: &mut TcpStream) -> std::io::Result<()> {
    let body = "404 Not Found";
    let response = format!(
        "HTTP/1.1 404 NOT FOUND\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}
