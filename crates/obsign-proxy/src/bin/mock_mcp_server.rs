//! Minimal MCP server for the demo.
//!
//! Speaks JSON-RPC 2.0 over stdio and exposes four tools, one of them
//! destructive. It executes whatever it is asked, with no checks at all —
//! which is precisely the point: the server does not defend itself, the
//! gateway protects it.

use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg): Result<Value, _> = serde_json::from_str(&line) else {
            continue;
        };

        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {}, "resources": {}, "prompts": {} },
                "serverInfo": { "name": "mock-db-ops", "version": "0.1.0" }
            }),

            "tools/list" => json!({
                "tools": [
                    { "name": "delete_production_db",
                      "description": "Permanently deletes a production database",
                      "inputSchema": { "type": "object" } },
                    { "name": "ticket_update",
                      "description": "Updates a support ticket",
                      "inputSchema": { "type": "object" } },
                    { "name": "search_docs",
                      "description": "Searches the internal documentation",
                      "inputSchema": { "type": "object" } },
                    { "name": "send_message",
                      "description": "Posts a message to a channel",
                      "inputSchema": { "type": "object" } },
                    { "name": "exfiltrate_secrets",
                      "description": "Tool not declared in the signed catalogue",
                      "inputSchema": { "type": "object" } }
                ]
            }),

            "tools/call" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // The server obeys without question. If it gets the call, it acts.
                eprintln!("[server] EXECUTING {name}");
                if name == "ticket_update" {
                    // Server-initiated notification, emitted before the
                    // response: transport tests use it to check the
                    // downstream channel (SSE stream over HTTP).
                    let notif = json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/resources/updated",
                        "params": { "uri": "ticket://T-8821" }
                    });
                    let mut lock = stdout.lock();
                    let _ = writeln!(lock, "{notif}");
                    let _ = lock.flush();
                }
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("{name} executed")
                    }],
                    "isError": false
                })
            }

            // The read channels the gateway must arbitrate exactly like tool
            // calls: same obedience, same absence of self-defence.
            "resources/list" => json!({
                "resources": [
                    { "uri": "docs://runbook", "name": "Operations runbook" },
                    { "uri": "db://prod/customers", "name": "Customer table dump" }
                ]
            }),

            "resources/read" => {
                let uri = msg
                    .pointer("/params/uri")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                eprintln!("[server] READING {uri}");
                json!({
                    "contents": [{
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": format!("contents of {uri}")
                    }]
                })
            }

            "prompts/list" => json!({
                "prompts": [
                    { "name": "summarize", "description": "Summarizes a document" }
                ]
            }),

            "prompts/get" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                eprintln!("[server] SERVING PROMPT {name}");
                json!({
                    "messages": [{
                        "role": "user",
                        "content": { "type": "text", "text": format!("prompt {name}") }
                    }]
                })
            }

            // Notification (no id): nothing to answer.
            _ if id.is_null() => continue,

            _ => json!({ "ok": true }),
        };

        let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{resp}");
        let _ = lock.flush();
    }
}
