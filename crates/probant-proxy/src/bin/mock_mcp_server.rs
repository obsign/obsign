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
                "capabilities": { "tools": {} },
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
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("{name} executed")
                    }],
                    "isError": false
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
