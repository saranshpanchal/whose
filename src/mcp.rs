use std::io::{self, BufRead, BufReader, Write};

use serde_json::{json, Value};

use crate::engine::{inspect_ports, list_listening, outbound_report};
use crate::error::{Error, Result};
use crate::kill::free_port;
use crate::model::{parse_port_spec, KillOpts, OutboundFilter, QueryOpts};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Lines,
    ContentLength,
}

pub fn run_stdio() -> Result<()> {
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    loop {
        let Some((framing, body)) = read_message(&mut input)? else {
            break;
        };
        if let Some(reply) = handle_message(&body) {
            write_message(&mut output, framing, &reply)?;
        }
    }
    Ok(())
}

pub fn handle_message(text: &str) -> Option<String> {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(err) => {
            return Some(error_line(
                Value::Null,
                -32700,
                &format!("parse error: {err}"),
            ));
        }
    };
    if is_notification(&value) {
        return None;
    }
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(Value::as_str).unwrap_or("");
    let reply = match method {
        "initialize" => ok(
            id,
            json!({
                "protocolVersion": value
                    .pointer("/params/protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("2024-11-05"),
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "whose", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "tools/list" => ok(id, json!({ "tools": tool_defs() })),
        "ping" => ok(id, json!({})),
        "tools/call" => match call_tool(value.get("params")) {
            Ok(payload) => ok(id, payload),
            Err(err) => ok(
                id,
                json!({
                    "content": [{ "type": "text", "text": err }],
                    "isError": true
                }),
            ),
        },
        _ => error_line(id, -32601, &format!("method not found: {method}")),
    };
    Some(reply)
}

fn call_tool(params: Option<&Value>) -> std::result::Result<Value, String> {
    let params = params.ok_or_else(|| "missing params".to_string())?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing tool name".to_string())?;
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let opts = QueryOpts {
        show_secrets: args
            .get("show_secrets")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    let value = match name {
        "whose_port" => {
            let spec = port_from_args(&args)?;
            as_json(inspect_ports(spec, &opts))?
        }
        "whose_list_ports" => as_json(list_listening(&opts))?,
        "whose_outbound_sockets" => {
            let filter = OutboundFilter {
                pid: args.get("pid").and_then(Value::as_u64).map(|v| v as u32),
                process: args
                    .get("process")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            };
            as_json(outbound_report(&filter, &opts))?
        }
        "whose_free_port" => {
            let spec = port_from_args(&args)?;
            let kill = KillOpts {
                yes: args.get("yes").and_then(Value::as_bool).unwrap_or(false),
                force: args.get("force").and_then(Value::as_bool).unwrap_or(false),
                grace_ms: args.get("grace_ms").and_then(Value::as_u64).unwrap_or(2000),
                interactive: false,
            };
            as_json(free_port(spec, kill))?
        }
        other => return Err(format!("unknown tool {other}")),
    };
    let text = serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?;
    Ok(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false
    }))
}

fn as_json<T: serde::Serialize>(result: Result<T>) -> std::result::Result<Value, String> {
    let value = result.map_err(|err| err.to_string())?;
    serde_json::to_value(value).map_err(|err| err.to_string())
}

fn port_from_args(args: &Value) -> std::result::Result<crate::model::PortSpec, String> {
    if let Some(port) = args.get("port") {
        let text = match port {
            Value::Number(number) => number.to_string(),
            Value::String(text) => text.clone(),
            _ => return Err("port must be a number or string".to_string()),
        };
        return parse_port_spec(&text).map_err(|err| err.to_string());
    }
    if let Some(query) = args.get("query").and_then(Value::as_str) {
        return parse_port_spec(query).map_err(|err| err.to_string());
    }
    Err("missing port".to_string())
}

fn tool_defs() -> Value {
    json!([
        {
            "name": "whose_port",
            "description": "Who owns a localhost TCP or UDP port: process ancestry, git worktree, exposure, tcp_info.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "port": { "description": "Port number, :port, or start-end range" },
                    "show_secrets": { "type": "boolean" }
                },
                "required": ["port"]
            }
        },
        {
            "name": "whose_list_ports",
            "description": "Listening TCP and UDP sockets grouped by git worktree.",
            "inputSchema": {
                "type": "object",
                "properties": { "show_secrets": { "type": "boolean" } }
            }
        },
        {
            "name": "whose_outbound_sockets",
            "description": "Established, SYN_SENT, CLOSE_WAIT, and TIME_WAIT sockets with RTT, retransmits, and byte counters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pid": { "type": "integer" },
                    "process": { "type": "string" },
                    "show_secrets": { "type": "boolean" }
                }
            }
        },
        {
            "name": "whose_free_port",
            "description": "Free a listening port by signaling its process group. Does not signal unless yes is true. Supervised processes also need force.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "port": { "description": "Port number or range" },
                    "yes": { "type": "boolean" },
                    "force": { "type": "boolean" },
                    "grace_ms": { "type": "integer" }
                },
                "required": ["port"]
            }
        }
    ])
}

fn ok(id: Value, result: Value) -> String {
    compact(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn error_line(id: Value, code: i32, message: &str) -> String {
    compact(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }))
}

fn compact(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| {
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"encode\"}}"
            .to_string()
    })
}

fn is_notification(value: &Value) -> bool {
    match value.get("id") {
        None | Some(Value::Null) => true,
        Some(_) => false,
    }
}

fn read_message(input: &mut impl BufRead) -> Result<Option<(Framing, String)>> {
    let mut line = String::new();
    let read = input.read_line(&mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.to_ascii_lowercase().starts_with("content-length:") {
        let len: usize = line
            .split_once(':')
            .and_then(|(_, value)| value.trim().parse().ok())
            .ok_or_else(|| Error::new("invalid Content-Length"))?;
        loop {
            line.clear();
            let read = input.read_line(&mut line)?;
            if read == 0 {
                return Ok(None);
            }
            if line == "\n" || line == "\r\n" {
                break;
            }
        }
        let mut buf = vec![0u8; len];
        input.read_exact(&mut buf)?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        return Ok(Some((Framing::ContentLength, text)));
    }
    Ok(Some((Framing::Lines, line)))
}

fn write_message(output: &mut impl Write, framing: Framing, body: &str) -> Result<()> {
    match framing {
        Framing::Lines => writeln!(output, "{body}")?,
        Framing::ContentLength => {
            write!(output, "Content-Length: {}\r\n\r\n{body}", body.len())?;
        }
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn initialize_list_and_call_round_trip() {
        let init = handle_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        )
        .unwrap();
        assert!(!init.contains('\n'));
        let init: Value = serde_json::from_str(&init).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "whose");
        assert_eq!(init["id"], 1);

        assert!(
            handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none()
        );

        let listed = handle_message(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        let listed: Value = serde_json::from_str(&listed).unwrap();
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(names.contains(&"whose_port"));
        assert!(names.contains(&"whose_list_ports"));
        assert!(names.contains(&"whose_outbound_sockets"));
        assert!(names.contains(&"whose_free_port"));

        let called = handle_message(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whose_list_ports","arguments":{}}}"#,
        )
        .unwrap();
        let called: Value = serde_json::from_str(&called).unwrap();
        assert_eq!(called["result"]["isError"], false);
        let text = called["result"]["content"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(text).unwrap();
        assert!(body.get("groups").is_some());
    }
}
