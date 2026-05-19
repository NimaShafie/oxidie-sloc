use crate::config::McpConfig;
use crate::http_client::HttpClient;
use crate::protocol::{McpRequest, McpResponse, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::tools::{analyze, compare, ingest, metrics};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct McpServer {
    config: Arc<McpConfig>,
    http: Arc<HttpClient>,
}

impl McpServer {
    pub fn new(config: McpConfig) -> Self {
        let http = HttpClient::new(config.api_key.clone());
        Self {
            config: Arc::new(config),
            http: Arc::new(http),
        }
    }

    pub fn tool_list() -> Value {
        json!([
            {
                "name": "analyze_path",
                "description": "Run oxide-sloc on a local directory or file and return SLOC metrics \
                    (code lines, comment lines, functions, test count, per-language breakdown).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Path to analyze." },
                        "config_file": { "type": "string", "description": "Optional .oxide-sloc.toml path." }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "get_metrics_latest",
                "description": "Fetch the most recent scan metrics from a running oxide-sloc server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_url": { "type": "string", "description": "Server base URL. Defaults to SLOC_SERVER_URL." }
                    }
                }
            },
            {
                "name": "get_metrics_history",
                "description": "Fetch time-series scan history from a running oxide-sloc server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_url": { "type": "string" },
                        "limit": { "type": "integer", "description": "Max entries to return (default 100)." }
                    }
                }
            },
            {
                "name": "get_run_metrics",
                "description": "Fetch metrics for a specific run_id from a running oxide-sloc server.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": { "type": "string", "description": "UUID of the run." },
                        "server_url": { "type": "string" }
                    },
                    "required": ["run_id"]
                }
            },
            {
                "name": "compare_runs",
                "description": "Compare two oxide-sloc JSON result files and return a SLOC delta summary.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "baseline_path": { "type": "string", "description": "Path to baseline JSON." },
                        "current_path": { "type": "string", "description": "Path to current JSON." }
                    },
                    "required": ["baseline_path", "current_path"]
                }
            },
            {
                "name": "health_check",
                "description": "Verify a running oxide-sloc server is reachable and return its version.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_url": { "type": "string" }
                    }
                }
            },
            {
                "name": "ingest_result",
                "description": "POST an AnalysisRun JSON into a running server's registry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "server_url": { "type": "string" },
                        "json_path": { "type": "string", "description": "Path to JSON file on disk." },
                        "json_inline": { "type": "string", "description": "Raw JSON string." }
                    }
                }
            }
        ])
    }

    pub async fn dispatch(&self, req: McpRequest) -> McpResponse {
        match req.method.as_str() {
            "initialize" => McpResponse::ok(
                req.id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "sloc-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }),
            ),

            "tools/list" => McpResponse::ok(req.id, json!({ "tools": Self::tool_list() })),

            "tools/call" => {
                let params = req.params.unwrap_or(Value::Null);
                let name = params["name"].as_str().unwrap_or("").to_owned();
                let args = params["arguments"].clone();
                self.call_tool(req.id, &name, args).await
            }

            _ => McpResponse::err(
                req.id,
                METHOD_NOT_FOUND,
                format!("unknown method: {}", req.method),
            ),
        }
    }

    async fn call_tool(&self, id: Value, name: &str, args: Value) -> McpResponse {
        let result = match name {
            "analyze_path" => {
                let path = match string_arg(&args, "path") {
                    Ok(v) => v,
                    Err(e) => return McpResponse::err(id, INVALID_PARAMS, e.to_string()),
                };
                analyze::analyze_path(path, opt_string(&args, "config_file"), &self.config).await
            }

            "get_metrics_latest" => {
                metrics::get_metrics_latest(
                    opt_string(&args, "server_url"),
                    &self.config,
                    &self.http,
                )
                .await
            }

            "get_metrics_history" => {
                let limit = args["limit"].as_u64();
                metrics::get_metrics_history(
                    opt_string(&args, "server_url"),
                    limit,
                    &self.config,
                    &self.http,
                )
                .await
            }

            "get_run_metrics" => {
                let run_id = match string_arg(&args, "run_id") {
                    Ok(v) => v,
                    Err(e) => return McpResponse::err(id, INVALID_PARAMS, e.to_string()),
                };
                metrics::get_run_metrics(
                    run_id,
                    opt_string(&args, "server_url"),
                    &self.config,
                    &self.http,
                )
                .await
            }

            "compare_runs" => {
                let baseline = match string_arg(&args, "baseline_path") {
                    Ok(v) => v,
                    Err(e) => return McpResponse::err(id, INVALID_PARAMS, e.to_string()),
                };
                let current = match string_arg(&args, "current_path") {
                    Ok(v) => v,
                    Err(e) => return McpResponse::err(id, INVALID_PARAMS, e.to_string()),
                };
                compare::compare_runs(baseline, current, &self.config).await
            }

            "health_check" => {
                metrics::health_check(opt_string(&args, "server_url"), &self.config, &self.http)
                    .await
            }

            "ingest_result" => {
                ingest::ingest_result(
                    opt_string(&args, "server_url"),
                    opt_string(&args, "json_path"),
                    opt_string(&args, "json_inline"),
                    &self.config,
                    &self.http,
                )
                .await
            }

            _ => return McpResponse::err(id, METHOD_NOT_FOUND, format!("unknown tool: {name}")),
        };

        match result {
            Ok(value) => McpResponse::ok(
                id,
                json!({
                    "content": [{ "type": "text", "text": value.to_string() }]
                }),
            ),
            Err(e) => {
                tracing::error!(tool = name, error = %e, "tool call failed");
                McpResponse::err(id, INTERNAL_ERROR, e.to_string())
            }
        }
    }
}

fn string_arg(args: &Value, key: &str) -> anyhow::Result<String> {
    args[key]
        .as_str()
        .map(|s| s.to_owned())
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {key}"))
}

fn opt_string(args: &Value, key: &str) -> Option<String> {
    args[key].as_str().map(|s| s.to_owned())
}
