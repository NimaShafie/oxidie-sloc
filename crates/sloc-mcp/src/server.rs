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
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {key}"))
}

fn opt_string(args: &Value, key: &str) -> Option<String> {
    args[key].as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::McpConfig;

    fn test_server() -> McpServer {
        McpServer::new(McpConfig {
            server_url: None,
            bin_path: "oxide-sloc".into(),
            api_key: None,
            allowed_roots: vec![],
        })
    }

    #[test]
    fn tool_list_is_array_with_expected_tools() {
        let tools = McpServer::tool_list();
        let arr = tools.as_array().expect("tool_list must be a JSON array");
        assert!(
            arr.len() >= 5,
            "expected at least 5 tools, got {}",
            arr.len()
        );
        let names: Vec<&str> = arr.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"analyze_path"), "must have analyze_path");
        assert!(
            names.contains(&"get_metrics_latest"),
            "must have get_metrics_latest"
        );
        assert!(names.contains(&"compare_runs"), "must have compare_runs");
        assert!(names.contains(&"health_check"), "must have health_check");
    }

    #[test]
    fn tool_list_each_has_name_description_schema() {
        let tools = McpServer::tool_list();
        for tool in tools.as_array().unwrap() {
            assert!(tool["name"].is_string(), "each tool must have a name");
            assert!(
                tool["description"].is_string(),
                "each tool must have a description"
            );
            assert!(
                tool["inputSchema"].is_object(),
                "each tool must have inputSchema"
            );
        }
    }

    #[tokio::test]
    async fn dispatch_initialize_returns_version() {
        let srv = test_server();
        let req = crate::protocol::McpRequest {
            id: json!(1),
            method: "initialize".into(),
            params: None,
        };
        let resp = srv.dispatch(req).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["serverInfo"]["name"].is_string());
    }

    #[tokio::test]
    async fn dispatch_tools_list_returns_tool_array() {
        let srv = test_server();
        let req = crate::protocol::McpRequest {
            id: json!(2),
            method: "tools/list".into(),
            params: None,
        };
        let resp = srv.dispatch(req).await;
        assert!(resp.result.is_some());
        let tools = &resp.result.unwrap()["tools"];
        assert!(tools.is_array());
        assert!(!tools.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dispatch_unknown_method_returns_method_not_found() {
        let srv = test_server();
        let req = crate::protocol::McpRequest {
            id: json!(3),
            method: "nonexistent/method".into(),
            params: None,
        };
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, crate::protocol::METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_tools_call_unknown_tool_returns_error() {
        let srv = test_server();
        let req = crate::protocol::McpRequest {
            id: json!(4),
            method: "tools/call".into(),
            params: Some(json!({"name": "nonexistent_tool", "arguments": {}})),
        };
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn dispatch_analyze_path_missing_arg_returns_invalid_params() {
        let srv = test_server();
        let req = crate::protocol::McpRequest {
            id: json!(5),
            method: "tools/call".into(),
            params: Some(json!({"name": "analyze_path", "arguments": {}})),
        };
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, crate::protocol::INVALID_PARAMS);
    }

    #[test]
    fn string_arg_present() {
        let args = json!({"path": "/tmp/test"});
        let result = string_arg(&args, "path").unwrap();
        assert_eq!(result, "/tmp/test");
    }

    #[test]
    fn string_arg_missing_errors() {
        let args = json!({});
        assert!(string_arg(&args, "path").is_err());
    }

    #[test]
    fn opt_string_present() {
        let args = json!({"server_url": "http://localhost:4317"});
        assert_eq!(
            opt_string(&args, "server_url"),
            Some("http://localhost:4317".into())
        );
    }

    #[test]
    fn opt_string_absent() {
        let args = json!({});
        assert_eq!(opt_string(&args, "server_url"), None);
    }
}
