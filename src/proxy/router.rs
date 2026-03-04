use crate::config::RouteConfig;

#[derive(Debug, Clone)]
pub struct MatchedRoute {
    pub upstream_host: String,
    pub upstream_port: u16,
    pub use_tls: bool,
    pub auth_required: bool,
}

pub struct RouteTable {
    entries: Vec<CompiledRoute>,
}

struct CompiledRoute {
    host: String,
    path_prefix: String,
    /// Pre-computed "prefix/" for segment-boundary matching without allocation.
    path_prefix_slash: String,
    upstream_host: String,
    upstream_port: u16,
    use_tls: bool,
    auth_required: bool,
}

impl RouteTable {
    /// Compile routes from config. Validates upstream format at startup.
    pub fn compile(routes: &[RouteConfig]) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(routes.len());
        for r in routes {
            let (host, port, tls) = parse_upstream(&r.upstream)?;
            let path_prefix_slash = if r.path_prefix.is_empty() || r.path_prefix == "/" {
                String::new()
            } else {
                format!("{}/", r.path_prefix)
            };
            entries.push(CompiledRoute {
                host: r.host.clone(),
                path_prefix: r.path_prefix.clone(),
                path_prefix_slash,
                upstream_host: host,
                upstream_port: port,
                use_tls: tls,
                auth_required: r.auth_required,
            });
        }
        Ok(Self { entries })
    }

    /// Match a request by host and path. Returns the first match.
    pub fn match_request(&self, host: &str, path: &str) -> Option<MatchedRoute> {
        let host = host.split(':').next().unwrap_or(host);
        self.entries.iter().find_map(|e| {
            let prefix_matches = e.path_prefix.is_empty()
                || e.path_prefix == "/"
                || path == e.path_prefix
                || (!e.path_prefix_slash.is_empty() && path.starts_with(&e.path_prefix_slash));
            if e.host == host && prefix_matches {
                Some(MatchedRoute {
                    upstream_host: e.upstream_host.clone(),
                    upstream_port: e.upstream_port,
                    use_tls: e.use_tls,
                    auth_required: e.auth_required,
                })
            } else {
                None
            }
        })
    }
}

fn parse_upstream(upstream: &str) -> Result<(String, u16, bool), String> {
    let url = upstream.trim_end_matches('/');
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        // Bare host:port defaults to plain HTTP
        return parse_host_port(url, false);
    };
    parse_host_port(rest, tls)
}

fn parse_host_port(s: &str, tls: bool) -> Result<(String, u16, bool), String> {
    let default_port: u16 = if tls { 443 } else { 80 };
    if let Some((host, port_str)) = s.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| format!("Bad port in upstream: {s}"))?;
        Ok((host.to_string(), port, tls))
    } else {
        Ok((s.to_string(), default_port, tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(host: &str, prefix: &str, upstream: &str, auth: bool) -> RouteConfig {
        RouteConfig {
            host: host.to_string(),
            path_prefix: prefix.to_string(),
            upstream: upstream.to_string(),
            auth_required: auth,
        }
    }

    #[test]
    fn test_exact_host_match() {
        let table = RouteTable::compile(&[
            route("app.example.com", "/", "http://127.0.0.1:8080", true),
        ])
        .unwrap();
        let m = table.match_request("app.example.com", "/foo").unwrap();
        assert_eq!(m.upstream_host, "127.0.0.1");
        assert_eq!(m.upstream_port, 8080);
        assert!(!m.use_tls);
    }

    #[test]
    fn test_host_mismatch() {
        let table = RouteTable::compile(&[
            route("app.example.com", "/", "http://127.0.0.1:8080", true),
        ])
        .unwrap();
        assert!(table.match_request("other.example.com", "/").is_none());
    }

    #[test]
    fn test_host_with_port_stripped() {
        let table = RouteTable::compile(&[
            route("app.example.com", "/", "http://127.0.0.1:8080", true),
        ])
        .unwrap();
        assert!(table.match_request("app.example.com:443", "/foo").is_some());
    }

    #[test]
    fn test_path_prefix_match() {
        let table = RouteTable::compile(&[
            route("api.example.com", "/v1", "http://127.0.0.1:9000", true),
            route("api.example.com", "/", "http://127.0.0.1:9001", false),
        ])
        .unwrap();
        let m = table.match_request("api.example.com", "/v1/users").unwrap();
        assert_eq!(m.upstream_port, 9000);
        assert!(m.auth_required);

        let m = table.match_request("api.example.com", "/health").unwrap();
        assert_eq!(m.upstream_port, 9001);
        assert!(!m.auth_required);
    }

    #[test]
    fn test_path_prefix_no_partial_match() {
        let table = RouteTable::compile(&[
            route("api.example.com", "/public", "http://127.0.0.1:9000", false),
            route("api.example.com", "/", "http://127.0.0.1:9001", true),
        ])
        .unwrap();
        // "/publicdocs" must NOT match the "/public" route
        let m = table.match_request("api.example.com", "/publicdocs").unwrap();
        assert_eq!(m.upstream_port, 9001);
        assert!(m.auth_required);

        // "/public/foo" should match "/public"
        let m = table.match_request("api.example.com", "/public/foo").unwrap();
        assert_eq!(m.upstream_port, 9000);
        assert!(!m.auth_required);

        // "/public" exactly should match "/public"
        let m = table.match_request("api.example.com", "/public").unwrap();
        assert_eq!(m.upstream_port, 9000);
    }

    #[test]
    fn test_https_upstream() {
        let table = RouteTable::compile(&[
            route("app.example.com", "/", "https://backend.example.com", true),
        ])
        .unwrap();
        let m = table.match_request("app.example.com", "/").unwrap();
        assert!(m.use_tls);
        assert_eq!(m.upstream_port, 443);
    }
}
