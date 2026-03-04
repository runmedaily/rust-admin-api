use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::prelude::*;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

use crate::auth::session::{extract_bearer_value, parse_session_cookie};
use crate::auth::verifier::{AuthOutcome, AuthVerifier, RequestCredentials};
use crate::proxy::router::{MatchedRoute, RouteTable};

/// Shared state for the gateway, wrapped in Arc for Pingora's thread pool.
pub struct GatewayState {
    pub router: RouteTable,
    pub verifier: AuthVerifier,
    pub login_url: String,
}

pub struct Gateway {
    pub state: Arc<GatewayState>,
}

/// Per-request context.
pub struct GatewayCtx {
    matched_route: Option<MatchedRoute>,
    username: Option<String>,
    role: Option<String>,
}

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx {
            matched_route: None,
            username: None,
            role: None,
        }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req = session.req_header();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let path = req.uri.path();

        // Route lookup
        let Some(route) = self.state.router.match_request(host, path) else {
            let _ = session.respond_error(404).await;
            return Ok(true);
        };

        if route.auth_required {
            // Extract credentials from raw headers
            let cookie_header = req
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let session_token = parse_session_cookie(cookie_header);

            let auth_header = req
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let bearer_token = extract_bearer_value(auth_header);

            let creds = RequestCredentials {
                session_token,
                bearer_token,
            };

            match self.state.verifier.verify(&creds) {
                AuthOutcome::Authenticated(user) => {
                    ctx.username = Some(user.username);
                    ctx.role = Some(user.role);
                }
                AuthOutcome::Unauthenticated => {
                    let original_url = format!("https://{host}{path}");
                    let rd = urlencoding::encode(&original_url);
                    let redirect_url = format!("{}?rd={rd}", self.state.login_url);

                    let mut resp = ResponseHeader::build(307, Some(1))?;
                    resp.insert_header("Location", &redirect_url)?;
                    session.write_response_header(Box::new(resp), true).await?;
                    return Ok(true);
                }
            }
        }

        ctx.matched_route = Some(route);
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let route = ctx
            .matched_route
            .as_ref()
            .ok_or_else(|| Error::new(ErrorType::ConnectError))?;

        let peer = HttpPeer::new(
            (&*route.upstream_host, route.upstream_port),
            route.use_tls,
            route.upstream_host.clone(),
        );
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Security: strip auth headers that clients might try to spoof
        upstream_request.remove_header("X-Forwarded-User");
        upstream_request.remove_header("X-Forwarded-Role");

        // Inject verified identity
        if let Some(ref user) = ctx.username {
            upstream_request.insert_header("X-Forwarded-User", user)?;
        }
        if let Some(ref role) = ctx.role {
            upstream_request.insert_header("X-Forwarded-Role", role)?;
        }

        Ok(())
    }
}
