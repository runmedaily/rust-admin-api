# nix/module.nix — called as: import ./nix/module.nix self
self:
{ config, pkgs, lib, ... }:

let
  cfg = config.services.rust-admin-api;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

  # Derive auth_url from domain
  effectiveAuthUrl =
    if cfg.domain != ""
    then "https://${cfg.domain}"
    else cfg.authUrl;

  # Internal address: loopback only when proxy is enabled
  internalAddr =
    if cfg.proxy.enable
    then "127.0.0.1:${toString cfg.webPort}"
    else "0.0.0.0:${toString cfg.webPort}";

  routesToToml = routes: lib.concatMapStrings (r: ''
    [[proxy.routes]]
    host = "${r.host}"
    ${lib.optionalString (r.pathPrefix != "") ''path_prefix = "${r.pathPrefix}"''}
    upstream = "${r.upstream}"
    auth_required = ${lib.boolToString r.authRequired}
  '') routes;

  # Auto-generate admin panel route + user-defined routes
  allRoutes =
    (lib.optional (cfg.domain != "") {
      host = cfg.domain;
      pathPrefix = "";
      upstream = "http://127.0.0.1:${toString cfg.webPort}";
      authRequired = false;
    })
    ++ cfg.proxy.routes;

  configFile = pkgs.writeText "rust-admin-api-config.toml" ''
    [server]
    listen_addr = "${internalAddr}"

    [auth]
    auth_url = "${effectiveAuthUrl}"
    ${lib.optionalString (cfg.cookieDomain != null) ''cookie_domain = "${cfg.cookieDomain}"''}
    cookie_secure = ${lib.boolToString cfg.cookieSecure}
    jwt_secret_file = "${cfg.dataDir}/jwt.secret"

    [database]
    path = "${cfg.dataDir}/admin.db"

    ${lib.optionalString cfg.proxy.enable ''
    [proxy]
    enabled = true
    http_addr = "0.0.0.0:${toString cfg.proxy.httpPort}"
    https_addr = "0.0.0.0:${toString cfg.proxy.httpsPort}"
    cert_path = "/var/lib/acme/${cfg.domain}/fullchain.pem"
    key_path = "/var/lib/acme/${cfg.domain}/key.pem"

    ${routesToToml allRoutes}
    ''}
  '';

  routeType = lib.types.submodule {
    options = {
      host = lib.mkOption { type = lib.types.str; description = "Hostname to match."; };
      pathPrefix = lib.mkOption { type = lib.types.str; default = ""; description = "Path prefix to match (empty = all paths)."; };
      upstream = lib.mkOption { type = lib.types.str; description = "Upstream address (e.g. http://127.0.0.1:3001)."; };
      authRequired = lib.mkOption { type = lib.types.bool; default = true; description = "Require authentication."; };
    };
  };
in {
  options.services.rust-admin-api = {
    enable = lib.mkEnableOption "rust-admin-api admin panel with Pingora proxy";

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/srv/rust-admin-api";
      description = "Directory for database and JWT secret.";
    };

    webPort = lib.mkOption {
      type = lib.types.port;
      default = 3030;
      description = "Internal web server port for the admin panel.";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Public domain for the auth service (e.g. auth.example.com). Required when proxy is enabled.";
    };

    authUrl = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Public URL of this auth service. Auto-derived from domain.";
    };

    cookieDomain = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Cookie domain for cross-subdomain auth (e.g. .example.com).";
    };

    cookieSecure = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Set Secure flag on session cookies.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the web port directly in the firewall (not needed when proxy is enabled).";
    };

    # --- Pingora proxy ---

    proxy.enable = lib.mkEnableOption "Pingora reverse proxy with TLS (replaces Caddy)";

    proxy.httpPort = lib.mkOption {
      type = lib.types.port;
      default = 80;
      description = "HTTP port for Pingora.";
    };

    proxy.httpsPort = lib.mkOption {
      type = lib.types.port;
      default = 443;
      description = "HTTPS port for Pingora.";
    };

    proxy.acmeEmail = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Email for Let's Encrypt ACME registration. Required when proxy is enabled.";
    };

    proxy.routes = lib.mkOption {
      type = lib.types.listOf routeType;
      default = [];
      description = "Proxy routes. The admin panel route is added automatically from 'domain'.";
      example = lib.literalExpression ''
        [
          { host = "grafana.example.com"; upstream = "http://localhost:3001"; authRequired = true; }
          { host = "api.example.com"; pathPrefix = "/public"; upstream = "http://localhost:9090"; authRequired = false; }
        ]
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Assertions
    assertions = [
      {
        assertion = cfg.proxy.enable -> cfg.domain != "";
        message = "services.rust-admin-api.domain must be set when proxy is enabled.";
      }
      {
        assertion = cfg.proxy.enable -> cfg.proxy.acmeEmail != "";
        message = "services.rust-admin-api.proxy.acmeEmail must be set when proxy is enabled.";
      }
    ];

    # Data directory
    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir} 0755 root root -"
    ];

    # Auth service
    systemd.services.rust-admin-api = {
      description = "rust-admin-api admin panel with Pingora proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ] ++ lib.optional cfg.proxy.enable "acme-${cfg.domain}.service";
      wants = [ "network-online.target" ];

      # Generate JWT secret on first start
      preStart = ''
        if [ ! -f ${cfg.dataDir}/jwt.secret ]; then
          ${pkgs.openssl}/bin/openssl rand -hex 32 > ${cfg.dataDir}/jwt.secret
          chmod 600 ${cfg.dataDir}/jwt.secret
        fi
      '';

      serviceConfig = {
        ExecStart = "${pkg}/bin/rust-admin-api --config ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;
        WorkingDirectory = cfg.dataDir;
      } // lib.optionalAttrs cfg.proxy.enable {
        # Pingora needs CAP_NET_BIND_SERVICE for ports 80/443
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
      };
    };

    # Direct firewall access (without proxy)
    networking.firewall.allowedTCPPorts =
      (lib.optional cfg.openFirewall cfg.webPort)
      ++ (lib.optionals cfg.proxy.enable [ cfg.proxy.httpPort cfg.proxy.httpsPort ]);

    # --- ACME certificate management (when proxy is enabled) ---
    security.acme = lib.mkIf cfg.proxy.enable {
      acceptTerms = true;
      defaults.email = cfg.proxy.acmeEmail;
      certs."${cfg.domain}" = {
        postRun = "systemctl restart rust-admin-api.service";
      };
    };
  };
}
