# nix/module.nix — called as: import ./nix/module.nix self
self:
{ config, pkgs, lib, ... }:

let
  cfg = config.services.rust-admin-api;
  pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;

  # Derive auth_url from domain when caddy is enabled
  effectiveAuthUrl =
    if cfg.caddy.enable && cfg.domain != ""
    then "https://${cfg.domain}"
    else cfg.authUrl;

  configFile = pkgs.writeText "rust-admin-api-config.toml" ''
    [server]
    listen_addr = "0.0.0.0:${toString cfg.webPort}"

    [auth]
    auth_url = "${effectiveAuthUrl}"
    ${lib.optionalString (cfg.cookieDomain != null) ''cookie_domain = "${cfg.cookieDomain}"''}
    cookie_secure = ${lib.boolToString cfg.cookieSecure}

    [database]
    path = "${cfg.dataDir}/admin.db"
  '';
in {
  options.services.rust-admin-api = {
    enable = lib.mkEnableOption "rust-admin-api admin panel with forward auth";

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/srv/rust-admin-api";
      description = "Directory for database and static assets.";
    };

    webPort = lib.mkOption {
      type = lib.types.port;
      default = 3030;
      description = "Internal web server port (Caddy proxies to this).";
    };

    domain = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Public domain for the auth service (e.g. auth.example.com). Required when caddy.enable is true.";
    };

    authUrl = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Public URL of this auth service. Auto-derived from domain when caddy is enabled.";
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
      description = "Open the web port directly in the firewall (not needed when using Caddy).";
    };

    # --- Caddy integration ---

    caddy.enable = lib.mkEnableOption "Caddy reverse proxy with automatic HTTPS and forward auth";

    caddy.protectedServices = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = "Map of domain -> upstream URL. Each domain gets forward auth + reverse proxy.";
      example = lib.literalExpression ''
        {
          "firetv.example.com" = "http://localhost:8081";
          "grafana.example.com" = "http://localhost:3000";
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Assertions
    assertions = [
      {
        assertion = cfg.caddy.enable -> cfg.domain != "";
        message = "services.rust-admin-api.domain must be set when caddy is enabled.";
      }
    ];

    # Data directory
    systemd.tmpfiles.rules = [
      "d ${cfg.dataDir} 0755 root root -"
    ];

    # Auth service
    systemd.services.rust-admin-api = {
      description = "rust-admin-api admin panel with forward auth";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        ExecStart = "${pkg}/bin/rust-admin-api --config ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;
        WorkingDirectory = cfg.dataDir;
      };
    };

    # Direct firewall access (without Caddy)
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.webPort ];

    # --- Caddy: auto-configured reverse proxy with forward auth ---
    services.caddy = lib.mkIf cfg.caddy.enable {
      enable = true;

      virtualHosts =
        # Auth service gets its own domain (login page, dashboard, verify endpoint)
        {
          "${cfg.domain}" = {
            extraConfig = ''
              reverse_proxy localhost:${toString cfg.webPort}
            '';
          };
        }
        # Each protected service gets forward_auth + reverse_proxy
        // lib.mapAttrs (_domain: upstream: {
          extraConfig = ''
            forward_auth localhost:${toString cfg.webPort} {
              uri /api/verify
              copy_headers X-Forwarded-User X-Forwarded-Role
            }
            reverse_proxy ${upstream}
          '';
        }) cfg.caddy.protectedServices;
    };
  };
}
