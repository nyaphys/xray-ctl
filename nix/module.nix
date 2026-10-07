{ config, lib, pkgs, ... }:

let
  cfg = config.services.blancctl;
  stateDirectory = "/var/lib/blancctl";
  control = "${cfg.package}/libexec/blancctl/service-control";
in
{
  imports = [ (lib.mkAliasOptionModule [ "services" "xrayCtl" ] [ "services" "blancctl" ]) ];

  options.services.blancctl = {
    enable = lib.mkEnableOption "Xray VLESS management through xray-ctl";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "The xray-ctl package to install.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      example = "alice";
      description = "Normal user allowed to configure and control BlancVPN.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "users";
      description = "Primary group used for the blancctl state directory and services.";
    };

    autoStart = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Start the TUN service at boot when an Xray configuration exists.";
    };

    failover = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Periodically check connectivity and recover or change servers after repeated failures.";
      };

      interval = lib.mkOption {
        type = lib.types.str;
        default = "30s";
        description = "Delay after one failover check finishes before the next check.";
      };

      failures = lib.mkOption {
        type = lib.types.ints.positive;
        default = 3;
        description = "Consecutive failed checks required before changing servers.";
      };

      timeout = lib.mkOption {
        type = lib.types.ints.positive;
        default = 5;
        description = "Connectivity probe timeout in seconds.";
      };

      candidates = lib.mkOption {
        type = lib.types.ints.positive;
        default = 6;
        description = "Maximum number of alternative servers tested during failover.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.user != "root";
        message = "services.blancctl.user must be a normal, non-root user";
      }
    ];

    environment.systemPackages = [ cfg.package ];
    boot.kernelModules = [ "tun" ];

    environment.etc."blancctl/owner" = {
      text = "${cfg.user}\n";
      mode = "0644";
    };

    systemd.tmpfiles.rules = [
      "d ${stateDirectory} 0700 ${cfg.user} ${cfg.group} -"
    ];

    security.sudo.extraConfig = ''
      Defaults!${control} !authenticate
      ${cfg.user} ALL=(root) NOPASSWD: ${control} check
      ${cfg.user} ALL=(root) NOPASSWD: ${control} start
      ${cfg.user} ALL=(root) NOPASSWD: ${control} stop
      ${cfg.user} ALL=(root) NOPASSWD: ${control} restart
      ${cfg.user} ALL=(root) NOPASSWD: ${control} status
      ${cfg.user} ALL=(root) NOPASSWD: ${control} log
    '';

    systemd.services.blancctl = {
      description = "BlancVPN Xray TUN";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = lib.optionals cfg.autoStart [ "multi-user.target" ];
      unitConfig.ConditionPathExists = "${stateDirectory}/xray.json";
      path = [ cfg.package pkgs.coreutils pkgs.curl pkgs.iproute2 pkgs.systemd pkgs.xray ];
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${pkgs.xray}/bin/xray run -c ${stateDirectory}/xray.json";
        ExecStartPost = "${cfg.package}/libexec/blancctl/tun-route start";
        ExecStopPost = "${cfg.package}/libexec/blancctl/tun-route stop";
        Restart = "on-failure";
        RestartSec = "3s";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadOnlyPaths = [ stateDirectory ];
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" ];
      };
    };

    systemd.services."blancctl-failover" = lib.mkIf cfg.failover.enable {
      description = "BlancVPN connectivity check and automatic failover";
      after = [ "network-online.target" "blancctl.service" ];
      wants = [ "network-online.target" ];
      path = [ cfg.package pkgs.coreutils pkgs.curl pkgs.iproute2 pkgs.systemd pkgs.xray ];
      environment = {
        BLANCCTL_FAILOVER_FAILURES = toString cfg.failover.failures;
        BLANCCTL_FAILOVER_TIMEOUT = toString cfg.failover.timeout;
        BLANCCTL_FAILOVER_CANDIDATES = toString cfg.failover.candidates;
      };
      serviceConfig = {
        Type = "oneshot";
        User = cfg.user;
        Group = cfg.group;
        ExecStart = "${cfg.package}/bin/xray-ctl failover-check";
        NoNewPrivileges = false;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ stateDirectory ];
      };
    };

    systemd.timers."blancctl-failover" = lib.mkIf cfg.failover.enable {
      description = "Check BlancVPN connectivity periodically";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "45s";
        OnUnitInactiveSec = cfg.failover.interval;
        AccuracySec = "5s";
        Persistent = true;
        Unit = "blancctl-failover.service";
      };
    };
  };
}
