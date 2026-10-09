# xray-ctl

Xray VLESS subscription manager with multiple sources, node selection, and configurable split tunneling on Linux.

Project documents: [verifiable requirements](REQUIREMENTS.md),
[architecture](docs/architecture.md), and a [split-tunneling guide](docs/split-tunneling.md)
with the `cldom.ru` diagnostic case. The requirements distinguish implemented
behavior from pending end-to-end verification and proposed improvements.

## Arch Linux installation

Until the AUR package is published, clone this repository and build the local
`PKGBUILD` with `paru`:

```console
git clone https://github.com/nyaphys/xray-ctl.git
cd xray-ctl
paru -Bi .
sudo xray-ctl-setup "$USER"
xray-ctl doctor
```

The package replaces the old `blancctl` package but keeps its private state in
`/var/lib/blancctl` and its existing systemd service name. Review package and
service changes before approving the `paru`/`sudo` prompts. Once the separate
AUR package has actually been published, installation becomes
`paru -S xray-ctl`; GitHub publication alone does not create an AUR package.

## NixOS installation from this directory

This repository exports both an `xray-ctl` package and a NixOS module. Add the
directory as an input of your NixOS configuration flake:

```nix
{
  inputs.xray-ctl.url = "path:/absolute/path/to/xray-ctl";

  outputs = { self, nixpkgs, ... }@inputs: {
    nixosConfigurations.my-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit inputs; };
      modules = [
        inputs.xray-ctl.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

Do not use a `path:` input pointing at a checkout that also contains private
files (for example `recovery/`): Nix may copy the whole input into the store.
Use a clean source directory, or after publishing use a GitHub input / a
tracked-only `git+file:` source. The package derivation itself includes only
the application and its service helpers.

Enable it in `configuration.nix`, replacing `your-user` with the normal desktop
user that should own the VPN configuration:

```nix
{
  services.xrayCtl = {
    enable = true;
    user = "your-user";
    group = "users";
    autoStart = true;
  };
}
```

Apply the configuration, then save the private subscription URL as the normal
user (do not put it in the Nix store):

```console
sudo nixos-rebuild switch --flake /path/to/nixos-config#my-host
xray-ctl subscription add primary 'https://example.invalid/private-subscription'
xray-ctl update
xray-ctl best
xray-ctl doctor
```

`autoStart` only starts the service at boot after `xray.json` has been created.
The subscription URL and generated state remain private under
`/var/lib/blancctl`. This legacy state path, `blancctl.service`, and the
`services.blancctl` option stay available to preserve existing installations.
The `blancctl` command remains a compatibility alias. On NixOS, do not run
`xray-ctl-setup`; the module owns the
user, systemd, state-directory, and narrowly scoped sudo configuration.

To test the package without installing the NixOS service, run
`nix run /absolute/path/to/xray-ctl -- --version`.

Public IPv4 and IPv6 TCP/UDP traffic uses the selected VLESS server by default,
including Russian domains and addresses. Only private/LAN destinations bypass
the VPN;
they are excluded in the kernel policy-routing table and remain available while
the VPN starts, stops, or changes servers. Xray also sniffs HTTP/TLS/QUIC
traffic on the TUN path so a domain can be recovered from a connection to an
IP address. The Linux TUN configuration does not change the system DNS server;
DNS behavior still depends on the host's resolver setup. If the VPN service is
stopped, system routing returns to the host's normal connection: this is split
tunneling, not a fail-closed kill switch.

```text
xray-ctl                  start the previously selected server
xray-ctl countries        list countries
xray-ctl country CODE     select the best cached/tested server in a country
xray-ctl update           refresh subscriptions (up to 8 concurrently)
xray-ctl best             test cached servers, select one, then refresh in background
xray-ctl best --refresh   refresh first, then select
xray-ctl update-status    show the last background refresh result
xray-ctl status           live VPN, country, ping, and speed check
xray-ctl log              show recent private diagnostic events (JSON lines)
xray-ctl log --lines 500  show more events, including rotated history
xray-ctl log --service    show Xray and failover systemd journal
xray-ctl proxy            show the local SOCKS5 proxy address
xray-ctl stop             stop the TUN
xray-ctl doctor           verify ownership, dependencies, service access, and shell proxy state
```

## Multiple subscriptions

```console
xray-ctl subscription add primary 'https://provider.example/subscription'
xray-ctl subscription add backup 'https://other.example/subscription'
xray-ctl subscription list
xray-ctl update
xray-ctl best
```

`subscription set NAME URL` changes one source; `subscription remove NAME` removes
it from the registry but retains its unique cached profiles as inactive backups.
The legacy `subscription URL` command still sets the `default` source. URLs may
also be passed as a path to a local file containing the URL, so the secret need
not appear in shell history. `subscription list` shows names only, never URLs.
Configured sources download with up to eight workers. If one fails while another
succeeds, the failed source's last current profiles stay available. Exact
duplicate connection profiles shared across sources become one selectable node,
but distinct connection settings remain separate. Run `update` after adding or
changing sources to include them in the next `best` selection; ordinary `best`
uses the cache first for speed, then refreshes in the background.

## Split tunneling

The default is proxy for all public destinations. Add only Russian sites that
you have confirmed work directly; there is deliberately no blanket `.ru` or
Russian-IP bypass, because some Russian sites still need the VPN.

```console
xray-ctl route show
xray-ctl route add direct domain example.ru
xray-ctl route add direct domain full:login.example.ru
xray-ctl route add direct ip 203.0.113.0/24
xray-ctl route apply
```

`domain:example.ru` (the default form) matches the domain and subdomains;
`full:example.ru` matches exactly. IP rules accept a single address or CIDR.
Rules are saved to private `/var/lib/blancctl/routing.json` and take effect
after `route apply` or the next connection selection. `route remove direct
domain example.ru` removes an exception. `route add proxy domain NAME` forces
proxying and `route add block domain NAME` blocks a destination. For public
traffic, block rules have highest priority, followed by proxy and direct
rules, then the default. `route default direct` reverses the default for specialized setups;
`route default proxy` restores the recommended mode. Local/private networks
remain direct at the kernel and Xray layers.

Domain rules rely on Xray sniffing HTTP, TLS, and QUIC hostnames; applications
that hide the hostname or connect by IP may need an IP rule. Be careful with
direct IP ranges: other websites on shared hosting/CDNs may use them. `route
apply` validates and restarts the selected service, reverting the live Xray
configuration if the new connection fails. It does not remove a saved rule on
failure; correct it with `route remove` or edit the private file. DNS and
fail-closed behavior depend on the host's resolver and firewall; this tool
does not promise leak protection when the tunnel is unavailable.
Sniffing uses `routeOnly`, so domain decisions can coexist with matching the
original destination IP without changing that destination.
For a domain that works through the physical interface but times out through
`blanc0`, investigate the split-tunneling policy before blaming the selected
node. `curl --noproxy '*'` bypasses an application proxy, not Linux TUN policy
routing; see the [diagnostic procedure](docs/split-tunneling.md).

`best` selects from the cached subscription, then starts a background refresh
after releasing its configuration lock. The command does not wait for that
download; `update-status` shows whether it completed. `best --refresh` still
downloads before testing when the new servers must be included immediately.
Russia (RU) endpoints remain in the private subscription/cache for recovery,
but are excluded from `best`, failover, automatic start, `country` selection,
and the `countries` list. Installing a new version does not interrupt an
already-running connection; run `best` to switch if needed.

The selection tests current connection profiles concurrently (up to 32 workers
by default). Profiles sharing one endpoint are summarized on one output line,
but each is still tested and can be selected independently. Each profile checks
Cloudflare, Telegram, ChatGPT, and YouTube concurrently
through one temporary SOCKS proxy. The result shows which of the four returned
HTTP success (2xx/3xx). Servers reaching more sites rank first; the initial
choice among them uses latency. One site's 4xx or 5xx response does not make
an otherwise working server disappear. A small GET range avoids HEAD-only
responses that differ from browser requests. The
per-endpoint timeout is adaptive:
5.5 seconds for an unmeasured server and a value based on previous latency,
capped by `--timeout` (8 seconds by default). After the connectivity checks,
`best` and `country` compare speed for at most four responsive profiles with
the best site coverage and comparable latency. These bounded 512 KiB tests run
in parallel and take at most four seconds of download time each. A speed test
failure never marks a working profile as dead; a measured gain must exceed 30%
to change the latency-based choice or an already healthy selection. `status`
still measures live download speed separately. After a switch, `xray-ctl`
checks the running SOCKS path; if no test site works, it
restores the previous configuration and restarts the previous connection. If
the already-running server and generated configuration are unchanged, `best`
keeps that connection instead of restarting it.

Subscription refreshes move profiles missing from the latest response to the
private `retained-nodes.json` backup cache; `nodes.json` contains only current
profiles. Existing caches with older records are migrated on the next refresh.
Their identifiers and cached measurements survive subscription
reordering and label changes. Identical connection profiles are represented by
one selectable node even when their names differ or the subscription repeats
them. Profiles with distinct connection settings and servers that fail checks
are never dropped for that reason. `best` tests current profiles plus the
currently selected older profile, and tests the remaining backups if none of
those work. `countries` counts endpoints rather than repeated SNI/short-ID
variants. The complete latest subscription response, including duplicate links,
is kept in
the private `subscription.raw` file for the default source and hashed files in
`subscription-raw/` for named sources, so unsupported or malformed entries are
not silently discarded. They cannot be selected until their format is
supported. `update` only changes the cache: it never switches or restarts the
running connection, even if a different server has the same name. `start` also
prefers the saved working configuration if its node is absent from the new
cache. Changing a subscription URL retains old profiles as backups after a
successful download. The download timeout adapts to the previous
successful refresh (8 seconds on the first run, up to 12 seconds later); it
does not perform automatic retry loops. The last successful latency is kept
separately from the latest pass/fail result, so a temporary failure cannot make
future checks too short.

BlancVPN describes "Xray Extra" as a mode in its app. `xray-ctl` uses the
standard Xray core with the VLESS/Reality settings from the subscription.
Profiles labeled Extra in that subscription can be selected here; this alone
does not establish that their behavior matches the phone app's Extra mode.
VLESS links using TCP, WebSocket, XHTTP (including its `mode` and `extra`
parameters), gRPC, or HTTPUpgrade are supported. Other transport types remain
in the private raw subscription but are not offered as working nodes. Unlike
NekoBox, `xray-ctl` does not use sing-box, and carrier-specific Extra profiles
still depend on the subscription settings enabled by the provider.

Automatic monitoring is enabled by `xray-ctl-setup` on Arch and by default in
the NixOS module. `blancctl-failover.timer` checks the live SOCKS path against
all four sites every 30 seconds. A transient failure keeps the current node;
the timer switches only after three consecutive checks in which none of the
sites are reachable. The six best distinct cached alternatives are tested in
parallel, prioritizing site coverage and then latency. A failed Xray systemd
unit is restarted before changing nodes. If the SOCKS path works but the TUN
policy route is missing, the timer first restarts Xray to restore that route,
with a cooldown between repair attempts. Endpoint probes do not hold the
configuration lock; the lock is taken only while changing the selected server.
A failover pass is scheduled 30 seconds after the previous pass finishes,
preventing back-to-back retries when every endpoint is unavailable. Checks
remain idle after a deliberate `xray-ctl stop`; that command does not trigger
endpoint scans or reconnect the VPN. If upgrading an older Arch installation,
run `sudo xray-ctl-setup "$USER"` again to enable the timer, or run:

```text
sudo systemctl enable --now blancctl-failover.timer
```

To opt out on Arch, disable the timer with `sudo systemctl disable --now
blancctl-failover.timer`; on NixOS set `services.xrayCtl.failover.enable =
false`. Re-running Arch setup enables it again. Switching nodes briefly
interrupts active connections, so this is automatic recovery, not a guarantee
of zero packet loss or a kill switch.

The defaults can be overridden in the failover service environment with
`BLANCCTL_FAILOVER_FAILURES`, `BLANCCTL_FAILOVER_TIMEOUT`, and
`BLANCCTL_FAILOVER_CANDIDATES`.

Commands, subscription refreshes, node probes, live four-site checks, service
restarts, route repairs, failover decisions, and unexpected exceptions are
recorded automatically in `/var/lib/blancctl/events.jsonl`. The journal is
private (`0600`) and rotates at 2 MiB, retaining four older files (about
10 MiB total). Events use UTC timestamps, profile IDs and hashed subscription
names; subscription URLs, VLESS credentials, raw server addresses, and node
labels are not logged there. `xray-ctl log` shows the latest 100 events and
`--lines N` can read the rotated history. Xray's own startup and runtime
messages, plus timer output, remain in systemd's journal and can be read with
`xray-ctl log --service`. Whether older systemd entries survive reboot depends
on the host's journald configuration. Diagnostic files should still be treated
as private when sharing them for troubleshooting.

`start` always enables persistent boot startup, rebuilds the selected
configuration, and performs a clean service restart, including stale failure
and routing cleanup. Selecting a server through `best` or `country` has the
same persistence behavior. A failed subscription
refresh falls back to the last cached node list when one is available.

The subscription URL and generated configurations are stored with mode `0600`
under `/var/lib/blancctl`; the URL is deliberately excluded from the package.
`xray-ctl-setup USER` also configures the system service to run as that user,
while systemd grants Xray only the network capabilities required by the TUN.
Setup repairs ownership and private permissions on existing state files.
Passwordless service authorization is package-owned and therefore survives
setup reruns and is restored by package upgrades; the privileged helper still
accepts commands only from the configured owner's numeric user ID.
Its command-specific authentication default also prevents a later generic
`PASSWD` rule for wheel users from overriding BlancCTL's narrow exemption.
The running service also provides a local SOCKS5 proxy at `127.0.0.1:10808`.
Subscription updates automatically use it, so they do not depend on another VPN.
Proxied UDP on port 443 is rejected so browsers such as Firefox immediately
fall back from QUIC/HTTP3 to reliable HTTP2 over TCP. Other UDP traffic uses
Xray's XUDP transport.
Interactive output uses colors; set `NO_COLOR=1` to disable them.

Run `xray-ctl` only as your normal user. The one-time
`sudo xray-ctl-setup USER` command installs narrowly scoped passwordless rules
for the privileged service helper; `xray-ctl doctor` verifies those rules.
It also rejects stale `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, or `ALL_PROXY`
variables when they point to a closed localhost port. Those variables override
the TUN route in terminal applications and can otherwise make programs such as
Codex look offline even while BlancVPN itself is healthy.
