{
  lib,
  stdenvNoCC,
  makeWrapper,
  bash,
  coreutils,
  curl,
  iproute2,
  python3,
  systemd,
  xray,
}:

stdenvNoCC.mkDerivation (finalAttrs: {
  pname = "xray-ctl";
  version = "0.6.2";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../app/blancctl.py
      ../lib/service-control
      ../lib/tun-route
    ];
  };

  nativeBuildInputs = [ makeWrapper bash python3 ];
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    install -Dm755 app/blancctl.py "$out/bin/xray-ctl"
    install -Dm755 lib/service-control "$out/libexec/blancctl/service-control"
    install -Dm755 lib/tun-route "$out/libexec/blancctl/tun-route"

    substituteInPlace "$out/bin/xray-ctl" \
      --replace-fail 'CONTROL = "/usr/lib/blancctl/service-control"' \
                     "CONTROL = \"$out/libexec/blancctl/service-control\""
    substituteInPlace "$out/libexec/blancctl/service-control" \
      --replace-fail /usr/bin/systemctl ${systemd}/bin/systemctl \
      --replace-fail /usr/bin/journalctl ${systemd}/bin/journalctl

    patchShebangs "$out/bin" "$out/libexec"

    wrapProgram "$out/bin/xray-ctl" \
      --prefix PATH : ${lib.makeBinPath [ curl iproute2 systemd xray ]}
    ln -s xray-ctl "$out/bin/blancctl"
    wrapProgram "$out/libexec/blancctl/service-control" \
      --prefix PATH : ${lib.makeBinPath [ coreutils systemd ]}
    wrapProgram "$out/libexec/blancctl/tun-route" \
      --prefix PATH : ${lib.makeBinPath [ coreutils iproute2 ]}

    runHook postInstall
  '';

  doInstallCheck = true;
  installCheckPhase = ''
    "$out/bin/xray-ctl" --version | grep -F 'xray-ctl ${finalAttrs.version}'
  '';

  meta = {
    description = "Xray TUN manager with multiple VLESS subscriptions and split tunneling";
    license = lib.licenses.mit;
    mainProgram = "xray-ctl";
    platforms = lib.platforms.linux;
  };
})
