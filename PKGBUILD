pkgname=xray-ctl
pkgver=0.6.1
pkgrel=1
pkgdesc='Xray TUN manager with multiple VLESS subscriptions and split tunneling'
arch=('any')
license=('MIT')
depends=('python' 'curl' 'xray' 'sudo' 'iproute2')
provides=('blancctl')
conflicts=('blancctl')
replaces=('blancctl')
source=()
sha256sums=()

package() {
    install -Dm755 "$startdir/app/blancctl.py" "$pkgdir/usr/bin/xray-ctl"
    ln -s xray-ctl "$pkgdir/usr/bin/blancctl"
    install -Dm755 "$startdir/lib/service-control" "$pkgdir/usr/lib/blancctl/service-control"
    install -Dm755 "$startdir/lib/blancctl-setup" "$pkgdir/usr/bin/xray-ctl-setup"
    ln -s xray-ctl-setup "$pkgdir/usr/bin/blancctl-setup"
    install -Dm755 "$startdir/lib/tun-route" "$pkgdir/usr/lib/blancctl/tun-route"
    install -Dm644 "$startdir/systemd/blancctl.service" "$pkgdir/usr/lib/systemd/system/blancctl.service"
    install -Dm644 "$startdir/systemd/blancctl-failover.service" "$pkgdir/usr/lib/systemd/system/blancctl-failover.service"
    install -Dm644 "$startdir/systemd/blancctl-failover.timer" "$pkgdir/usr/lib/systemd/system/blancctl-failover.timer"
    install -Dm440 "$startdir/sudoers/blancctl" "$pkgdir/etc/sudoers.d/blancctl"
    install -Dm644 "$startdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
