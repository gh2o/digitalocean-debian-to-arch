# Maintainer: Gavin Li
# Contributor: Kyle Manna <kyle at kylemanna dot com>

pkgname=digitalocean-synchronize
pkgver=2.6
pkgrel=1
pkgdesc='DigitalOcean Synchronization (passwords, keys, networks)'
url='https://github.com/gh2o/digitalocean-debian-to-arch'

arch=(any)
license=(GPL)
options=(!strip)

depends=(wget)

source=(digitalocean-synchronize.sh
        digitalocean-synchronize.service
        90-dosync-virtio-no-rename.link)

sha256sums=('37261e4f5a79a5308e8e94925a037cc2e3d13fa5a473f6fc9b57bed07c06ed5d'
            '0e51944270c52293f81ea63cb73af42f93341009ddf714ca3a7afe9d4d15a2a8'
            'd85cde96e602a4ff296d18a7769c683a66feffe5db35a03cdeab651922681f85')

package() {
    install -Dm755 digitalocean-synchronize.sh ${pkgdir}/usr/bin/digitalocean-synchronize
    install -Dm644 digitalocean-synchronize.service ${pkgdir}/usr/lib/systemd/system/digitalocean-synchronize.service
    install -Dm644 90-dosync-virtio-no-rename.link ${pkgdir}/usr/lib/systemd/network/90-dosync-virtio-no-rename.link

    local wantsdir=${pkgdir}/usr/lib/systemd/system/multi-user.target.wants
    install -dm755 ${wantsdir}
    ln -s ../digitalocean-synchronize.service ${wantsdir}/
}
