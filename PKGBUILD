# Maintainer: Gavin Li
# Contributor: Kyle Manna <kyle at kylemanna dot com>

pkgname=digitalocean-synchronize
pkgver=2.4
pkgrel=2
pkgdesc='DigitalOcean Synchronization (passwords, keys, networks)'
url='https://github.com/gh2o/digitalocean-debian-to-arch'
arch=any
license=GPL
install=digitalocean-synchronize.install

source=('digitalocean-synchronize'
        'digitalocean-synchronize.service')

sha256sums=('2115bcf34d80186103e4399f5a20d410145ee50d316a67bdfe6f43c4b11d2064'
            '5888d367a08604b17528d58aa26050209d8ececf7ed35f90b5e96b31165b6a1c')

package() {
    install -Dm755 digitalocean-synchronize ${pkgdir}/usr/bin/digitalocean-synchronize
    install -Dm644 digitalocean-synchronize.service ${pkgdir}/usr/lib/systemd/system/digitalocean-synchronize.service
}
