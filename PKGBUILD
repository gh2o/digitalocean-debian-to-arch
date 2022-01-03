# Maintainer: Gavin Li
# Contributor: Kyle Manna <kyle at kylemanna dot com>

pkgname=digitalocean-synchronize
pkgver=2.7
pkgrel=2
pkgdesc='DigitalOcean Synchronization (passwords, keys, networks)'
url='https://github.com/gh2o/digitalocean-debian-to-arch'

arch=(any)
license=(GPL)
options=(!strip)

depends=(
  curl  # For requests to metadata service
)

source=(digitalocean-synchronize.sh
        digitalocean-synchronize.service
        90-dosync-virtio-no-rename.link)

sha256sums=('4b657d5fb413180bb1d5e513e8e466d8388ff935ef27e048c70fd34220a164d2'
            '25e28f7b3351662b8e2da71aee38a1131df2568177e676e49f47a75d33894d64'
            'd85cde96e602a4ff296d18a7769c683a66feffe5db35a03cdeab651922681f85')

package() {
    install -Dm755 digitalocean-synchronize.sh ${pkgdir}/usr/bin/digitalocean-synchronize
    install -Dm644 digitalocean-synchronize.service ${pkgdir}/usr/lib/systemd/system/digitalocean-synchronize.service
    install -Dm644 90-dosync-virtio-no-rename.link ${pkgdir}/usr/lib/systemd/network/90-dosync-virtio-no-rename.link

    local wantsdir=${pkgdir}/usr/lib/systemd/system/multi-user.target.wants
    install -dm755 ${wantsdir}
    ln -s ../digitalocean-synchronize.service ${wantsdir}/
}
