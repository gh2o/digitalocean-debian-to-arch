PKGNAME = $(shell grep ^pkgname PKGBUILD | sed -e 's:.*=::')
PKGVER  = $(shell grep ^pkgver PKGBUILD | sed -e 's:.*=::')
PKGREL  = $(shell grep ^pkgrel PKGBUILD | sed -e 's:.*=::')
PKGARCH = $(shell grep ^arch PKGBUILD | sed -e 's:.*=::')

PKG     = $(PKGNAME)-$(PKGVER)-$(PKGREL)-$(PKGARCH).pkg.tar.xz
PKG_SRC = $(PKGNAME)-$(PKGVER)-$(PKGREL).src.tar.gz

DEPS    = digitalocean-synchronize \
		  digitalocean-synchronize.service \
		  digitalocean-synchronize.install \
		  PKGBUILD \
		  Makefile

install.pkg.sh: $(PKG)
	@cat $(subst .pkg,,$@) > $@
	@echo -e '\ncat <<EMBEDDED\n\n!!!!digitalocean-synchronize.pkg.tar.xz' >> $@
	@base64 $< >> $@
	@echo -e '!!!!\n\nEMBEDDED' >> $@

	$(info Build complete!)
	$(info Output file: $@)

$(PKG): $(DEPS)
	updpkgsums
	mksrcinfo
	makepkg -fc

clean:
	rm -f $(PKG) install.pkg.sh