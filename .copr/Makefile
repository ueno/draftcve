CRATE = draftcve
VERSION = 0.1.0
DEPENDENCIES = cargo cargo-vendor-filterer rpkg

.PHONY: prep

prep:
	rpm -qi $(DEPENDENCIES) || dnf -y install $(DEPENDENCIES)

$(CRATE)-$(VERSION).crate: prep
	cargo package && mv target/package/$@ $@

$(CRATE)-$(VERSION)-vendor.tar.xz: $(CRATE)-$(VERSION).crate
	tar xf $< && \
	(cd $(CRATE)-$(VERSION) && \
	cargo vendor-filterer --platform x86_64-unknown-linux-gnu \
                      --platform powerpc64le-unknown-linux-gnu \
                      --platform aarch64-unknown-linux-gnu \
                      --platform i686-unknown-linux-gnu \
                      --platform s390x-unknown-linux-gnu \
                      --all-features && \
	tar jcf ../$@ vendor)

srpm: $(CRATE).spec $(CRATE)-$(VERSION)-vendor.tar.xz
	rpkg srpm --outdir=$(outdir)
	outdir="$(outdir)/"; \
	rm -f $${outdir}$(CRATE)-$(VERSION).crate $${outdir}$(CRATE)-$(VERSION)-vendor.tar.xz
