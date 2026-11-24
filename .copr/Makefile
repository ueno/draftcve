CRATE = draftcve
VERSION = 0.1.0

target/package/$(CRATE)-$(VERSION).crate:
	cargo package

$(CRATE)-$(VERSION)-vendor.tar.xz: target/package/$(CRATE)-$(VERSION).crate
	cargo package
	tar xf target/package/$(CRATE)-$(VERSION).crate
	(cd $(CRATE)-$(VERSION) && \
	cargo vendor-filterer --platform x86_64-unknown-linux-gnu \
                      --platform powerpc64le-unknown-linux-gnu \
                      --platform aarch64-unknown-linux-gnu \
                      --platform i686-unknown-linux-gnu \
                      --platform s390x-unknown-linux-gnu \
                      --all-features && \
	tar jcf ../$@ vendor)

srpm: $(CRATE).spec $(CRATE)-$(VERSION)-vendor.tar.xz
	dnf -y install cargo tito
	tito build --builder=SomeBuilder --test --srpm --output=$(outdir)
