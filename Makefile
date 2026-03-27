PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
BINARY = escapes

.PHONY: build install uninstall clean setup

build:
	cargo build --release

install: build
	install -m 4755 -o root target/release/$(BINARY) $(BINDIR)/$(BINARY)
	@echo "Installed $(BINDIR)/$(BINARY) with setuid bit"

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -rf $(PREFIX)/share/openape
	@echo "Removed $(BINDIR)/$(BINARY)"
	@echo "Config (/etc/openape) and logs (/var/log/openape) preserved."
	@echo "Remove manually: sudo rm -rf /etc/openape /var/log/openape"

clean:
	cargo clean

test:
	cargo test

clippy:
	cargo clippy -- -D warnings

setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured (pre-commit: fmt + clippy + test)"
