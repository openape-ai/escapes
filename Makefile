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
	@echo "Removed $(BINDIR)/$(BINARY)"

clean:
	cargo clean

test:
	cargo test

clippy:
	cargo clippy -- -D warnings

setup:
	git config core.hooksPath .githooks
	@echo "Git hooks configured (pre-commit: fmt + clippy + test)"
