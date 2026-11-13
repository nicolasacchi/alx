PREFIX ?= $(HOME)/bin

.PHONY: build install uninstall

build:
	cargo build --release

install: build
	mkdir -p $(PREFIX)
	cp target/release/alx $(PREFIX)/alx
	@echo "Installed alx to $(PREFIX)/alx"
	@echo "Make sure $(PREFIX) is on your PATH"

uninstall:
	rm -f $(PREFIX)/alx
	@echo "Removed $(PREFIX)/alx"
