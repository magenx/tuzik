BINARY   := tuzik
PREFIX   ?= /usr/local
SBINDIR  ?= $(PREFIX)/sbin
CONFDIR  ?= /etc/tuzik

GO       := go
GOFLAGS  := -trimpath
CGO_ENABLED := 0

.PHONY: all build install uninstall test clean

all: build

build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -o $(BINARY) .

install: build
	install -D -m 0750 $(BINARY) $(DESTDIR)$(SBINDIR)/$(BINARY)
	install -D -m 0640 config.yaml $(DESTDIR)$(CONFDIR)/config.yaml

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/$(BINARY)
	rm -rf $(DESTDIR)$(CONFDIR)

test:
	$(GO) test -v ./...

clean:
	rm -f $(BINARY)
