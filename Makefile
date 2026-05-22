BINARY   := sshpot
CMD      := ./cmd/sshpot
PREFIX   := /usr/local
DESTDIR  :=

BUILD_FLAGS := -trimpath -ldflags="-s -w"

.PHONY: all build build-unseal install uninstall lint test clean

all: build

build:
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BINARY) $(CMD)

build-unseal:
	CGO_ENABLED=0 go build $(BUILD_FLAGS) -o sshpot-unseal ./cmd/sshpot-unseal

install: build
	install -m 755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	@if [ -z "$(DESTDIR)" ] && [ "$$(id -u)" -ne 0 ]; then \
		echo "install requires root privileges" >&2; \
		exit 1; \
	fi
	@if ! getent group sshpot >/dev/null; then \
		groupadd --system sshpot; \
	fi
	@if ! getent passwd sshpot >/dev/null; then \
		useradd --system --gid sshpot --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sshpot; \
	fi
	install -d -m 750 $(DESTDIR)/etc/sshpot
	install -d -m 755 $(DESTDIR)/etc/fail2ban/filter.d
	install -d -m 755 $(DESTDIR)/etc/fail2ban/jail.d
	install -d -m 755 $(DESTDIR)/etc/fail2ban/action.d
	install -d -m 755 $(DESTDIR)/etc/logrotate.d
	install -d -m 755 $(DESTDIR)/etc/sshpot
	install -d -m 750 -o sshpot -g sshpot $(DESTDIR)/var/log/sshpot
	install -m 640 /dev/null $(DESTDIR)/var/log/sshpot/logins.csv
	chown sshpot:sshpot $(DESTDIR)/var/log/sshpot/logins.csv
	chmod 640 $(DESTDIR)/var/log/sshpot/logins.csv
	@if [ ! -f $(DESTDIR)/etc/sshpot/config.toml ]; then \
		install -m 640 configs/config.toml $(DESTDIR)/etc/sshpot/config.toml; \
		echo "Installed default config to $(DESTDIR)/etc/sshpot/config.toml"; \
	else \
		echo "Config already exists, skipping ($(DESTDIR)/etc/sshpot/config.toml)"; \
	fi
	@if [ ! -f $(DESTDIR)/etc/sshpot/output_text.txt ]; then \
		install -m 644 configs/output_text.txt $(DESTDIR)/etc/sshpot/output_text.txt; \
		echo "Installed output text to $(DESTDIR)/etc/sshpot/output_text.txt"; \
	else \
		echo "Output text already exists, skipping ($(DESTDIR)/etc/sshpot/output_text.txt)"; \
	fi
	install -m 644 contrib/fail2ban/filter.d/sshpot.conf $(DESTDIR)/etc/fail2ban/filter.d/sshpot.conf
	install -m 644 sshpot.service $(DESTDIR)/etc/systemd/system/sshpot.service
	install -m 644 contrib/fail2ban/jail.d/sshpot.conf $(DESTDIR)/etc/fail2ban/jail.d/sshpot.conf
	install -m 644 contrib/fail2ban/action.d/abuseipdb.conf $(DESTDIR)/etc/fail2ban/action.d/abuseipdb.conf
	install -m 644 contrib/logrotate/sshpot $(DESTDIR)/etc/logrotate.d/sshpot
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload; \
		systemctl enable --now sshpot; \
		echo "Enabled and started sshpot via systemd"; \
	else \
		echo "Staged install complete; run systemctl daemon-reload && systemctl enable --now sshpot on the target system."; \
	fi
	@echo ""
	@echo "To finish setup:"
	@echo "  1. Edit /etc/sshpot/config.toml"
	@echo "  2. Set /etc/fail2ban/fail2ban.local abuseipdb_apikey if you use AbuseIPDB reporting"
	@echo "  3. If you used DESTDIR, run: systemctl daemon-reload && systemctl enable --now sshpot"

uninstall:
	@if [ -z "$(DESTDIR)" ]; then \
		if [ "$$(id -u)" -ne 0 ]; then \
			echo "uninstall requires root privileges" >&2; \
			exit 1; \
		fi; \
		systemctl disable --now sshpot 2>/dev/null || true; \
		systemctl daemon-reload; \
	fi
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)/etc/systemd/system/sshpot.service
	rm -f $(DESTDIR)/etc/fail2ban/filter.d/sshpot.conf
	rm -f $(DESTDIR)/etc/fail2ban/jail.d/sshpot.conf
	rm -f $(DESTDIR)/etc/fail2ban/action.d/abuseipdb.conf
	rm -f $(DESTDIR)/var/log/sshpot/logins.csv
	rm -f $(DESTDIR)/etc/logrotate.d/sshpot
	rm -f $(DESTDIR)/etc/sshpot/output_text.txt

lint:
	go vet ./...

test:
	go test -race ./...

clean:
	rm -f $(BINARY)
