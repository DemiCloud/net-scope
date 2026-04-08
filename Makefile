# Project metadata
NAME    := net-scope
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
OUI_URL := https://maclookup.app/downloads/json-database/get-db?version=latest

# Linker flags
DEV_LDFLAGS     := -X main.version=$(VERSION)
RELEASE_LDFLAGS := -s -w -X main.version=$(VERSION)

# Output naming convention: net-scope_<os>_<arch>[.exe]
cli_out  = build/$(NAME)_$(1)_$(2)$(if $(filter windows,$(1)),.exe,)

.PHONY: help linux windows bsd all test vet release clean

## ── Dev shortcuts ────────────────────────────────────────────────────────────

help: ## Show this help
	@echo "net-scope $(VERSION)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

## ── Platform targets (dev builds, unstripped) ────────────────────────────────

linux: fetch-oui ## Build unified binary for linux/amd64 → build/
	mkdir -p build
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-tags with_oui -ldflags "$(DEV_LDFLAGS)" -o $(call cli_out,linux,amd64) ./cmd/net-scope

windows: gen-resources fetch-oui ## Cross-compile unified binary for windows/amd64 → build/
	mkdir -p build
	GOOS=windows GOARCH=amd64 go build \
		-tags with_oui -ldflags "$(DEV_LDFLAGS)" -o $(call cli_out,windows,amd64) ./cmd/net-scope

fetch-oui: ## Download OUI JSON database for embedding (requires internet)
	@if [ ! -f internal/scan/oui.json ] || [ $$(wc -c < internal/scan/oui.json) -lt 1000 ]; then \
		echo "Fetching OUI database…"; \
		curl -fsSL --max-time 60 '$(OUI_URL)' -o internal/scan/oui.json \
			&& echo "OUI: $$(wc -c < internal/scan/oui.json) bytes" \
			|| (echo "OUI download failed — build will use stub (no vendor lookup)"; exit 1); \
	else \
		echo "OUI: using cached internal/scan/oui.json ($$(wc -c < internal/scan/oui.json) bytes)"; \
	fi

gen-resources: ## Generate icon.ico + resource_windows_amd64.syso for GUI
	go run ./cmd/gen-ico/ -o cmd/gui-win/icon.ico
	go run ./cmd/gen-rsrc/ -dir cmd/gui-win

bsd: fetch-oui ## Cross-compile unified binary for freebsd/amd64 (OPNsense) → build/
	mkdir -p build
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build \
		-tags with_oui -ldflags "$(DEV_LDFLAGS)" -o $(call cli_out,freebsd,amd64) ./cmd/cli

all: linux windows bsd ## Build all platforms → build/

## ── Tests ────────────────────────────────────────────────────────────────────

test: ## Run all tests
	go test ./...

vet: ## Run go vet
	go vet ./...

## ── Release (stripped, trimpath, sha256 manifest) ───────────────────────────

release: clean fetch-oui ## Build all platforms stripped → dist/ + checksums.txt
	mkdir -p dist
	go mod tidy
	@set -e; \
	build_cli() { \
		os=$$1 arch=$$2; \
		ext=$$([ "$$os" = "windows" ] && echo ".exe" || echo ""); \
		out=dist/$(NAME)_$${os}_$${arch}$${ext}; \
		echo "  cli  $$os/$$arch → $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -trimpath \
			-tags with_oui -ldflags "$(RELEASE_LDFLAGS)" -o $$out ./cmd/net-scope; \
	}; \
	echo "==> Linux"; \
	build_cli linux amd64; \
	build_cli linux arm64; \
	echo "==> Windows"; \
	build_cli windows amd64; \
	echo "==> FreeBSD (OPNsense)"; \
	build_cli freebsd amd64; \
	echo "==> Packaging"; \
	cd dist && \
	for f in $(NAME)_linux_amd64 $(NAME)_linux_arm64 $(NAME)_freebsd_amd64; do \
		cp $$f $(NAME) && tar -czf $${f}.tar.gz $(NAME) && rm $(NAME); \
		echo "  $$f.tar.gz"; \
	done && \
	zip -q $(NAME)_windows_amd64.zip $(NAME)_windows_amd64.exe && \
	echo "  $(NAME)_windows_amd64.zip" && \
	rm $(NAME)_linux_amd64 $(NAME)_linux_arm64 $(NAME)_freebsd_amd64 $(NAME)_windows_amd64.exe
	@echo "==> Checksums"
	cd dist && sha256sum * > checksums.txt && cat checksums.txt

clean: ## Remove build/ and dist/
	rm -rf build dist

refresh-oui: ## Force re-download of OUI database (ignores cached file)
	rm -f internal/scan/oui.json
	$(MAKE) fetch-oui
