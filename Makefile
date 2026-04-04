# Project metadata
NAME     := net-sweep
VERSION  := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
BUILT_BY ?= DemiCloud

# Base linker flags (dev builds)
LDFLAGS :=

# Release linker flags (strip + trim)
RELEASE_LDFLAGS := -s -w

# Windows GUI needs -H windowsgui to suppress the console window
GUI_LDFLAGS := -H windowsgui $(RELEASE_LDFLAGS)

.PHONY: help build gui test vet release clean

# Default target — list available commands
help:
	@echo "net-sweep $(VERSION)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Build CLI for the current platform → build/net-sweep
	mkdir -p build
	go mod tidy
	go build -ldflags "$(LDFLAGS)" -o build/$(NAME) ./cmd/cli

gui: ## Cross-compile Windows GUI → build/net-sweep-win.exe
	mkdir -p build
	GOOS=windows GOARCH=amd64 go build \
		-ldflags "$(GUI_LDFLAGS)" \
		-o build/$(NAME)-win.exe ./cmd/gui-win

test: ## Run all tests
	go test ./...

vet: ## Run go vet (static analysis)
	go vet ./...

release: clean ## Build stripped multi-arch release tarballs → dist/
	mkdir -p dist
	go mod tidy
	@set -e; for platform in linux/amd64 linux/arm64; do \
		OS=$$(echo $$platform | cut -d/ -f1); \
		ARCH=$$(echo $$platform | cut -d/ -f2); \
		echo "building $$OS/$$ARCH"; \
		GOOS=$$OS GOARCH=$$ARCH CGO_ENABLED=0 go build -trimpath \
			-ldflags "$(RELEASE_LDFLAGS)" \
			-o dist/$(NAME) ./cmd/cli; \
		tar -czf dist/$(NAME)_$(VERSION)_$${OS}_$${ARCH}.tar.gz -C dist $(NAME); \
		rm dist/$(NAME); \
	done
	@echo "building windows/amd64 (gui)"
	GOOS=windows GOARCH=amd64 go build -trimpath \
		-ldflags "$(GUI_LDFLAGS)" \
		-o dist/$(NAME)-win.exe ./cmd/gui-win
	tar -czf dist/$(NAME)_$(VERSION)_windows_amd64.tar.gz -C dist $(NAME)-win.exe
	rm dist/$(NAME)-win.exe
	cd dist && sha256sum *.tar.gz > checksums.txt

clean: ## Remove build/ and dist/
	rm -rf build dist
