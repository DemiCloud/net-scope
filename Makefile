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

.PHONY: build gui test vet release clean

# Default: CLI for the current platform
build:
	mkdir -p build
	go mod tidy
	go build -ldflags "$(LDFLAGS)" -o build/$(NAME) ./cmd/cli

# Windows GUI (cross-compiled from any host)
gui:
	mkdir -p build
	GOOS=windows GOARCH=amd64 go build \
		-ldflags "$(GUI_LDFLAGS)" \
		-o build/$(NAME)-win.exe ./cmd/gui-win

# Run all tests
test:
	go test ./...

# Static analysis
vet:
	go vet ./...

# Release: stripped CLI (linux/amd64, linux/arm64) + Windows GUI
release: clean
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

clean:
	rm -rf build dist
