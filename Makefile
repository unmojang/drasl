# ==============================================================================
# GLOBAL VARIABLES & KERNEL-LEVEL ENVIRONMENT INJECTION
# ==============================================================================
prefix ?= /usr
.DEFAULT_GOAL := build

# FIX: Elevate env vars to global Make variables to guarantee injection into the Go toolchain process tree
export GOFLAGS     := -buildmode=pie
export CGO_CPPFLAGS := -D_FORTIFY_SOURCE=3
export CGO_LDFLAGS  := -Wl,-z,relro,-z,now

# Dynamically resolve the path of the swag toolchain
SWAG := $(shell command -v swag || echo 'go run github.com/swaggo/swag/cmd/swag@v1.16.4')

# ==============================================================================
# EXPLICIT PHONY TARGETS DECLARATION (Prevents collisions with physical entities)
# ==============================================================================
.PHONY: build prebuild swag npm-install clean test install

# ==============================================================================
# BUILD ROUTING TOPO-MATRIX
# ==============================================================================

# PERFORMANCE OPTIMIZATION: Implement file-timestamp-based dependency tracking
# Triggers 'npm install' only when package.json mutates, mitigating redundant disk I/O
node_modules: package.json
	npm install

npm-install: node_modules

swag:
	$(SWAG) init --generalInfo api.go --output ./assets/ --outputTypes json --exclude node_modules

# Abstract the asset bundling stage as a pre-requisite state
prebuild: node_modules swag
	node esbuild.config.js

# Compilation boundary: 'go build' now securely inherits PIE & RELRO hardening parameters
build: prebuild
	go build

install: build
	install -Dm 755 drasl "$(prefix)/bin/drasl"
	install -Dm 644 LICENSE "$(prefix)/share/licenses/drasl/LICENSE"
	mkdir -p "$(prefix)/share/drasl/"
	cp -R assets view public locales "$(prefix)/share/drasl/"

clean:
	rm -f drasl
	rm -f swagger.json
	rm -f public/bundle.js
	rm -rf node_modules  # Deep purge of localized node artifacts

test: prebuild
	go test