prefix ?= /usr
.DEFAULT_GOAL := build

SWAG := $(shell command -v swag || echo 'go tool swag')

node_modules: package.json
	npm install

.PHONY: swag
swag:
	$(SWAG) init --generalInfo api.go --output ./assets/ --outputTypes json

.PHONY: prebuild
prebuild: node_modules swag
	node esbuild.config.js

.PHONY: build
build: prebuild
	GOFLAGS='-buildmode=pie' \
	CGO_CPPFLAGS="-D_FORTIFY_SOURCE=3" \
	CGO_LDFLAGS="-Wl,-z,relro,-z,now" \
	go build

.PHONY: install
install: build
	install -Dm 755 drasl "$(prefix)/bin/drasl"
	install -Dm 644 LICENSE "$(prefix)/share/licenses/drasl/LICENSE"
	mkdir -p "$(prefix)/share/drasl/"
	cp -R assets view public locales "$(prefix)/share/drasl/"

.PHONY: clean
clean:
	rm -f drasl
	rm -f swagger.json
	rm -f public/bundle.js

.PHONY: test
test: prebuild
	go test
