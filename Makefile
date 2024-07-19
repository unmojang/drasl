prefix ?= /usr
.DEFAULT_GOAL := build

npm-install:
	npm install

swag:
	swag init --generalInfo api.go --output . --outputTypes json

prebuild: npm-install swag
	node esbuild.config.js

build: prebuild
	export GOFLAGS='-buildmode=pie'
	export CGO_CPPFLAGS="-D_FORTIFY_SOURCE=3"
	export CGO_LDFLAGS="-Wl,-z,relro,-z,now"
	go build

install: build
	install -Dm 755 drasl "$(prefix)/bin/drasl"
	install -Dm 644 LICENSE "$(prefix)/share/licenses/drasl/LICENSE"
	mkdir -p "$(prefix)/share/drasl/"
	cp -R assets view public "$(prefix)/share/drasl/"

clean:
	rm -f drasl
	rm -f swagger.json
	rm -f public/bundle.js

test: prebuild
	go test
