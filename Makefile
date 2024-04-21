prefix ?= /usr
.DEFAULT_GOAL := build

npm-install:
	npm install

prebuild: npm-install
	node esbuild.config.js
	swag init --generalInfo api.go --output swagger/

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
	rm drasl
	rm -r public/* public/.*

test: prebuild
	go test
