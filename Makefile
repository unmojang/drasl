prefix ?= /usr/local
.DEFAULT_GOAL := build

prebuild:
	npm install
	node esbuild.config.js
	cp css/style.css public/

build: prebuild
	go build

install: build
	install -Dm 755 drasl "$(prefix)/bin/drasl"
	mkdir -p "$(prefix)/share/drasl/"
	cp -R assets view public "$(prefix)/share/drasl/"

clean:
	rm drasl
	rm -r public/* public/.*
