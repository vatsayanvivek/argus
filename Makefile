.PHONY: build build-all test vet lint clean install run embed-prep windows-installer windows-versioninfo docker docker-push

VERSION ?= 1.0.0
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

# Go's //go:embed directive cannot reference parent directories ("..").
# We mirror the canonical policies/ and data/ trees into the package
# directories that own the embed directives.
embed-prep:
	@rm -rf internal/engine/policies internal/benchmark/data internal/reporter/templates
	@mkdir -p internal/engine internal/benchmark internal/reporter
	@cp -R policies internal/engine/policies
	@cp -R data internal/benchmark/data
	@mkdir -p internal/reporter/templates
	@cp templates/report.html internal/reporter/templates/report.html
	@cp data/azure_builtin_roles.json internal/drift/builtin_roles.json

# Regenerate cmd/resource_windows_amd64.syso from scripts/versioninfo.json.
# Run this after bumping VERSION so the Windows exe's embedded Company /
# Product / FileVersion / Copyright strings reflect the new release.
# Requires the `goversioninfo` tool on PATH (go install fetches it).
windows-versioninfo:
	@command -v goversioninfo >/dev/null 2>&1 || go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest
	@goversioninfo -64 -o cmd/resource_windows_amd64.syso scripts/versioninfo.json
	@echo "Regenerated cmd/resource_windows_amd64.syso"

build: embed-prep
	go build $(LDFLAGS) -o argus ./main.go

build-all: embed-prep windows-versioninfo
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/argus-linux-amd64 ./main.go
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/argus-darwin-amd64 ./main.go
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/argus-darwin-arm64 ./main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/argus-windows-amd64.exe ./main.go

test:
	go test ./... -v

vet:
	go vet ./...

lint:
	golangci-lint run ./... || true

install: build
	install -m 755 argus /usr/local/bin/argus

run: build
	./argus --help

clean:
	rm -rf dist/ argus argus-output/ argus-evidence*/ scripts/dist/

# Builds the Docker image locally. Tag defaults to argus:local for
# quick iteration; release images are tagged via the CI workflow.
docker:
	docker build --build-arg VERSION=$(VERSION) -t argus:local -t argus:$(VERSION) .
	@echo "Built argus:local and argus:$(VERSION)"
	@echo "Try: docker run --rm argus:local --version"

# Pushes to ghcr.io. Requires `docker login ghcr.io` + a PAT with
# write:packages scope. Mostly used by the release workflow, but
# available for manual runs during emergency releases.
docker-push: docker
	docker tag argus:$(VERSION) ghcr.io/vatsayanvivek/argus:$(VERSION)
	docker tag argus:$(VERSION) ghcr.io/vatsayanvivek/argus:latest
	docker push ghcr.io/vatsayanvivek/argus:$(VERSION)
	docker push ghcr.io/vatsayanvivek/argus:latest

# Builds the Windows GUI installer (argus-setup.exe) via NSIS.
# Requires: makensis in PATH (brew install makensis on macOS).
# Depends on dist/argus-windows-amd64.exe existing — run `make build-all` first.
windows-installer: build-all
	@command -v makensis >/dev/null 2>&1 || { echo "makensis not found. Install with: brew install makensis"; exit 1; }
	@mkdir -p scripts/dist
	@cd scripts && makensis -V1 argus-installer.nsi
	@echo "Built scripts/dist/argus-setup.exe"
