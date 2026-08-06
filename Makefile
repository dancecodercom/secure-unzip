BINARY  := secure-unzip

# VERSION.md is the single source of truth, managed by setver
# (github.com/pforret/setver) — bump with 'setver patch|minor|major', never by
# hand-editing here. Bare semver in the file, 'v' prefix everywhere it is shown.
VERSION ?= $(shell tr -d '[:space:]' < VERSION.md 2>/dev/null)
ifeq ($(strip $(VERSION)),)
$(error VERSION.md is missing or empty — expected a bare semver like 0.1.1)
endif
LDFLAGS := -s -w -X main.version=v$(VERSION)

# Release targets (plan A4). bin/ is gitignored; these are the release assets.
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all build build-host version test lint fixtures bench report clean

all: lint test build-host

# What setver last wrote, and therefore what 'make build' will stamp and name.
version:
	@echo v$(VERSION)

build:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" \
			-o bin/$(BINARY)-$$os-$$arch-v$(VERSION)$$ext . || exit 1; \
	done
	@echo "built v$(VERSION) into bin/"

build-host:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

test:
	go test ./...

lint:
	go vet ./...

# Regenerates docs/benchmark/security_report.md
report:
	go test -run TestSecurityReport -v .

# Regenerates the example archives both benchmark harnesses run against.
fixtures:
	python3 benchmark/security/generate_examples.py
	python3 benchmark/performance/generate_examples.py

# Regenerates docs/benchmark/performance_report.md over the whole corpus.
# Run 'make fixtures' first if benchmark/performance/examples/ is empty.
bench: build-host
	bash benchmark/performance/benchmark.sh

clean:
	rm -rf bin
