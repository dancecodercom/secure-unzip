BINARY  := secure-unzip
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Release targets (plan A4). bin/ is gitignored; these are the release assets.
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all build build-host test lint fixtures bench report clean

all: lint test build-host

build:
	@mkdir -p bin
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" \
			-o bin/$(BINARY)-$$os-$$arch$$ext . || exit 1; \
	done
	@echo "built $(VERSION) into bin/"

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
