BINARY := build/aegis
GOLANGCI_LINT ?= golangci-lint

.PHONY: build run test lint generate check-generate fmt tidy clean

build:
	CGO_ENABLED=0 go build -o $(BINARY) .

run:
	go run ./main.go

test:
	go test ./...

lint:
	$(GOLANGCI_LINT) run ./...

generate:
	buf generate

check-generate: generate
	@git diff --exit-code -- internal/rpc/hermes/v1

fmt:
	go fmt ./...

tidy:
	go mod tidy

clean:
	rm -rf build
