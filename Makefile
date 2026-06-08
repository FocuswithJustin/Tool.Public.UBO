BINARY := ubo

.PHONY: build run test test-integration vm-build clean fmt vet

build:
	go build -o $(BINARY) .

run:
	go run . $(ARGS)

test:
	go test ./...

# vm-build: download Debian 13 cloud image and prepare tmp/ for integration tests.
# Only needs to run once; results are cached in tmp/.
vm-build:
	bash tests/build-vm.sh

# test-integration: boot the VM and run integration tests against it.
# Requires: make vm-build && make build
test-integration: build
	PROJECT_ROOT=$(CURDIR) go test -v -tags integration -timeout 20m ./tests/

clean:
	rm -f $(BINARY)

fmt:
	gofmt -w .

vet:
	go vet ./...
