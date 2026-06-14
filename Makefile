BINARY := ubo

.PHONY: build run test test-integration vm-build luks-build clean fmt vet complexity check

# Maximum allowed cyclomatic complexity per function (code and tests).
CYCLO_MAX := 6

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

# luks-build: build the LUKS-encrypted server image used by the full remote-unlock
# integration test. Builds entirely inside a builder VM (no host root). Depends on
# vm-build outputs (tmp/debian-trixie.qcow2 + tmp/test_ed25519). Cached in tmp/.
# Runs inside nix-shell so qemu-img/qemu-system-x86_64/xorriso are in PATH.
luks-build:
	nix-shell --run "bash tests/build-luks-vm.sh"

# test-integration: boot the VM(s) and run integration tests against them.
# Requires: make vm-build (and make luks-build for the LUKS/unlock tests).
# Runs inside nix-shell so wg/ssh-keygen are in PATH.
test-integration:
	nix-shell --run "go build -o $(BINARY) . && PROJECT_ROOT=$(CURDIR) go test -v -tags integration -timeout 30m ./tests/"

# complexity: fail if any function (code OR test) exceeds CYCLO_MAX cyclomatic
# complexity. Runs inside nix-shell so gocyclo is on PATH.
complexity:
	@nix-shell --run '\
		out=$$(gocyclo -over $(CYCLO_MAX) .); \
		if [ -n "$$out" ]; then \
			echo "functions over complexity $(CYCLO_MAX):"; \
			echo "$$out"; \
			exit 1; \
		fi; \
		echo "complexity OK: no function exceeds $(CYCLO_MAX)"'

# check: full local gate — formatting, vet, complexity, and unit tests.
check: fmt vet complexity test

clean:
	rm -f $(BINARY)

fmt:
	gofmt -w .

vet:
	go vet ./...
