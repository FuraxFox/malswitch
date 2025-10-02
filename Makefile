TARGETS := \
    github.com/FuraxFox/malswitch/cmd/subgateway  \
	github.com/FuraxFox/malswitch/cmd/subanalyzer \
	github.com/FuraxFox/malswitch/cmd/exchanger   \
	github.com/FuraxFox/malswitch/cmd/catbrowser

.PHONY: all clean test lint

# Set the Go binary
GOBIN := $(shell go env GOBIN)

# Set the build directory
BUILD_DIR := build

# Build all targets
all: $(TARGETS)

# Build a specific target
$(TARGETS):
	@echo "building $@ : $(notdir $@)"
	go build -o $(BUILD_DIR)/$(notdir $@) $@

# Run tests for all targets
test: test_$(TARGETS)

# Run tests for a specific target
test_%:
	go test -v $(BUILD_DIR)/$(basename $(subst test_,,$@))

# Clean the build directory
clean:
	rm -rf $(BUILD_DIR)

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
