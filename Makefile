TARGETS := \
    github.com/FuraxFox/malswitch/cmd/subgateway  \
	github.com/FuraxFox/malswitch/cmd/subanalyzer \
	github.com/FuraxFox/malswitch/cmd/exchanger   \
	github.com/FuraxFox/malswitch/cmd/catbrowser \
	github.com/FuraxFox/malswitch/cmd/searchhead \
	github.com/FuraxFox/malswitch/cmd/searchclient \
	github.com/FuraxFox/malswitch/cmd/keygen 


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

keygen: github.com/FuraxFox/malswitch/cmd/keygen
	@echo "keygen built"


search:	github.com/FuraxFox/malswitch/cmd/searchhead 	github.com/FuraxFox/malswitch/cmd/searchclient
	@echo "search built"

subgateway: github.com/FuraxFox/malswitch/cmd/subgateway  
	@echo "subgateway built"

subanalyzer: github.com/FuraxFox/malswitch/cmd/subanalyzer 
	@echo "subanalyzer built"

exchanger: github.com/FuraxFox/malswitch/cmd/exchanger   
	@echo "echanger built"

catbrowser:	github.com/FuraxFox/malswitch/cmd/catbrowser 
	@echo "catbrowser built"
	

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
