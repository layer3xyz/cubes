-include .env

.PHONY: deploy test coverage build deploy_proxy fork_test

DEFAULT_ANVIL_PRIVATE_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

install:; forge install
build:; forge build
test :; forge clean && forge test --ffi
coverage :; forge coverage --ffi --report debug > coverage-report.txt
snapshot :; forge snapshot --ffi

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_PRIVATE_KEY) --broadcast

# Goerli
ifeq ($(findstring --network goerli,$(ARGS)),--network goerli)
	NETWORK_ARGS := --rpc-url $(GOERLI_RPC_ENDPOINT) --private-key $(PRIVATE_KEY) --verify --etherscan-api-key $(ETHERSCAN_API_KEY) --broadcast -vvvv
endif

# Base
ifeq ($(findstring --network op_sepolia,$(ARGS)),--network op_sepolia)
	NETWORK_ARGS := --rpc-url https://sepolia.optimism.io --account baseSepolia --broadcast -vvvv
endif

# Base Sepolia
ifeq ($(findstring --network base_sepolia,$(ARGS)),--network base_sepolia)
	NETWORK_ARGS := --rpc-url $(BASE_SEPOLIA_RPC_ENDPOINT) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif

deploy:
	@forge script script/DeployCube.s.sol:DeployCube $(NETWORK_ARGS)

deploy_proxy:
	@forge script script/DeployProxy.s.sol:DeployProxy $(NETWORK_ARGS) --ffi

upgrade_proxy:
	@forge script script/UpgradeCube.s.sol:UpgradeCube $(NETWORK_ARGS) --ffi

fork_test:
	@forge test --rpc-url $(RPC_ENDPOINT) -vvv