-include .env

.PHONY: deploy test coverage build

DEFAULT_ANVIL_PRIVATE_KEY := 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

build:; forge build
test :; forge test 
coverage :; forge coverage --report debug > coverage-report.txt
snapshot :; forge snapshot

NETWORK_ARGS := --rpc-url http://localhost:8545 --private-key $(DEFAULT_ANVIL_PRIVATE_KEY) --broadcast
MUMBAI_RPC_ENDPOINT := https://polygon-mumbai.g.alchemy.com/v2/fb3CvnodOHZmfiAE8TGIzq9N83Tx24Va

ifeq ($(findstring --network goerli,$(ARGS)),--network goerli)
	NETWORK_ARGS := --rpc-url $(RPC_ENDPOINT) --private-key $(PRIVATE_KEY) --broadcast -vvvv
endif
# when contract is ready, add `--verify --etherscan-api-key $(ETHERSCAN_API_KEY)`

deploy:
	@forge script script/DeployCube.s.sol:DeployCube $(NETWORK_ARGS)

deploy_proxy:
	@forge script script/DeployProxy.s.sol:DeployProxy $(NETWORK_ARGS)