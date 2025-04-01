from web3 import Web3
import json

# Connect to Ganache
GANACHE_URL = "http://127.0.0.1:7545"
web3 = Web3(Web3.HTTPProvider(GANACHE_URL))

# Load contract ABI & Bytecode
with open("./FileStorage.abi") as f:
    contract_abi = json.load(f)
with open("./FileStorage.bin") as f:
    contract_bytecode = f.read()

# Use the first account from Ganache as the contract owner
account = web3.eth.accounts[0]

# Deploy contract
CertificateVerification = web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = CertificateVerification.constructor().transact({"from": account})
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

# Get contract address
contract_address = tx_receipt.contractAddress
print(f"✅ Contract Deployed Successfully!")
print(f"🔗 Contract Address: {contract_address}")
