from solcx import compile_source, install_solc
import json

# Install the Solidity compiler
install_solc("0.8.0")

# Load the contract source
with open("../contracts/FileStorage.sol", "r") as f:
    contract_source = f.read()

# Compile the contract
compiled_sol = compile_source(contract_source, solc_version="0.8.0")

# Extract the contract ABI and Bytecode
contract_id, contract_interface = compiled_sol.popitem()

# Save ABI and Bytecode to files
with open("FileStorage.abi", "w") as abi_file:
    json.dump(contract_interface["abi"], abi_file)

with open("FileStorage.bin", "w") as bin_file:
    bin_file.write(contract_interface["bin"])

print("Contract ABI and Bytecode generated successfully!")
