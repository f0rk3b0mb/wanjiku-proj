from web3 import Web3
import os
from typing import Optional, List, Dict, Any
from web3.exceptions import ContractLogicError, TransactionNotFound

class BlockchainUtils:
    def __init__(self, ganache_url: str = "http://127.0.0.1:8545"):
        """
        Initialize blockchain connection to Ganache.
        
        Args:
            ganache_url (str): URL of the Ganache blockchain node
        """
        self.w3 = Web3(Web3.HTTPProvider(ganache_url))
            
    def store_file_hash(self, contract_address: str, contract_abi: List[Dict[str, Any]], 
                       file_hash: str, account_address: str, private_key: str,
                       certificate_id: str) -> tuple[bool, Optional[str]]:
        """
        Store file hash in the smart contract.
        
        Args:
            contract_address (str): Address of the deployed smart contract
            contract_abi (List[Dict[str, Any]]): ABI of the smart contract
            file_hash (str): Hash of the file to store
            account_address (str): Address of the account sending the transaction
            private_key (str): Private key of the account
            certificate_id (str): ID of the certificate to store
            
        Returns:
            tuple[bool, Optional[str]]: (True if successful, transaction hash) or (False, None)
            
        Raises:
            ValueError: If contract address or account address is invalid
        """
        if not self.w3.is_address(contract_address):
            raise ValueError("Invalid contract address")
        if not self.w3.is_address(account_address):
            raise ValueError("Invalid account address")
            
        try:
            # Ensure contract ABI is properly formatted
            if isinstance(contract_abi, str):
                import json
                contract_abi = json.loads(contract_abi)
            
            contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
            
            # Get the nonce
            nonce = self.w3.eth.get_transaction_count(account_address)
            
            # Get gas price
            gas_price = self.w3.eth.gas_price
            
            # Build transaction
            transaction = contract.functions.issueCertificate(certificate_id, file_hash).build_transaction({
                'from': account_address,
                'chainId': 1337,  # Ganache default chain ID
                'gas': 2000000,
                'gasPrice': gas_price,
                'nonce': nonce,
            })
            
            # Sign transaction with the private key
            signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key=private_key)
            
            # Send the signed transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            
            # Wait for transaction receipt
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            return tx_receipt['status'] == 1, tx_hash.hex()
            
        except ContractLogicError as e:
            print(f"Contract logic error: {str(e)}")
            return False, None
        except TransactionNotFound as e:
            print(f"Transaction not found: {str(e)}")
            return False, None
        except Exception as e:
            print(f"Unexpected error storing file hash in blockchain: {str(e)}")
            return False, None
            
    def get_stored_hash(self, contract_address: str, contract_abi: List[Dict[str, Any]], certificate_id: str) -> Optional[str]:
        """
        Retrieve the stored file hash from the smart contract.
        
        Args:
            contract_address (str): Address of the deployed smart contract
            contract_abi (List[Dict[str, Any]]): ABI of the smart contract
            certificate_id (str): ID of the certificate to retrieve
            
        Returns:
            Optional[str]: Stored file hash if successful, None otherwise
            
        Raises:
            ValueError: If contract address is invalid
        """
        if not self.w3.is_address(contract_address):
            raise ValueError("Invalid contract address")
            
        try:
            contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
            return contract.functions.verifyCertificate(certificate_id).call()
        except ContractLogicError as e:
            print(f"Contract logic error: {str(e)}")
            return None
        except Exception as e:
            print(f"Unexpected error retrieving file hash from blockchain: {str(e)}")
            return None
