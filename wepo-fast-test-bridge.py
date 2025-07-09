#!/usr/bin/env python3
"""
WEPO Fast Test Blockchain Bridge
Instant blockchain for testing functionality
"""

import time
import hashlib
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

class FastTestBlockchain:
    """Fast test blockchain with instant operations"""
    
    def __init__(self):
        self.blocks = []
        self.transactions = {}
        self.mempool = {}
        self.utxos = {}
        self.wallets = {}
        
        # Create instant genesis block
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create instant genesis block"""
        genesis_tx = {
            "txid": "genesis_coinbase_tx",
            "inputs": [],
            "outputs": [{
                "address": "wepo1genesis0000000000000000000000",
                "value": 40000000000,  # 400 WEPO in satoshis
            }],
            "timestamp": int(time.time()),
            "type": "coinbase"
        }
        
        genesis_block = {
            "height": 0,
            "hash": "000000genesis000000000000000000000000000000000000000000000000000",
            "prev_hash": "0" * 64,
            "merkle_root": hashlib.sha256("genesis".encode()).hexdigest(),
            "timestamp": int(time.time()),
            "nonce": 12345,
            "difficulty": 1,
            "transactions": [genesis_tx["txid"]],
            "reward": 40000000000
        }
        
        self.blocks.append(genesis_block)
        self.transactions[genesis_tx["txid"]] = genesis_tx
        self.utxos[f"{genesis_tx['txid']}:0"] = genesis_tx["outputs"][0]
        
        print("⚡ INSTANT test genesis block created!")
        print(f"   Block hash: {genesis_block['hash']}")
        print(f"   Genesis reward: 400 WEPO")
        print(f"   Genesis UTXO: {genesis_tx['outputs'][0]['address']}")
    
    def get_balance(self, address):
        """Calculate balance for address"""
        balance = 0
        for utxo_key, utxo in self.utxos.items():
            if utxo["address"] == address:
                balance += utxo["value"]
        return balance / 100000000.0  # Convert to WEPO
    
    def get_transactions(self, address):
        """Get transactions for address"""
        result = []
        for tx in self.transactions.values():
            # Check if address is involved
            involved = False
            tx_type = "unknown"
            amount = 0
            
            for output in tx["outputs"]:
                if output["address"] == address:
                    involved = True
                    tx_type = "receive"
                    amount = output["value"] / 100000000.0
                    break
            
            if involved:
                result.append({
                    "txid": tx["txid"],
                    "type": tx_type,
                    "amount": amount,
                    "from_address": "coinbase" if tx.get("type") == "coinbase" else "unknown",
                    "to_address": address,
                    "timestamp": tx["timestamp"],
                    "status": "confirmed",
                    "confirmations": len(self.blocks),
                    "block_height": 0 if tx.get("type") == "coinbase" else None
                })
        
        return result
    
    def create_transaction(self, from_address, to_address, amount):
        """Create a test transaction"""
        txid = f"tx_{int(time.time())}_{hash(from_address + to_address)}"
        
        tx = {
            "txid": txid,
            "inputs": [{"address": from_address, "amount": amount}],
            "outputs": [{
                "address": to_address,
                "value": int(amount * 100000000)  # Convert to satoshis
            }],
            "timestamp": int(time.time()),
            "type": "transfer"
        }
        
        self.mempool[txid] = tx
        print(f"⚡ Test transaction created: {amount} WEPO from {from_address} to {to_address}")
        return txid
    
    def mine_block(self):
        """Instantly mine a block with mempool transactions"""
        if not self.mempool:
            print("⚠️ No transactions in mempool")
            return None
        
        height = len(self.blocks)
        prev_hash = self.blocks[-1]["hash"]
        
        # Calculate reward based on WEPO tokenomics
        if height <= 13140:  # Q1 
            reward = 40000000000  # 400 WEPO
        elif height <= 26280:  # Q2
            reward = 20000000000  # 200 WEPO  
        elif height <= 39420:  # Q3
            reward = 10000000000  # 100 WEPO
        else:  # Q4+
            reward = 5000000000   # 50 WEPO
        
        # Create coinbase transaction
        coinbase_tx = {
            "txid": f"coinbase_{height}",
            "inputs": [],
            "outputs": [{
                "address": "wepo1miner0000000000000000000000000",
                "value": reward
            }],
            "timestamp": int(time.time()),
            "type": "coinbase"
        }
        
        # Add coinbase to transactions
        block_txs = [coinbase_tx["txid"]]
        self.transactions[coinbase_tx["txid"]] = coinbase_tx
        self.utxos[f"{coinbase_tx['txid']}:0"] = coinbase_tx["outputs"][0]
        
        # Add mempool transactions to block
        for txid, tx in self.mempool.items():
            block_txs.append(txid)
            self.transactions[txid] = tx
            # Add UTXOs for transaction outputs
            for i, output in enumerate(tx["outputs"]):
                self.utxos[f"{txid}:{i}"] = output
        
        # Create block
        block = {
            "height": height,
            "hash": f"00000{height:010d}{hashlib.sha256(str(height).encode()).hexdigest()[:50]}",
            "prev_hash": prev_hash,
            "merkle_root": hashlib.sha256(f"block_{height}".encode()).hexdigest(),
            "timestamp": int(time.time()),
            "nonce": height * 1000,
            "difficulty": 1,
            "transactions": block_txs,
            "reward": reward
        }
        
        self.blocks.append(block)
        self.mempool.clear()
        
        print(f"⚡ INSTANT block mined: #{height}")
        print(f"   Block hash: {block['hash']}")
        print(f"   Transactions: {len(block_txs)}")
        print(f"   Block reward: {reward / 100000000.0} WEPO")
        
        return block

class WepoFastTestBridge:
    """Fast test bridge for instant blockchain operations"""
    
    def __init__(self):
        self.blockchain = FastTestBlockchain()
        self.app = FastAPI(title="WEPO Fast Test Bridge", version="1.0.0")
        self.setup_cors()
        self.setup_routes()
    
    def setup_cors(self):
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def setup_routes(self):
        @self.app.get("/")
        async def root():
            return {
                "message": "WEPO Fast Test Bridge", 
                "version": "1.0.0",
                "blockchain_ready": True,
                "blocks": len(self.blockchain.blocks)
            }
        
        @self.app.get("/api/")
        async def api_root():
            return {
                "message": "WEPO Fast Test API", 
                "blockchain_ready": True,
                "test_mode": True
            }
        
        @self.app.get("/api/network/status")
        async def get_network_status():
            return {
                "block_height": len(self.blockchain.blocks) - 1,
                "best_block_hash": self.blockchain.blocks[-1]["hash"],
                "difficulty": 1,
                "mempool_size": len(self.blockchain.mempool),
                "total_supply": 63900006,
                "network": "testnet",
                "status": "ready",
                "active_masternodes": 0,
                "total_staked": 0,
                "circulating_supply": len(self.blockchain.blocks) * 400
            }
        
        @self.app.post("/api/wallet/create")
        async def create_wallet(request: dict):
            address = request.get("address")
            self.blockchain.wallets[address] = {
                "username": request.get("username"),
                "created_at": time.strftime('%Y-%m-%d %H:%M:%S')
            }
            print(f"⚡ Test wallet created: {address}")
            return {"success": True, "address": address}
        
        @self.app.get("/api/wallet/{address}")
        async def get_wallet(address: str):
            balance = self.blockchain.get_balance(address)
            return {
                "address": address,
                "balance": balance,
                "username": self.blockchain.wallets.get(address, {}).get("username", "test_user"),
                "created_at": self.blockchain.wallets.get(address, {}).get("created_at", "2025-01-01T00:00:00Z"),
                "is_staking": False,
                "is_masternode": False
            }
        
        @self.app.get("/api/wallet/{address}/transactions")
        async def get_wallet_transactions(address: str):
            return self.blockchain.get_transactions(address)
        
        @self.app.post("/api/transaction/send")
        async def send_transaction(request: dict):
            from_address = request.get('from_address')
            to_address = request.get('to_address')
            amount = request.get('amount')
            
            # Validation: Check if from_address has sufficient balance
            current_balance = self.blockchain.get_balance(from_address)
            if current_balance < amount:
                raise HTTPException(status_code=400, detail=f"Insufficient balance. Available: {current_balance} WEPO, Required: {amount} WEPO")
            
            # Validation: Check for valid amount
            if amount <= 0:
                raise HTTPException(status_code=400, detail="Transaction amount must be greater than 0")
            
            # Validation: Check if to_address is valid (basic check)
            if not to_address or not to_address.startswith("wepo1") or len(to_address) != 37:
                raise HTTPException(status_code=400, detail="Invalid recipient address format")
            
            txid = self.blockchain.create_transaction(from_address, to_address, amount)
            return {
                "transaction_id": txid,
                "tx_hash": txid,
                "status": "pending",
                "message": "Transaction added to mempool"
            }
        
        @self.app.get("/api/mining/info")
        async def get_mining_info():
            height = len(self.blockchain.blocks) - 1
            return {
                "current_block_height": height,
                "current_reward": 400.0 if height < 13140 else 200.0 if height < 26280 else 100.0 if height < 39420 else 50.0,
                "difficulty": 1,
                "algorithm": "FastTest",
                "mining_enabled": True,
                "mempool_size": len(self.blockchain.mempool),
                "reward_schedule": "TEST: 400→200→100→50 WEPO per block"
            }
        
        @self.app.post("/api/test/mine-block")
        async def mine_test_block():
            block = self.blockchain.mine_block()
            if block:
                return {
                    "success": True,
                    "block_height": block["height"],
                    "block_hash": block["hash"],
                    "transactions": len(block["transactions"]),
                    "reward": block["reward"] / 100000000.0
                }
            else:
                return {"success": False, "message": "No transactions to mine"}
        
        @self.app.post("/api/test/fund-wallet")
        async def fund_wallet(request: dict):
            """Fund a wallet for testing"""
            address = request.get("address")
            amount = request.get("amount", 100.0)
            
            # Create funding transaction from genesis
            txid = self.blockchain.create_transaction("wepo1genesis0000000000000000000000", address, amount)
            
            # Mine block to confirm transaction
            block = self.blockchain.mine_block()
            
            return {
                "success": True,
                "txid": txid,
                "amount": amount,
                "block_height": block["height"] if block else None,
                "balance": self.blockchain.get_balance(address)
            }
        
        @self.app.get("/api/dex/rate")
        async def get_exchange_rate():
            return {
                "btc_to_wepo": 1.0,
                "wepo_to_btc": 1.0,
                "fee_percentage": 0.1,
                "last_updated": time.strftime('%Y-%m-%d %H:%M:%S')
            }

def main():
    print("=" * 60)
    print("⚡ WEPO FAST TEST BLOCKCHAIN BRIDGE")
    print("=" * 60)
    print("INSTANT blockchain for testing functionality")
    print("Genesis block ready, instant mining, zero delays!")
    print("=" * 60)
    
    bridge = WepoFastTestBridge()
    
    uvicorn.run(
        bridge.app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )

if __name__ == "__main__":
    main()