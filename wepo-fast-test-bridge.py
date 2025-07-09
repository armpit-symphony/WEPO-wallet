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
        """Calculate balance for address from confirmed UTXOs only"""
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
    
    def get_available_utxos(self, address):
        """Get all available UTXOs for an address"""
        utxos = []
        for utxo_key, utxo in self.utxos.items():
            if utxo["address"] == address:
                utxos.append({
                    "key": utxo_key,
                    "value": utxo["value"],
                    "address": utxo["address"]
                })
        return utxos
    
    def create_transaction(self, from_address, to_address, amount):
        """Create a transaction with proper validation (don't consume UTXOs yet)"""
        txid = f"tx_{int(time.time())}_{hash(from_address + to_address + str(amount))}"
        
        # Validate sender has sufficient balance
        current_balance = self.get_balance(from_address)
        amount_satoshis = int(amount * 100000000)
        
        if from_address != "wepo1genesis0000000000000000000000":
            if current_balance < amount:
                raise ValueError(f"Insufficient balance. Available: {current_balance} WEPO, Required: {amount} WEPO")
            
            # Get UTXOs for input calculation
            available_utxos = self.get_available_utxos(from_address)
            if not available_utxos:
                raise ValueError(f"No UTXOs available for address {from_address}")
            
            # Calculate total input value
            total_input_value = sum(utxo["value"] for utxo in available_utxos)
            change_value = total_input_value - amount_satoshis
            
            # Create transaction structure (but don't consume UTXOs yet)
            tx = {
                "txid": txid,
                "inputs": [{"utxo_key": utxo["key"], "value": utxo["value"], "address": from_address} for utxo in available_utxos],
                "outputs": [{
                    "address": to_address,
                    "value": amount_satoshis
                }],
                "timestamp": int(time.time()),
                "type": "transfer",
                "from_address": from_address,
                "to_address": to_address,
                "amount": amount
            }
            
            # Add change output if needed
            if change_value > 0:
                tx["outputs"].append({
                    "address": from_address,
                    "value": change_value
                })
        else:
            # Genesis/funding transaction
            tx = {
                "txid": txid,
                "inputs": [],
                "outputs": [{
                    "address": to_address,
                    "value": amount_satoshis
                }],
                "timestamp": int(time.time()),
                "type": "transfer",
                "from_address": from_address,
                "to_address": to_address,
                "amount": amount
            }
        
        # Add to mempool (UTXOs remain in place until mining)
        self.mempool[txid] = tx
        print(f"⚡ Transaction created: {amount} WEPO from {from_address} to {to_address}")
        print(f"   Transaction ID: {txid}")
        print(f"   Status: In mempool (pending)")
        return txid
    
    def mine_block(self):
        """Instantly mine a block with mempool transactions and proper UTXO management"""
        height = len(self.blocks)
        prev_hash = self.blocks[-1]["hash"]
        
        # Check if there's already a coinbase transaction in mempool
        has_coinbase = False
        for tx in self.mempool.values():
            if tx.get("type") == "coinbase":
                has_coinbase = True
                break
        
        # Only create default coinbase if there isn't one already
        if not has_coinbase:
            # Calculate reward based on WEPO tokenomics
            if height < 13140:  # Q1 (blocks 0-13139)
                reward = 40000000000  # 400 WEPO in satoshis
            elif height < 26280:  # Q2 (blocks 13140-26279)
                reward = 20000000000  # 200 WEPO in satoshis
            elif height < 39420:  # Q3 (blocks 26280-39419)
                reward = 10000000000  # 100 WEPO in satoshis
            elif height < 52560:  # Q4 (blocks 39420-52559)
                reward = 5000000000   # 50 WEPO in satoshis
            else:  # Year 2+
                reward = 1240000000   # 12.4 WEPO in satoshis
            
            # Create default coinbase transaction
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
            
            # Add default coinbase to mempool temporarily
            self.mempool[coinbase_tx["txid"]] = coinbase_tx
        
        # Now process all mempool transactions (including coinbase)
        block_txs = []
        for txid, tx in list(self.mempool.items()):
            block_txs.append(txid)
            self.transactions[txid] = tx
            
            # Consume input UTXOs for non-coinbase transactions
            if tx.get("type") != "coinbase" and "inputs" in tx:
                for inp in tx["inputs"]:
                    if "utxo_key" in inp:
                        # Remove consumed UTXO
                        if inp["utxo_key"] in self.utxos:
                            del self.utxos[inp["utxo_key"]]
                            print(f"   Consumed UTXO: {inp['utxo_key']}")
            
            # Create new UTXOs for transaction outputs
            for i, output in enumerate(tx["outputs"]):
                utxo_key = f"{txid}:{i}"
                self.utxos[utxo_key] = output
                print(f"   Created UTXO: {utxo_key} -> {output['value']/100000000:.1f} WEPO to {output['address']}")
        
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
            "reward": sum(out["value"] for tx in self.mempool.values() if tx.get("type") == "coinbase" for out in tx["outputs"])
        }
        
        self.blocks.append(block)
        self.mempool.clear()
        
        print(f"⚡ INSTANT block mined: #{height}")
        print(f"   Block hash: {block['hash']}")
        print(f"   Transactions: {len(block_txs)}")
        print(f"   Block reward: {block['reward'] / 100000000.0} WEPO")
        print(f"   UTXOs updated: {len(self.utxos)} total UTXOs")
        
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
            # Validate address format
            if not address or not address.startswith("wepo1") or len(address) != 37:
                raise HTTPException(status_code=400, detail="Invalid address format")
            
            # Get balance (works for any valid address)
            balance = self.blockchain.get_balance(address)
            return {
                "address": address,
                "balance": balance,
                "username": self.blockchain.wallets.get(address, {}).get("username", "unknown"),
                "created_at": self.blockchain.wallets.get(address, {}).get("created_at", "2025-01-01T00:00:00Z"),
                "is_staking": False,
                "is_masternode": False
            }
        
        @self.app.get("/api/wallet/{address}/transactions")
        async def get_wallet_transactions(address: str):
            # Validate address format
            if not address or not address.startswith("wepo1") or len(address) != 37:
                raise HTTPException(status_code=400, detail="Invalid address format")
                
            return self.blockchain.get_transactions(address)
        
        @self.app.post("/api/transaction/send")
        async def send_transaction(request: dict):
            try:
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
                
                # Validation: Check if from_address is valid
                if not from_address or not from_address.startswith("wepo1") or len(from_address) != 37:
                    raise HTTPException(status_code=400, detail="Invalid sender address format")
                
                txid = self.blockchain.create_transaction(from_address, to_address, amount)
                return {
                    "transaction_id": txid,
                    "tx_hash": txid,
                    "status": "pending",
                    "message": "Transaction added to mempool"
                }
            except ValueError as e:
                # Handle blockchain validation errors
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                # Handle unexpected errors
                raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
        
        @self.app.get("/api/mining/info")
        async def get_mining_info():
            height = len(self.blockchain.blocks) - 1
            
            # Calculate current reward based on WEPO tokenomics
            if height < 13140:  # Q1 (blocks 0-13139)
                current_reward = 400.0
                quarter_info = "Q1 (400 WEPO per block)"
            elif height < 26280:  # Q2 (blocks 13140-26279)
                current_reward = 200.0 
                quarter_info = "Q2 (200 WEPO per block)"
            elif height < 39420:  # Q3 (blocks 26280-39419)
                current_reward = 100.0
                quarter_info = "Q3 (100 WEPO per block)"
            elif height < 52560:  # Q4 (blocks 39420-52559)
                current_reward = 50.0
                quarter_info = "Q4 (50 WEPO per block)"
            else:  # Year 2+ 
                current_reward = 12.4
                quarter_info = "Year 2+ (12.4 WEPO per block)"
            
            return {
                "current_block_height": height,
                "current_reward": current_reward,
                "quarter_info": quarter_info,
                "difficulty": 1,
                "algorithm": "FastTest",
                "mining_enabled": True,
                "mempool_size": len(self.blockchain.mempool),
                "reward_schedule": "WEPO Tokenomics: Q1=400, Q2=200, Q3=100, Q4=50, Year2+=12.4 WEPO per block"
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
        
        @self.app.post("/api/test/mine-block")
        async def mine_test_block(request: dict = None):
            """Mine a test block with optional miner address"""
            # Create a mining reward transaction for the specified miner
            miner_address = "wepo1miner0000000000000000000000000"
            if request and request.get("miner_address"):
                miner_address = request.get("miner_address")
            
            # Create mining reward transaction directly in mempool
            height = len(self.blockchain.blocks)
            
            # Calculate reward
            if height < 13140:  # Q1
                reward_satoshis = 40000000000  # 400 WEPO
            elif height < 26280:  # Q2
                reward_satoshis = 20000000000  # 200 WEPO
            elif height < 39420:  # Q3
                reward_satoshis = 10000000000  # 100 WEPO
            elif height < 52560:  # Q4
                reward_satoshis = 5000000000   # 50 WEPO
            else:
                reward_satoshis = 1240000000   # 12.4 WEPO
            
            # Create mining reward transaction
            reward_txid = f"mining_reward_{height}_{int(time.time())}"
            reward_tx = {
                "txid": reward_txid,
                "inputs": [],
                "outputs": [{
                    "address": miner_address,
                    "value": reward_satoshis
                }],
                "timestamp": int(time.time()),
                "type": "coinbase",
                "from_address": "system",
                "to_address": miner_address,
                "amount": reward_satoshis / 100000000.0
            }
            
            # Add to mempool
            self.blockchain.mempool[reward_txid] = reward_tx
            
            # Mine block
            block = self.blockchain.mine_block()
            
            if block:
                return {
                    "success": True,
                    "block_height": block["height"],
                    "block_hash": block["hash"],
                    "transactions": len(block["transactions"]),
                    "reward": reward_satoshis / 100000000.0,
                    "miner_address": miner_address,
                    "miner_balance": self.blockchain.get_balance(miner_address)
                }
            else:
                return {"success": False, "message": "Mining failed"}
        
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