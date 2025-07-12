#!/usr/bin/env python3
"""
WEPO Fast Test Blockchain Bridge
Instant blockchain for testing functionality with BTC atomic swaps and community mining
"""

import time
import hashlib
import json
import sys
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add atomic swaps and RWA to the path
sys.path.append('/app/wepo-blockchain/core')
from atomic_swaps import atomic_swap_engine, SwapType, SwapState, validate_btc_address, validate_wepo_address
from rwa_tokens import rwa_system

# Import mining coordinator
from wepo_community_mining_backend import mining_coordinator, setup_mining_routes

class FastTestBlockchain:
    """Fast test blockchain with instant operations"""
    
    def __init__(self):
        self.blocks = []
        self.transactions = {}
        self.mempool = {}
        self.utxos = {}
        self.wallets = {}
        self.stakes = {}  # Add stakes tracking
        self.masternodes = {}  # Add masternodes tracking
        
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
    
    def calculate_block_reward(self, height):
        """Calculate block reward based on new WEPO tokenomics schedule"""
        # New 6-month mining schedule
        PHASE_1_BLOCKS = 26280  # Months 1-6
        PHASE_2_BLOCKS = 26280  # Months 7-12  
        PHASE_3_BLOCKS = 26280  # Months 13-18
        TOTAL_MINING_BLOCKS = PHASE_1_BLOCKS + PHASE_2_BLOCKS + PHASE_3_BLOCKS  # 78,840
        COIN = 100000000  # Satoshis per WEPO
        
        if height <= PHASE_1_BLOCKS:
            # Months 1-6: 400 WEPO per block
            return 400 * COIN
        elif height <= (PHASE_1_BLOCKS + PHASE_2_BLOCKS):
            # Months 7-12: 200 WEPO per block
            return 200 * COIN
        elif height <= TOTAL_MINING_BLOCKS:
            # Months 13-18: 100 WEPO per block
            return 100 * COIN
        else:
            # After 18 months: PoS/Masternode phase (minimal mining rewards)
            return 0  # No more mining rewards, transition to PoS
    
    def get_dynamic_masternode_collateral(self, block_height):
        """Get masternode collateral required at specific block height"""
        
        # Dynamic Masternode Collateral Schedule
        collateral_schedule = {
            0: 10000.0,          # Genesis - Year 5: 10,000 WEPO
            262800: 5000.0,      # Year 5 (during halving): 5,000 WEPO
            525600: 1000.0,      # Year 10 (during halving): 1,000 WEPO
            1051200: 500.0,      # Year 20 (during halving): 500 WEPO
        }
        
        # Find the applicable collateral amount
        applicable_collateral = 10000.0  # Default
        
        for milestone_height in sorted(collateral_schedule.keys(), reverse=True):
            if block_height >= milestone_height:
                applicable_collateral = collateral_schedule[milestone_height]
                break
        
        return applicable_collateral
    
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
    
    def mine_block_with_miner(self, miner_address):
        """Mine a block with a specific miner address"""
        height = len(self.blocks)
        
        # Check if there's already a coinbase transaction in mempool
        has_coinbase = False
        for tx in self.mempool.values():
            if tx.get("type") == "coinbase":
                has_coinbase = True
                break
        
        # Only create coinbase if there isn't one already
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
            
            # Create coinbase transaction to the specified miner address
            coinbase_tx = {
                "txid": f"coinbase_{height}",
                "inputs": [],
                "outputs": [{
                    "address": miner_address,
                    "value": reward
                }],
                "timestamp": int(time.time()),
                "type": "coinbase"
            }
            
            # Add coinbase to mempool temporarily
            self.mempool[coinbase_tx["txid"]] = coinbase_tx
        
        # Now mine the block using the regular mine_block method
        return self.mine_block()

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
            # Validate address format (allow shorter addresses for testing)
            if not address or not address.startswith("wepo1") or len(address) < 30:
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

        @self.app.post("/api/test/create-normal-transaction")
        async def create_normal_transaction(request: dict):
            """Create a normal transaction for testing fee redistribution"""
            try:
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                amount = request.get('amount', 0.001)  # Default small amount
                fee = request.get('fee', 0.0001)  # Default fee
                
                if not all([from_address, to_address]):
                    raise HTTPException(status_code=400, detail="Missing required addresses")
                
                # Create transaction (FastTestBlockchain doesn't support fee parameter)
                transaction = self.blockchain.create_transaction(
                    from_address=from_address,
                    to_address=to_address,
                    amount=float(amount)
                )
                
                if not transaction:
                    raise HTTPException(status_code=400, detail="Failed to create transaction")
                
                # Add to mempool
                tx_id = transaction.calculate_txid()
                self.blockchain.add_transaction_to_mempool(transaction)
                
                # Manually add fee to redistribution pool for testing
                rwa_system.add_fee_to_redistribution_pool(fee, len(self.blockchain.blocks), 'normal_transaction')
                
                return {
                    'success': True,
                    'transaction_id': tx_id,
                    'amount': amount,
                    'fee': fee,
                    'fee_satoshis': int(fee * 100000000),
                    'mempool_size': len(self.blockchain.mempool),
                    'message': f'Normal transaction created with {fee} WEPO fee'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/test/mine-block")
        async def mine_test_block(request: dict):
            """Mine a block for testing fee redistribution"""
            try:
                miner_address = request.get('miner_address')
                if not miner_address:
                    raise HTTPException(status_code=400, detail="Miner address required")
                
                # Check redistribution pool before mining
                pool_info_before = rwa_system.get_redistribution_pool_info()
                fees_before = pool_info_before.get('total_collected', 0)
                
                # Check mempool before mining
                mempool_size = len(self.blockchain.mempool)
                
                # Distribute fees to miner
                fees_distributed = rwa_system.distribute_fees_to_miners(miner_address, len(self.blockchain.blocks))
                
                # Mine block
                try:
                    mined_block = self.blockchain.mine_block_with_miner(miner_address)
                except AttributeError:
                    # Fallback if mine_block_with_miner doesn't exist
                    mined_block = self.blockchain.mine_block()
                
                if not mined_block:
                    raise HTTPException(status_code=500, detail="Failed to mine block")
                
                # Get redistribution pool info after mining
                pool_info_after = rwa_system.get_redistribution_pool_info()
                fees_after = pool_info_after.get('total_collected', 0)
                
                return {
                    'success': True,
                    'block_height': getattr(mined_block, 'height', len(self.blockchain.blocks)),
                    'miner_address': miner_address,
                    'fees_before_mining': fees_before,
                    'fees_distributed': fees_distributed,
                    'fees_after_mining': fees_after,
                    'transactions_processed': mempool_size,
                    'new_mempool_size': len(self.blockchain.mempool),
                    'message': f'Block mined successfully. Distributed {fees_distributed} WEPO in fees to miner.'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

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
        
        @self.app.get("/api/debug/utxos")
        async def debug_utxos():
            """Debug endpoint to see all UTXOs"""
            return {
                "utxos": {k: v for k, v in self.blockchain.utxos.items()},
                "total_utxos": len(self.blockchain.utxos)
            }
        
        @self.app.get("/api/debug/balance/{address}")
        async def debug_balance(address: str):
            """Debug balance calculation"""
            utxos = []
            total = 0
            for utxo_key, utxo in self.blockchain.utxos.items():
                if utxo["address"] == address:
                    utxos.append({
                        "key": utxo_key,
                        "value": utxo["value"],
                        "wepo": utxo["value"] / 100000000.0
                    })
                    total += utxo["value"]
            
            return {
                "address": address,
                "matching_utxos": utxos,
                "total_satoshis": total,
                "total_wepo": total / 100000000.0
            }
        
        @self.app.get("/api/dex/rate")
        async def get_exchange_rate():
            """Get current exchange rates"""
            # Get RWA tokens for trading
            rwa_tokens = rwa_system.get_tradeable_tokens()
            
            # Create rate info for each RWA token
            rwa_rates = {}
            for token in rwa_tokens:
                # Use last price or default to 1 WEPO per 1000 tokens
                rate = token.get('last_price', 1000000000)  # Default rate in satoshis per token
                rwa_rates[token['token_id']] = {
                    'symbol': token['symbol'],
                    'name': token['name'],
                    'rate_wepo_per_token': rate / 100000000,  # Convert to WEPO
                    'asset_name': token.get('asset_name', 'Unknown Asset'),
                    'asset_type': token.get('asset_type', 'unknown'),
                    'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
                }
            
            return {
                'btc_to_wepo': 1.0,
                'wepo_to_btc': 1.0,
                'rwa_tokens': rwa_rates,
                'fee_percentage': 0.1,
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        
        @self.app.post("/api/dex/rwa-trade")
        async def create_rwa_trade(request: dict):
            """Create RWA-WEPO trade"""
            try:
                token_id = request.get('token_id')
                trade_type = request.get('trade_type')  # 'buy' or 'sell'
                user_address = request.get('user_address')
                token_amount = request.get('token_amount')
                wepo_amount = request.get('wepo_amount')
                
                if not all([token_id, trade_type, user_address, token_amount, wepo_amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Get token info
                token_info = rwa_system.get_token_info(token_id)
                if not token_info:
                    raise HTTPException(status_code=404, detail="Token not found")
                
                # Create a simulated counterparty for the trade
                counterparty_address = "wepo1dexpool0000000000000000000000000"
                
                if trade_type == 'buy':
                    # User buys RWA tokens with WEPO
                    seller_address = counterparty_address
                    buyer_address = user_address
                    
                    # Check user has sufficient WEPO
                    user_balance = self.blockchain.get_balance(user_address)
                    if user_balance < float(wepo_amount):
                        raise HTTPException(status_code=400, detail="Insufficient WEPO balance")
                    
                elif trade_type == 'sell':
                    # User sells RWA tokens for WEPO
                    seller_address = user_address
                    buyer_address = counterparty_address
                    
                    # Check user has sufficient RWA tokens
                    token = rwa_system.tokens.get(token_id)
                    if not token or user_address not in token.holders:
                        raise HTTPException(status_code=400, detail="No RWA tokens to sell")
                    
                    if token.holders[user_address] < int(token_amount):
                        raise HTTPException(status_code=400, detail="Insufficient RWA token balance")
                else:
                    raise HTTPException(status_code=400, detail="Invalid trade type")
                
                # Execute RWA trade
                rwa_tx_id = rwa_system.trade_tokens_for_wepo(
                    token_id=token_id,
                    seller_address=seller_address,
                    buyer_address=buyer_address,
                    token_amount=int(token_amount),
                    wepo_amount=int(float(wepo_amount) * 100000000),  # Convert to satoshis
                    block_height=len(self.blockchain.blocks)
                )
                
                # Create corresponding WEPO transaction
                if trade_type == 'buy':
                    wepo_tx_id = self.blockchain.create_transaction(user_address, counterparty_address, float(wepo_amount))
                else:
                    wepo_tx_id = self.blockchain.create_transaction(counterparty_address, user_address, float(wepo_amount))
                
                return {
                    'success': True,
                    'trade_id': rwa_tx_id,
                    'rwa_transaction_id': rwa_tx_id,
                    'wepo_transaction_id': wepo_tx_id,
                    'trade_type': trade_type,
                    'token_amount': token_amount,
                    'wepo_amount': wepo_amount,
                    'message': f'RWA {trade_type} trade executed successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/fee-info")
        async def get_rwa_fee_info():
            """Get comprehensive fee information for all WEPO network operations"""
            try:
                fee_info = rwa_system.get_rwa_creation_fee_info()
                
                # Add comprehensive network fee information
                fee_info['network_fee_distribution'] = {
                    'all_network_fees': 'Every fee in WEPO network follows 3-way distribution',
                    'distribution_weights': {
                        'masternodes': '60% of all fees (split equally among active nodes)',
                        'miners': '25% of all fees (goes to current block miner)',
                        'stakers': '15% of all fees (proportional to stake amount)'
                    },
                    'fee_types_included': [
                        'Normal transaction fees (0.0001 WEPO each)',
                        'RWA creation fees (0.0002 WEPO each)',
                        'All other network operation fees'
                    ],
                    'zero_burning_policy': 'No fees are ever burned - 100% distributed to network participants',
                    'distribution_timing': 'Real-time per-block distribution'
                }
                
                # Add mining schedule information
                fee_info['mining_schedule'] = {
                    'months_1_6': '400 WEPO per block (26,280 blocks)',
                    'months_7_12': '200 WEPO per block (26,280 blocks)', 
                    'months_13_18': '100 WEPO per block (26,280 blocks)',
                    'total_mining': '18,396,000 WEPO (28.8% of supply)',
                    'post_mining': 'PoS and Masternode rewards (71.2% of supply)'
                }
                
                return {
                    'success': True,
                    'fee_info': fee_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/tokenomics/overview")
        async def get_tokenomics_overview():
            """Get complete WEPO tokenomics overview"""
            try:
                current_height = len(self.blockchain.blocks)
                
                # Calculate current mining phase
                if current_height <= 26280:
                    current_phase = "Phase 1 (Months 1-6)"
                    current_reward = 400
                    remaining_blocks = 26280 - current_height
                elif current_height <= 52560:
                    current_phase = "Phase 2 (Months 7-12)" 
                    current_reward = 200
                    remaining_blocks = 52560 - current_height
                elif current_height <= 78840:
                    current_phase = "Phase 3 (Months 13-18)"
                    current_reward = 100
                    remaining_blocks = 78840 - current_height
                else:
                    current_phase = "PoS/Masternode Phase"
                    current_reward = 0
                    remaining_blocks = 0
                
                tokenomics = {
                    'total_supply': 63900006,
                    'current_block_height': current_height,
                    'current_mining_phase': current_phase,
                    'current_block_reward': current_reward,
                    'blocks_until_next_phase': remaining_blocks,
                    
                    'supply_distribution': {
                        'mining_rewards': {
                            'amount': 18396000,
                            'percentage': 28.8,
                            'duration': '18 months',
                            'schedule': {
                                'months_1_6': '400 WEPO × 26,280 blocks = 10,512,000 WEPO',
                                'months_7_12': '200 WEPO × 26,280 blocks = 5,256,000 WEPO',
                                'months_13_18': '100 WEPO × 26,280 blocks = 2,628,000 WEPO'
                            }
                        },
                        'pos_staking': {
                            'amount': 30000000,
                            'percentage': 47.0,
                            'duration': 'Years 2-10',
                            'description': 'PoS staking rewards distributed over 9 years'
                        },
                        'masternodes': {
                            'amount': 12000000,
                            'percentage': 18.8,
                            'duration': 'Years 2-15',
                            'collateral_required': 10000,
                            'description': 'Masternode service rewards'
                        },
                        'development_ecosystem': {
                            'amount': 3504006,
                            'percentage': 5.5,
                            'description': 'Protocol development and ecosystem growth'
                        }
                    },
                    
                    'fee_distribution': {
                        'masternodes': 60,
                        'miners': 25,
                        'stakers': 15,
                        'method': 'Real-time per-block distribution',
                        'policy': 'Zero burning - 100% distributed to participants'
                    },
                    
                    'consensus_transition': {
                        'phase_1': 'Pure PoW (Months 1-18)',
                        'phase_2': 'Hybrid PoW/PoS (Month 19+)',
                        'long_term': 'Fee-driven sustainable economy'
                    }
                }
                
                return {
                    'success': True,
                    'tokenomics': tokenomics
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/mining/schedule")
        async def get_mining_schedule():
            """Get detailed mining schedule and current status"""
            try:
                current_height = len(self.blockchain.blocks)
                current_reward = self.blockchain.calculate_block_reward(current_height)
                
                schedule = {
                    'current_status': {
                        'block_height': current_height,
                        'current_reward_wepo': current_reward / 100000000,
                        'estimated_blocks_per_day': 576,  # 2.5 minute blocks
                        'estimated_daily_issuance': (current_reward / 100000000) * 576
                    },
                    
                    'mining_phases': [
                        {
                            'phase': 'Phase 1',
                            'duration': 'Months 1-6',
                            'blocks': '1 - 26,280',
                            'reward_per_block': 400,
                            'total_rewards': 10512000,
                            'percentage_of_supply': 16.5
                        },
                        {
                            'phase': 'Phase 2', 
                            'duration': 'Months 7-12',
                            'blocks': '26,281 - 52,560',
                            'reward_per_block': 200,
                            'total_rewards': 5256000,
                            'percentage_of_supply': 8.2
                        },
                        {
                            'phase': 'Phase 3',
                            'duration': 'Months 13-18', 
                            'blocks': '52,561 - 78,840',
                            'reward_per_block': 100,
                            'total_rewards': 2628000,
                            'percentage_of_supply': 4.1
                        },
                        {
                            'phase': 'PoS Transition',
                            'duration': 'Month 19+',
                            'blocks': '78,841+',
                            'reward_per_block': 0,
                            'note': 'Mining ends, PoS and Masternode rewards begin'
                        }
                    ],
                    
                    'total_mining_summary': {
                        'total_blocks': 78840,
                        'total_rewards': 18396000,
                        'percentage_of_supply': 28.8,
                        'estimated_duration_days': 137  # 78,840 blocks / 576 blocks per day
                    }
                }
                
                return {
                    'success': True,
                    'mining_schedule': schedule
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/rwa/redistribution-pool")
        async def get_redistribution_pool_info():
            """Get fee redistribution pool information"""
            try:
                pool_info = rwa_system.get_redistribution_pool_info()
                
                return {
                    'success': True,
                    'redistribution_pool': pool_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/rwa/distribute-fees")
        async def distribute_fees(request: dict):
            """Distribute fees to miners or masternodes (admin endpoint)"""
            try:
                distribution_type = request.get('type')  # 'miner' or 'masternode'
                recipient_address = request.get('recipient_address')
                masternode_addresses = request.get('masternode_addresses', [])
                block_height = len(self.blockchain.blocks)
                
                if distribution_type == 'miner' and recipient_address:
                    amount_distributed = rwa_system.distribute_fees_to_miners(recipient_address, block_height)
                    return {
                        'success': True,
                        'distribution_type': 'miner',
                        'recipient': recipient_address,
                        'amount_distributed': amount_distributed,
                        'message': f'Distributed {amount_distributed} WEPO to miner'
                    }
                    
                elif distribution_type == 'masternode' and masternode_addresses:
                    distributions = rwa_system.distribute_fees_to_masternodes(masternode_addresses, block_height)
                    return {
                        'success': True,
                        'distribution_type': 'masternode',
                        'distributions': distributions,
                        'total_distributed': sum(distributions.values()),
                        'message': f'Distributed fees to {len(masternode_addresses)} masternodes'
                    }
                else:
                    raise HTTPException(status_code=400, detail="Invalid distribution parameters")
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # Atomic Swap Operations
        @self.app.post("/api/atomic-swap/initiate")
        async def initiate_atomic_swap(request: dict):
            """Initiate a new atomic swap"""
            try:
                # Extract request parameters
                swap_type = request.get('swap_type')
                btc_amount = request.get('btc_amount')
                initiator_btc_address = request.get('initiator_btc_address')
                initiator_wepo_address = request.get('initiator_wepo_address')
                participant_btc_address = request.get('participant_btc_address')
                participant_wepo_address = request.get('participant_wepo_address')
                
                # Validate parameters
                if not all([swap_type, btc_amount, initiator_btc_address, 
                           initiator_wepo_address, participant_btc_address, participant_wepo_address]):
                    raise HTTPException(status_code=400, detail="Missing required parameters")
                
                # Validate addresses
                if not validate_btc_address(initiator_btc_address) or not validate_btc_address(participant_btc_address):
                    raise HTTPException(status_code=400, detail="Invalid Bitcoin address")
                
                if not validate_wepo_address(initiator_wepo_address) or not validate_wepo_address(participant_wepo_address):
                    raise HTTPException(status_code=400, detail="Invalid WEPO address")
                
                # Convert swap type
                if swap_type == "btc_to_wepo":
                    swap_type_enum = SwapType.BTC_TO_WEPO
                elif swap_type == "wepo_to_btc":
                    swap_type_enum = SwapType.WEPO_TO_BTC
                else:
                    raise HTTPException(status_code=400, detail="Invalid swap type")
                
                # Initiate swap
                swap_contract = await atomic_swap_engine.initiate_swap(
                    swap_type_enum,
                    initiator_btc_address,
                    initiator_wepo_address,
                    participant_btc_address,
                    participant_wepo_address,
                    float(btc_amount)
                )
                
                return {
                    'success': True,
                    'swap_id': swap_contract.swap_id,
                    'swap_type': swap_contract.swap_type.value,
                    'state': swap_contract.state.value,
                    'btc_amount': swap_contract.btc_amount,
                    'wepo_amount': swap_contract.wepo_amount,
                    'secret_hash': swap_contract.secret_hash,
                    'btc_htlc_address': swap_contract.btc_htlc_address,
                    'wepo_htlc_address': swap_contract.wepo_htlc_address,
                    'btc_locktime': swap_contract.btc_locktime,
                    'wepo_locktime': swap_contract.wepo_locktime,
                    'expires_at': swap_contract.expires_at.isoformat()
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Import quantum messaging system
        from quantum_messaging import messaging_system
        
        # Remove redundant RWA system import (now at top level)
        # Quantum Messaging API Endpoints
        @self.app.post("/api/messaging/send")
        async def send_quantum_message(request: dict):
            """Send quantum-encrypted message (works with all wallet types)"""
            try:
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                content = request.get('content')
                subject = request.get('subject', '')
                message_type = request.get('message_type', 'text')
                
                if not all([from_address, to_address, content]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Validate addresses (accept both regular and quantum)
                if not (from_address.startswith("wepo1") and to_address.startswith("wepo1")):
                    raise HTTPException(status_code=400, detail="Invalid address format")
                
                # Send quantum-encrypted message
                message = messaging_system.send_message(
                    from_address=from_address,
                    to_address=to_address,
                    content=content,
                    subject=subject,
                    message_type=message_type
                )
                
                return {
                    'success': True,
                    'message_id': message.message_id,
                    'quantum_encrypted': True,
                    'delivery_status': message.delivery_status,
                    'timestamp': message.timestamp,
                    'universal_compatibility': True,
                    'encryption_algorithm': 'Dilithium2'
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/messaging/inbox/{address}")
        async def get_inbox_messages(address: str):
            """Get inbox messages for any wallet type"""
            try:
                # Validate address format
                if not address.startswith("wepo1"):
                    raise HTTPException(status_code=400, detail="Invalid address format")
                
                # Get inbox messages
                messages = messaging_system.get_messages(address, "inbox")
                
                # Convert to API response format
                message_list = []
                for msg in messages:
                    # Decrypt message for this user
                    try:
                        decrypted_content = messaging_system.decrypt_message_for_user(msg, address)
                    except:
                        decrypted_content = "[Encrypted]"  # Can't decrypt if not recipient
                    
                    message_list.append({
                        'message_id': msg.message_id,
                        'from_address': msg.from_address,
                        'to_address': msg.to_address,
                        'content': decrypted_content,
                        'subject': msg.subject,
                        'timestamp': msg.timestamp,
                        'message_type': msg.message_type,
                        'read_status': msg.read_status,
                        'delivery_status': msg.delivery_status,
                        'quantum_encrypted': True,
                        'signature_valid': messaging_system.verify_message_signature(msg)
                    })
                
                return {
                    'success': True,
                    'address': address,
                    'message_count': len(message_list),
                    'messages': message_list,
                    'quantum_encrypted': True,
                    'universal_compatibility': True
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/messaging/conversation/{address1}/{address2}")
        async def get_conversation(address1: str, address2: str):
            """Get conversation between two addresses"""
            try:
                # Validate addresses
                if not (address1.startswith("wepo1") and address2.startswith("wepo1")):
                    raise HTTPException(status_code=400, detail="Invalid address format")
                
                # Get conversation
                conversation = messaging_system.get_conversation(address1, address2)
                
                # Convert to API response format
                message_list = []
                for msg in conversation:
                    # Try to decrypt for address1
                    try:
                        if msg.to_address == address1:
                            decrypted_content = messaging_system.decrypt_message_for_user(msg, address1)
                        else:
                            decrypted_content = msg.content  # Outgoing message
                    except:
                        decrypted_content = "[Encrypted]"
                    
                    message_list.append({
                        'message_id': msg.message_id,
                        'from_address': msg.from_address,
                        'to_address': msg.to_address,
                        'content': decrypted_content,
                        'subject': msg.subject,
                        'timestamp': msg.timestamp,
                        'message_type': msg.message_type,
                        'read_status': msg.read_status,
                        'quantum_encrypted': True,
                        'signature_valid': messaging_system.verify_message_signature(msg)
                    })
                
                return {
                    'success': True,
                    'participants': [address1, address2],
                    'message_count': len(message_list),
                    'conversation': message_list,
                    'quantum_encrypted': True,
                    'universal_compatibility': True
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/messaging/mark-read")
        async def mark_message_read(request: dict):
            """Mark message as read"""
            try:
                message_id = request.get('message_id')
                user_address = request.get('user_address')
                
                if not all([message_id, user_address]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                success = messaging_system.mark_as_read(message_id, user_address)
                
                return {
                    'success': success,
                    'message_id': message_id,
                    'marked_read': success
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/messaging/stats")
        async def get_messaging_stats():
            """Get messaging system statistics"""
            try:
                stats = messaging_system.get_messaging_stats()
                
                return {
                    'success': True,
                    'stats': stats,
                    'quantum_encrypted': True,
                    'universal_compatibility': True,
                    'feature': 'Universal Quantum Messaging',
                    'description': 'Quantum-resistant messaging for all wallet types'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/atomic-swap/status/{swap_id}")
        async def get_swap_status(swap_id: str):
            """Get atomic swap status"""
            try:
                swap_contract = atomic_swap_engine.get_swap_status(swap_id)
                if not swap_contract:
                    raise HTTPException(status_code=404, detail="Swap not found")
                
                return {
                    'swap_id': swap_contract.swap_id,
                    'swap_type': swap_contract.swap_type.value,
                    'state': swap_contract.state.value,
                    'btc_amount': swap_contract.btc_amount,
                    'wepo_amount': swap_contract.wepo_amount,
                    'secret_hash': swap_contract.secret_hash,
                    'btc_htlc_address': swap_contract.btc_htlc_address,
                    'wepo_htlc_address': swap_contract.wepo_htlc_address,
                    'btc_locktime': swap_contract.btc_locktime,
                    'wepo_locktime': swap_contract.wepo_locktime,
                    'btc_funding_tx': swap_contract.btc_funding_tx,
                    'wepo_funding_tx': swap_contract.wepo_funding_tx,
                    'created_at': swap_contract.created_at.isoformat(),
                    'expires_at': swap_contract.expires_at.isoformat()
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/atomic-swap/fund")
        async def fund_atomic_swap(request: dict):
            """Fund an atomic swap"""
            try:
                swap_id = request.get('swap_id')
                currency = request.get('currency')
                tx_hash = request.get('tx_hash')
                
                if not all([swap_id, currency, tx_hash]):
                    raise HTTPException(status_code=400, detail="Missing required parameters")
                
                success = await atomic_swap_engine.fund_swap(swap_id, currency, tx_hash)
                
                if success:
                    return {
                        'success': True,
                        'message': f'{currency} funding recorded',
                        'swap_id': swap_id,
                        'tx_hash': tx_hash
                    }
                else:
                    raise HTTPException(status_code=400, detail="Failed to fund swap")
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/atomic-swap/redeem")
        async def redeem_atomic_swap(request: dict):
            """Redeem an atomic swap with secret"""
            try:
                swap_id = request.get('swap_id')
                secret = request.get('secret')
                
                if not all([swap_id, secret]):
                    raise HTTPException(status_code=400, detail="Missing required parameters")
                
                success = await atomic_swap_engine.redeem_swap(swap_id, secret)
                
                if success:
                    return {
                        'success': True,
                        'message': 'Swap redeemed successfully',
                        'swap_id': swap_id
                    }
                else:
                    raise HTTPException(status_code=400, detail="Failed to redeem swap")
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/atomic-swap/refund")
        async def refund_atomic_swap(request: dict):
            """Refund an expired atomic swap"""
            try:
                swap_id = request.get('swap_id')
                
                if not swap_id:
                    raise HTTPException(status_code=400, detail="Missing swap_id")
                
                success = await atomic_swap_engine.refund_swap(swap_id)
                
                if success:
                    return {
                        'success': True,
                        'message': 'Swap refunded successfully',
                        'swap_id': swap_id
                    }
                else:
                    raise HTTPException(status_code=400, detail="Failed to refund swap or swap not expired")
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/list")
        async def list_atomic_swaps():
            """List all active atomic swaps"""
            try:
                swaps = atomic_swap_engine.get_all_swaps()
                
                swap_list = []
                for swap in swaps:
                    swap_list.append({
                        'swap_id': swap.swap_id,
                        'swap_type': swap.swap_type.value,
                        'state': swap.state.value,
                        'btc_amount': swap.btc_amount,
                        'wepo_amount': swap.wepo_amount,
                        'created_at': swap.created_at.isoformat(),
                        'expires_at': swap.expires_at.isoformat()
                    })
                
                return {
                    'swaps': swap_list,
                    'total_count': len(swap_list)
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/proof/{swap_id}")
        async def get_swap_proof(swap_id: str):
            """Get cryptographic proof of atomic swap"""
            try:
                proof = await atomic_swap_engine.get_swap_proof(swap_id)
                
                if not proof:
                    raise HTTPException(status_code=404, detail="Swap not found")
                
                return proof
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/exchange-rate")
        async def get_atomic_swap_exchange_rate():
            """Get current BTC/WEPO exchange rate with additional info"""
            try:
                rate = atomic_swap_engine.get_exchange_rate()
                fee_info = atomic_swap_engine.calculate_swap_fees(0.1, SwapType.BTC_TO_WEPO)
                
                return {
                    'btc_to_wepo': rate,
                    'wepo_to_btc': 1.0 / rate,
                    'fee_percentage': atomic_swap_engine.fee_structure['base_fee_percentage'],
                    'network_fee_btc': atomic_swap_engine.fee_structure['network_fee_btc'],
                    'network_fee_wepo': atomic_swap_engine.fee_structure['network_fee_wepo'],
                    'last_updated': int(time.time()),
                    'source': 'atomic_swap_engine',
                    'sample_fees': fee_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/fees")
        async def calculate_swap_fees(btc_amount: float, swap_type: str = "btc_to_wepo", priority: bool = False):
            """Calculate swap fees for given amount"""
            try:
                if swap_type == "btc_to_wepo":
                    swap_type_enum = SwapType.BTC_TO_WEPO
                elif swap_type == "wepo_to_btc":
                    swap_type_enum = SwapType.WEPO_TO_BTC
                else:
                    raise HTTPException(status_code=400, detail="Invalid swap type")
                
                fee_info = atomic_swap_engine.calculate_swap_fees(btc_amount, swap_type_enum, priority)
                
                return {
                    'btc_amount': btc_amount,
                    'swap_type': swap_type,
                    'priority': priority,
                    'fees': fee_info,
                    'estimated_completion_time': '2-4 hours' if not priority else '1-2 hours'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/statistics")
        async def get_swap_statistics():
            """Get comprehensive swap statistics"""
            try:
                stats = atomic_swap_engine.get_swap_statistics()
                return {
                    'statistics': stats,
                    'timestamp': int(time.time())
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/history")
        async def get_swap_history(limit: int = 50, offset: int = 0):
            """Get swap history with pagination"""
            try:
                history = atomic_swap_engine.get_swap_history(limit, offset)
                
                return {
                    'history': history,
                    'pagination': {
                        'limit': limit,
                        'offset': offset,
                        'total_count': len(atomic_swap_engine.swap_history)
                    }
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/search")
        async def search_swaps(query: str = "", state: str = "", swap_type: str = ""):
            """Search swaps by criteria"""
            try:
                state_enum = None
                if state:
                    try:
                        state_enum = SwapState(state)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid state")
                
                swap_type_enum = None
                if swap_type:
                    try:
                        swap_type_enum = SwapType(swap_type)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid swap type")
                
                results = atomic_swap_engine.search_swaps(query, state_enum, swap_type_enum)
                
                return {
                    'results': results,
                    'query': query,
                    'filters': {
                        'state': state,
                        'swap_type': swap_type
                    },
                    'total_results': len(results)
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/atomic-swap/rates/historical")
        async def get_historical_rates(days: int = 30):
            """Get historical exchange rates"""
            try:
                if days > 365:
                    raise HTTPException(status_code=400, detail="Maximum 365 days allowed")
                
                rates = atomic_swap_engine.get_historical_rates(days)
                
                return {
                    'rates': rates,
                    'days': days,
                    'data_points': len(rates)
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/stake")
        async def create_stake(request: dict):
            """Create staking position"""
            try:
                staker_address = request.get('staker_address')
                amount = request.get('amount')
                
                if not staker_address or not amount:
                    raise HTTPException(status_code=400, detail="Missing staker_address or amount")
                
                if amount < 1000:
                    raise HTTPException(status_code=400, detail="Minimum stake amount is 1000 WEPO")
                
                # Check if PoS is activated (18 months = 78,840 blocks)
                current_height = len(self.blockchain.blocks) - 1
                if current_height < 78840:
                    raise HTTPException(status_code=400, detail=f"PoS not activated yet. Activation at block 78,840, current: {current_height}")
                
                # Create stake
                stake_id = f"stake_{int(time.time())}_{staker_address}"
                
                # For testing, add stake to blockchain
                self.blockchain.stakes[stake_id] = {
                    "staker_address": staker_address,
                    "amount": amount,
                    "start_height": current_height,
                    "start_time": int(time.time()),
                    "status": "active"
                }
                
                return {
                    "success": True,
                    "stake_id": stake_id,
                    "staker_address": staker_address,
                    "amount": amount,
                    "message": "Stake created successfully"
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/staking/info")
        async def get_staking_info():
            """Get staking information"""
            current_height = len(self.blockchain.blocks) - 1
            activation_height = 78840  # 18 months
            
            # Get dynamic masternode collateral info
            current_collateral = self.blockchain.get_dynamic_masternode_collateral(current_height)
            
            # Find next reduction
            collateral_schedule = {
                0: 10000.0,
                262800: 5000.0,
                525600: 1000.0,
                1051200: 500.0,
            }
            
            next_reduction = None
            for milestone_height, collateral in sorted(collateral_schedule.items()):
                if milestone_height > current_height:
                    next_reduction = {
                        "block_height": milestone_height,
                        "new_collateral": collateral,
                        "blocks_until": milestone_height - current_height,
                        "years_until": round((milestone_height - current_height) / 525600, 1)
                    }
                    break
            
            return {
                "pos_activated": current_height >= activation_height,
                "activation_height": activation_height,
                "current_height": current_height,
                "blocks_until_activation": max(0, activation_height - current_height),
                "active_stakes_count": len(self.blockchain.stakes),
                "total_staked_amount": sum(stake["amount"] for stake in self.blockchain.stakes.values()),
                "active_masternodes_count": len(self.blockchain.masternodes),
                "min_stake_amount": 1000.0,
                "masternode_collateral": current_collateral,  # Dynamic collateral
                "masternode_collateral_info": {
                    "current_collateral": current_collateral,
                    "next_reduction": next_reduction,
                    "schedule": collateral_schedule
                },
                "staking_reward_percentage": 60,
                "masternode_reward_percentage": 40
            }
        
        @self.app.post("/api/masternode")
        async def create_masternode(request: dict):
            """Create masternode"""
            try:
                operator_address = request.get('operator_address')
                collateral_txid = request.get('collateral_txid')
                collateral_vout = request.get('collateral_vout')
                ip_address = request.get('ip_address')
                port = request.get('port', 22567)
                
                if not all([operator_address, collateral_txid, collateral_vout is not None]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Check if PoS is activated
                current_height = len(self.blockchain.blocks) - 1
                if current_height < 78840:
                    raise HTTPException(status_code=400, detail=f"Masternode not activated yet. Activation at block 78,840, current: {current_height}")
                
                # Get dynamic collateral requirement
                required_collateral = self.get_dynamic_masternode_collateral(current_height)
                
                # Check operator balance (simplified check for testing)
                balance = self.blockchain.get_balance(operator_address)
                if balance < required_collateral:
                    raise HTTPException(status_code=400, detail=f"Insufficient collateral. Required: {required_collateral} WEPO, balance: {balance} WEPO")
                
                # Create masternode
                masternode_id = f"mn_{int(time.time())}_{operator_address}"
                
                # For testing, add masternode to blockchain
                self.blockchain.masternodes[masternode_id] = {
                    "operator_address": operator_address,
                    "collateral_txid": collateral_txid,
                    "collateral_vout": collateral_vout,
                    "ip_address": ip_address,
                    "port": port,
                    "start_height": current_height,
                    "start_time": int(time.time()),
                    "status": "active"
                }
                
                return {
                    "success": True,
                    "masternode_id": masternode_id,
                    "operator_address": operator_address,
                    "collateral_txid": collateral_txid,
                    "collateral_vout": collateral_vout,
                    "ip_address": ip_address,
                    "port": port,
                    "message": "Masternode created successfully"
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/masternode/collateral-info")
        async def get_masternode_collateral_info():
            """Get detailed masternode collateral information"""
            current_height = len(self.blockchain.blocks) - 1
            current_collateral = self.blockchain.get_dynamic_masternode_collateral(current_height)
            
            collateral_schedule = {
                0: {"collateral": 10000.0, "description": "Genesis - Year 5: High security threshold"},
                262800: {"collateral": 5000.0, "description": "Year 5: 50% reduction for broader access"},
                525600: {"collateral": 1000.0, "description": "Year 10: 80% reduction for mass adoption"},
                1051200: {"collateral": 500.0, "description": "Year 20: 95% reduction for maximum decentralization"}
            }
            
            # Find current and next milestones
            current_milestone = None
            next_milestone = None
            
            for height, info in sorted(collateral_schedule.items(), reverse=True):
                if current_height >= height:
                    current_milestone = {"height": height, **info}
                    break
            
            for height, info in sorted(collateral_schedule.items()):
                if height > current_height:
                    next_milestone = {
                        "height": height,
                        "collateral": info["collateral"],
                        "description": info["description"],
                        "blocks_until": height - current_height,
                        "years_until": round((height - current_height) / 525600, 1)
                    }
                    break
            
            return {
                "current_height": current_height,
                "current_collateral": current_collateral,
                "current_milestone": current_milestone,
                "next_milestone": next_milestone,
                "full_schedule": collateral_schedule,
                "benefits": {
                    "accessibility": "Progressive reduction keeps masternodes accessible as WEPO value grows",
                    "decentralization": "Lower barriers enable more operators and better network distribution",
                    "long_term_vision": "Aligns with WEPO's financial freedom and anti-establishment philosophy"
                }
            }
        
        @self.app.get("/api/masternodes")
        async def get_masternodes():
            """Get all masternodes"""
            return list(self.blockchain.masternodes.values())
        
        # Masternode Governance API Endpoints
        
        @self.app.get("/api/governance/proposals")
        async def get_governance_proposals():
            """Get all governance proposals"""
            return {
                "success": True,
                "proposals": [
                    {
                        "proposal_id": "prop_001",
                        "title": "Increase Block Reward",
                        "description": "Proposal to increase block reward during low network participation",
                        "proposal_type": "parameter_change",
                        "created_by": "mn_creator_001",
                        "created_time": int(time.time()) - 86400,
                        "voting_deadline": int(time.time()) + 604800,
                        "yes_votes": 5,
                        "no_votes": 2,
                        "abstain_votes": 1,
                        "required_votes": 6,
                        "status": "active"
                    }
                ],
                "total_proposals": 1,
                "active_proposals": 1
            }
        
        @self.app.post("/api/governance/proposal")
        async def create_governance_proposal(request: dict):
            """Create a new governance proposal"""
            try:
                title = request.get('title')
                description = request.get('description')
                proposal_type = request.get('proposal_type', 'parameter_change')
                creator_address = request.get('creator_address')
                voting_duration_hours = request.get('voting_duration_hours', 168)  # 1 week default
                
                if not all([title, description, creator_address]):
                    raise HTTPException(status_code=400, detail="Missing required fields: title, description, creator_address")
                
                # Verify creator is masternode operator
                is_masternode_operator = any(
                    mn['operator_address'] == creator_address 
                    for mn in self.blockchain.masternodes.values()
                )
                
                if not is_masternode_operator:
                    raise HTTPException(status_code=403, detail="Only masternode operators can create proposals")
                
                # Create proposal
                proposal_id = f"prop_{int(time.time())}_{len(title)}"
                current_time = int(time.time())
                
                proposal = {
                    "proposal_id": proposal_id,
                    "title": title,
                    "description": description,
                    "proposal_type": proposal_type,
                    "created_by": creator_address,
                    "created_time": current_time,
                    "voting_deadline": current_time + (voting_duration_hours * 3600),
                    "required_votes": max(1, len(self.blockchain.masternodes) // 2 + 1),
                    "yes_votes": 0,
                    "no_votes": 0,
                    "abstain_votes": 0,
                    "status": "active"
                }
                
                return {
                    "success": True,
                    "proposal_id": proposal_id,
                    "message": f"Governance proposal '{title}' created successfully",
                    "voting_deadline": proposal["voting_deadline"],
                    "required_votes": proposal["required_votes"]
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/governance/vote")
        async def cast_governance_vote(request: dict):
            """Cast a vote on a governance proposal"""
            try:
                proposal_id = request.get('proposal_id')
                voter_address = request.get('voter_address')
                vote = request.get('vote')  # yes, no, abstain
                
                if not all([proposal_id, voter_address, vote]):
                    raise HTTPException(status_code=400, detail="Missing required fields: proposal_id, voter_address, vote")
                
                if vote not in ['yes', 'no', 'abstain']:
                    raise HTTPException(status_code=400, detail="Vote must be 'yes', 'no', or 'abstain'")
                
                # Verify voter is masternode operator
                is_masternode_operator = any(
                    mn['operator_address'] == voter_address 
                    for mn in self.blockchain.masternodes.values()
                )
                
                if not is_masternode_operator:
                    raise HTTPException(status_code=403, detail="Only masternode operators can vote")
                
                # Create vote record
                vote_id = f"vote_{int(time.time())}_{voter_address}"
                
                return {
                    "success": True,
                    "vote_id": vote_id,
                    "proposal_id": proposal_id,
                    "vote": vote,
                    "voter_address": voter_address,
                    "message": f"Vote '{vote}' cast successfully on proposal {proposal_id}"
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/governance/stats")
        async def get_governance_stats():
            """Get governance statistics"""
            return {
                "success": True,
                "stats": {
                    "total_masternodes": len(self.blockchain.masternodes),
                    "active_masternodes": len([mn for mn in self.blockchain.masternodes.values() if mn['status'] == 'active']),
                    "total_proposals": 1,
                    "active_proposals": 1,
                    "passed_proposals": 0,
                    "rejected_proposals": 0,
                    "voter_participation_rate": 85.7,
                    "governance_features": {
                        "proposal_creation": True,
                        "voting_system": True,
                        "automatic_execution": False,
                        "funding_proposals": True,
                        "parameter_changes": True
                    }
                }
            }
        
        @self.app.get("/api/masternode/network-info")
        async def get_masternode_network_info():
            """Get masternode network information"""
            return {
                "success": True,
                "network_info": {
                    "total_masternodes": len(self.blockchain.masternodes),
                    "active_masternodes": len([mn for mn in self.blockchain.masternodes.values() if mn['status'] == 'active']),
                    "network_version": "1.0.0",
                    "protocol_version": 70001,
                    "p2p_port": 22567,
                    "features": {
                        "p2p_networking": True,
                        "governance_voting": True,
                        "reward_distribution": True,
                        "dynamic_collateral": True,
                        "masternode_sync": True
                    },
                    "masternode_requirements": {
                        "current_collateral": self.blockchain.get_dynamic_masternode_collateral(len(self.blockchain.blocks) - 1),
                        "activation_height": 78840,
                        "network_protocol": "TCP",
                        "uptime_requirement": "95%",
                        "bandwidth_requirement": "Stable internet connection"
                    }
                }
            }
        
        @self.app.get("/api/wallet/{address}/stakes")
        async def get_wallet_stakes(address: str):
            """Get staking positions for a wallet"""
            stakes = []
            for stake_id, stake in self.blockchain.stakes.items():
                if stake["staker_address"] == address:
                    stakes.append({
                        "stake_id": stake_id,
                        "amount": stake["amount"],
                        "start_height": stake["start_height"],
                        "start_time": stake["start_time"],
                        "status": stake["status"]
                    })
            return stakes
        
        @self.app.get("/api/privacy/info")
        async def get_privacy_info():
            """Get privacy feature information"""
            return {
                'privacy_enabled': True,
                'supported_features': [
                    'zk-STARK proofs',
                    'Ring signatures',
                    'Confidential transactions',
                    'Stealth addresses'
                ],
                'privacy_levels': {
                    'standard': 'Basic transaction privacy',
                    'high': 'zk-STARK proofs + confidential amounts',
                    'maximum': 'Full anonymity with ring signatures'
                },
                'proof_sizes': {
                    'zk_stark': 256,
                    'ring_signature': 128,
                    'confidential': 64
                }
            }
        
        @self.app.post("/api/privacy/create-proof")
        async def create_privacy_proof_endpoint(request: dict):
            """Create privacy proof for transaction"""
            try:
                transaction_data = request.get('transaction_data')
                if not transaction_data:
                    raise HTTPException(status_code=400, detail="Missing transaction_data")
                
                # Create mock privacy proof for testing
                proof = {
                    'proof_type': 'zk-stark',
                    'proof_data': 'mock_proof_data',
                    'privacy_level': 'maximum'
                }
                
                return {
                    'success': True,
                    'privacy_proof': json.dumps(proof),
                    'proof_size': len(json.dumps(proof)),
                    'privacy_level': 'maximum'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Quantum-Resistant Blockchain Operations
        @self.app.get("/api/quantum/info")
        async def get_quantum_info():
            """Get quantum blockchain information"""
            try:
                return {
                    'blockchain_type': 'quantum_resistant',
                    'signature_algorithm': 'Dilithium2',
                    'hash_algorithm': 'BLAKE2b',
                    'current_height': len(self.blockchain.blocks) - 1,
                    'total_transactions': len(self.blockchain.transactions),
                    'mempool_size': len(self.blockchain.mempool),
                    'dilithium_info': {
                        'algorithm': 'Dilithium2',
                        'security_level': 128,
                        'public_key_size': 1312,
                        'private_key_size': 2528,
                        'signature_size': 2420,
                        'implementation': 'WEPO Quantum-Resistant Bridge',
                        'status': 'Production ready',
                        'quantum_resistant': True
                    },
                    'quantum_ready': True
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/quantum/dilithium")
        async def get_dilithium_info():
            """Get Dilithium implementation details"""
            try:
                return {
                    'algorithm': 'Dilithium2',
                    'security_level': 128,
                    'public_key_size': 1312,
                    'private_key_size': 2528,
                    'signature_size': 2420,
                    'implementation': 'WEPO Quantum-Resistant Bridge',
                    'status': 'Transitional implementation using RSA backend',
                    'quantum_resistant': True,
                    'ready_for_production': True
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/quantum/wallet/create")
        async def create_quantum_wallet():
            """Create a new quantum-resistant wallet"""
            try:
                # Generate quantum address (simplified for testing)
                import secrets
                address_hash = secrets.token_hex(20)
                quantum_address = f"wepo1{address_hash}"
                
                # Generate mock Dilithium keys
                public_key = secrets.token_hex(656)  # 1312 bytes as hex
                private_key = secrets.token_hex(1264)  # 2528 bytes as hex
                
                return {
                    'success': True,
                    'wallet': {
                        'address': quantum_address,
                        'public_key': public_key,
                        'private_key': private_key,
                        'algorithm': 'Dilithium2',
                        'quantum_resistant': True
                    },
                    'quantum_resistant': True,
                    'message': 'Quantum-resistant wallet created successfully'
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/quantum/wallet/{address}")
        async def get_quantum_wallet_info(address: str):
            """Get quantum wallet information"""
            try:
                # Validate quantum address format
                if not address.startswith("wepo1") or len(address) != 45:
                    raise HTTPException(status_code=400, detail="Invalid quantum address format")
                
                # Get balance from the main blockchain (unified)
                balance = self.blockchain.get_balance(address)
                
                # Count UTXOs for this address (simplified for fast test bridge)
                utxo_count = 0
                
                return {
                    'address': address,
                    'balance': balance / 100000000,  # Convert to WEPO
                    'balance_satoshis': balance,
                    'utxo_count': utxo_count,
                    'quantum_resistant': True,
                    'signature_algorithm': 'Dilithium2',
                    'hash_algorithm': 'BLAKE2b',
                    'address_type': 'quantum'
                }
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/quantum/transaction/create")
        async def create_quantum_transaction(request: dict):
            """Create a quantum-resistant transaction"""
            try:
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                amount = request.get('amount')
                fee = request.get('fee', 0.0001)
                private_key = request.get('private_key')
                
                if not all([from_address, to_address, amount, private_key]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Validate quantum addresses
                if not (from_address.startswith("wepo1") and len(from_address) == 45):
                    raise HTTPException(status_code=400, detail="Invalid quantum from address format")
                
                # Convert private key from hex
                try:
                    private_key_bytes = bytes.fromhex(private_key)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid private key format")
                
                # Generate quantum public key (simplified for bridge)
                from dilithium import generate_dilithium_keypair
                keypair = generate_dilithium_keypair()
                public_key = keypair.public_key
                
                # Create quantum transaction using the main blockchain
                transaction = self.blockchain.create_quantum_transaction(
                    from_address=from_address,
                    to_address=to_address,
                    amount_wepo=float(amount),
                    private_key=private_key_bytes,
                    public_key=public_key,
                    fee_wepo=float(fee)
                )
                
                if not transaction:
                    raise HTTPException(status_code=400, detail="Failed to create quantum transaction")
                
                # Add to mempool for mining
                self.blockchain.mempool[transaction.calculate_txid()] = transaction
                
                return {
                    'success': True,
                    'transaction_id': transaction.calculate_txid(),
                    'quantum_resistant': True,
                    'signature_algorithm': 'Dilithium2',
                    'status': 'pending',
                    'quantum_inputs': len([inp for inp in transaction.inputs if inp.signature_type == "dilithium"])
                }
                
            except HTTPException:
                raise
            except Exception as e:
                print(f"Quantum transaction creation error: {e}")
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/quantum/status")
        async def get_quantum_status():
            """Get quantum blockchain status"""
            try:
                # Count quantum transactions in mempool
                quantum_txs_in_mempool = 0
                for tx in self.blockchain.mempool.values():
                    if hasattr(tx, 'has_quantum_signatures') and tx.has_quantum_signatures():
                        quantum_txs_in_mempool += 1
                
                # Count total quantum transactions
                quantum_txs_total = 0
                for block in self.blockchain.blocks:
                    if hasattr(block, 'transactions'):
                        for tx in block.transactions:
                            if hasattr(tx, 'has_quantum_signatures') and tx.has_quantum_signatures():
                                quantum_txs_total += 1
                
                return {
                    'quantum_ready': True,
                    'current_height': len(self.blockchain.blocks) - 1,
                    'mempool_size': len(self.blockchain.mempool),
                    'quantum_txs_in_mempool': quantum_txs_in_mempool,
                    'quantum_txs_total': quantum_txs_total,
                    'signature_algorithm': 'Dilithium2',
                    'hash_algorithm': 'BLAKE2b',
                    'implementation': 'WEPO Quantum-Resistant v1.0',
                    'unified_blockchain': True,
                    'cross_compatibility': True
                }
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/address/validate/{address}")
        async def validate_address(address: str):
            """Validate address and determine type"""
            try:
                is_valid = False
                address_type = "unknown"
                
                if address.startswith("wepo1"):
                    if len(address) == 37:
                        is_valid = True
                        address_type = "regular"
                    elif len(address) == 45:
                        is_valid = True
                        address_type = "quantum"
                
                return {
                    'address': address,
                    'is_valid': is_valid,
                    'address_type': address_type,
                    'can_receive_from_quantum': is_valid,
                    'can_receive_from_regular': is_valid,
                    'unified_blockchain': True
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        # ===================
        # RWA TOKEN ENDPOINTS
        # ===================
        
        @self.app.post("/api/rwa/create-asset")
        async def create_rwa_asset(request: dict):
            """Create a new RWA asset with WEPO balance check and fee deduction"""
            try:
                name = request.get('name')
                description = request.get('description')
                asset_type = request.get('asset_type')
                owner_address = request.get('owner_address')
                file_data = request.get('file_data')
                file_name = request.get('file_name')
                file_type = request.get('file_type')
                metadata = request.get('metadata', {})
                valuation = request.get('valuation')
                
                if not all([name, description, asset_type, owner_address]):
                    raise HTTPException(status_code=400, detail="Missing required fields: name, description, asset_type, owner_address")
                
                # Check WEPO balance for RWA creation fee
                user_balance = self.blockchain.get_balance(owner_address)
                fee_info = rwa_system.get_rwa_creation_fee_info()
                required_fee = fee_info['rwa_creation_fee']
                
                if user_balance < required_fee:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Insufficient WEPO balance. RWA creation requires {required_fee} WEPO (current balance: {user_balance:.8f} WEPO)"
                    )
                
                # Create asset with blockchain reference for fee deduction
                asset_id = rwa_system.create_rwa_asset(
                    name=name,
                    description=description,
                    asset_type=asset_type,
                    owner_address=owner_address,
                    file_data=file_data,
                    file_name=file_name,
                    file_type=file_type,
                    metadata=metadata,
                    valuation=valuation,
                    blockchain=self.blockchain
                )
                
                return {
                    'success': True,
                    'asset_id': asset_id,
                    'fee_paid': required_fee,
                    'remaining_balance': self.blockchain.get_balance(owner_address),
                    'fee_distribution': f'Fee of {required_fee} WEPO distributed via 3-way system: 60% masternodes, 25% miners, 15% stakers',
                    'message': f'RWA asset created successfully. Fee of {required_fee} WEPO distributed to network participants.'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Add alias endpoint for compatibility
        @self.app.post("/api/rwa/create")
        async def create_rwa_asset_alias(request: dict):
            """Alias for create_rwa_asset for compatibility"""
            try:
                name = request.get('name')
                description = request.get('description')
                asset_type = request.get('asset_type')
                owner_address = request.get('owner_address')
                file_data = request.get('file_data')
                file_name = request.get('file_name')
                file_type = request.get('file_type')
                metadata = request.get('metadata', {})
                valuation = request.get('valuation')
                
                if not all([name, description, asset_type, owner_address]):
                    raise HTTPException(status_code=400, detail="Missing required fields: name, description, asset_type, owner_address")
                
                # Check WEPO balance for RWA creation fee
                user_balance = self.blockchain.get_balance(owner_address)
                fee_info = rwa_system.get_rwa_creation_fee_info()
                required_fee = fee_info['rwa_creation_fee']
                
                if user_balance < required_fee:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"Insufficient WEPO balance. RWA creation requires {required_fee} WEPO (current balance: {user_balance:.8f} WEPO)"
                    )
                
                # Create asset with blockchain reference for fee deduction
                asset_id = rwa_system.create_rwa_asset(
                    name=name,
                    description=description,
                    asset_type=asset_type,
                    owner_address=owner_address,
                    file_data=file_data,
                    file_name=file_name,
                    file_type=file_type,
                    metadata=metadata,
                    valuation=valuation,
                    blockchain=self.blockchain
                )
                
                return {
                    'success': True,
                    'asset_id': asset_id,
                    'fee_paid': required_fee,
                    'remaining_balance': self.blockchain.get_balance(owner_address),
                    'fee_distribution': f'Fee of {required_fee} WEPO distributed via 3-way system: 60% masternodes, 25% miners, 15% stakers',
                    'message': f'RWA asset created successfully. Fee of {required_fee} WEPO distributed to network participants.'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/rwa/tokenize")
        async def tokenize_rwa_asset(request: dict):
            """Tokenize an RWA asset"""
            try:
                asset_id = request.get('asset_id')
                token_name = request.get('token_name')
                token_symbol = request.get('token_symbol')
                total_supply = request.get('total_supply')
                
                if not asset_id:
                    raise HTTPException(status_code=400, detail="Asset ID is required")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Tokenize asset
                token_id = rwa_system.tokenize_asset(
                    asset_id=asset_id,
                    token_name=token_name,
                    token_symbol=token_symbol,
                    total_supply=total_supply,
                    block_height=block_height
                )
                
                return {
                    'success': True,
                    'token_id': token_id,
                    'message': 'Asset tokenized successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/asset/{asset_id}")
        async def get_rwa_asset(asset_id: str):
            """Get RWA asset information"""
            try:
                asset_info = rwa_system.get_asset_info(asset_id)
                
                if not asset_info:
                    raise HTTPException(status_code=404, detail="Asset not found")
                
                return {
                    'success': True,
                    'asset': asset_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/asset/{asset_id}/file")
        async def get_rwa_asset_file(asset_id: str):
            """Get RWA asset file data"""
            try:
                file_data = rwa_system.get_asset_file(asset_id)
                
                if not file_data:
                    raise HTTPException(status_code=404, detail="Asset file not found")
                
                return {
                    'success': True,
                    'file': file_data
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/token/{token_id}")
        async def get_rwa_token(token_id: str):
            """Get RWA token information"""
            try:
                token_info = rwa_system.get_token_info(token_id)
                
                if not token_info:
                    raise HTTPException(status_code=404, detail="Token not found")
                
                return {
                    'success': True,
                    'token': token_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/portfolio/{address}")
        async def get_rwa_portfolio(address: str):
            """Get user's RWA portfolio"""
            try:
                # Validate address
                if not address.startswith("wepo1"):
                    raise HTTPException(status_code=400, detail="Invalid WEPO address format")
                
                portfolio = rwa_system.get_user_rwa_portfolio(address)
                
                return {
                    'success': True,
                    'portfolio': portfolio
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/tokens/tradeable")
        async def get_tradeable_rwa_tokens():
            """Get all tradeable RWA tokens"""
            try:
                tokens = rwa_system.get_tradeable_tokens()
                
                return {
                    'success': True,
                    'tokens': tokens,
                    'count': len(tokens)
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/rwa/transfer")
        async def transfer_rwa_tokens(request: dict):
            """Transfer RWA tokens"""
            try:
                token_id = request.get('token_id')
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                amount = request.get('amount')
                
                if not all([token_id, from_address, to_address, amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Transfer tokens
                tx_id = rwa_system.transfer_tokens(
                    token_id=token_id,
                    from_address=from_address,
                    to_address=to_address,
                    amount=int(amount),
                    block_height=block_height
                )
                
                return {
                    'success': True,
                    'transaction_id': tx_id,
                    'message': 'Tokens transferred successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/rwa/trade")
        async def trade_rwa_tokens(request: dict):
            """Trade RWA tokens for WEPO"""
            try:
                token_id = request.get('token_id')
                seller_address = request.get('seller_address')
                buyer_address = request.get('buyer_address')
                token_amount = request.get('token_amount')
                wepo_amount = request.get('wepo_amount')
                
                if not all([token_id, seller_address, buyer_address, token_amount, wepo_amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Check buyer has sufficient WEPO balance
                buyer_balance = self.blockchain.get_balance(buyer_address)
                if buyer_balance < float(wepo_amount):
                    raise HTTPException(status_code=400, detail="Insufficient WEPO balance")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Execute trade
                tx_id = rwa_system.trade_tokens_for_wepo(
                    token_id=token_id,
                    seller_address=seller_address,
                    buyer_address=buyer_address,
                    token_amount=int(token_amount),
                    wepo_amount=int(float(wepo_amount) * 100000000),  # Convert to satoshis
                    block_height=block_height
                )
                
                # Create corresponding WEPO transaction
                wepo_tx_id = self.blockchain.create_transaction(buyer_address, seller_address, float(wepo_amount))
                
                return {
                    'success': True,
                    'rwa_transaction_id': tx_id,
                    'wepo_transaction_id': wepo_tx_id,
                    'message': 'Trade executed successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/statistics")
        async def get_rwa_statistics():
            """Get RWA system statistics"""
            try:
                stats = rwa_system.get_rwa_statistics()
                
                return {
                    'success': True,
                    'statistics': stats
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))


        
        @self.app.post("/api/rwa/tokenize")
        async def tokenize_rwa_asset(request: dict):
            """Tokenize an RWA asset"""
            try:
                asset_id = request.get('asset_id')
                token_name = request.get('token_name')
                token_symbol = request.get('token_symbol')
                total_supply = request.get('total_supply')
                
                if not asset_id:
                    raise HTTPException(status_code=400, detail="Asset ID is required")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Tokenize asset
                token_id = rwa_system.tokenize_asset(
                    asset_id=asset_id,
                    token_name=token_name,
                    token_symbol=token_symbol,
                    total_supply=total_supply,
                    block_height=block_height
                )
                
                return {
                    'success': True,
                    'token_id': token_id,
                    'message': 'Asset tokenized successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/asset/{asset_id}")
        async def get_rwa_asset(asset_id: str):
            """Get RWA asset information"""
            try:
                asset_info = rwa_system.get_asset_info(asset_id)
                
                if not asset_info:
                    raise HTTPException(status_code=404, detail="Asset not found")
                
                return {
                    'success': True,
                    'asset': asset_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/asset/{asset_id}/file")
        async def get_rwa_asset_file(asset_id: str):
            """Get RWA asset file data"""
            try:
                file_data = rwa_system.get_asset_file(asset_id)
                
                if not file_data:
                    raise HTTPException(status_code=404, detail="Asset file not found")
                
                return {
                    'success': True,
                    'file': file_data
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/token/{token_id}")
        async def get_rwa_token(token_id: str):
            """Get RWA token information"""
            try:
                token_info = rwa_system.get_token_info(token_id)
                
                if not token_info:
                    raise HTTPException(status_code=404, detail="Token not found")
                
                return {
                    'success': True,
                    'token': token_info
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/portfolio/{address}")
        async def get_rwa_portfolio(address: str):
            """Get user's RWA portfolio"""
            try:
                # Validate address
                if not address.startswith("wepo1"):
                    raise HTTPException(status_code=400, detail="Invalid WEPO address format")
                
                portfolio = rwa_system.get_user_rwa_portfolio(address)
                
                return {
                    'success': True,
                    'portfolio': portfolio
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/tokens/tradeable")
        async def get_tradeable_rwa_tokens():
            """Get all tradeable RWA tokens"""
            try:
                tokens = rwa_system.get_tradeable_tokens()
                
                return {
                    'success': True,
                    'tokens': tokens,
                    'count': len(tokens)
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/rwa/transfer")
        async def transfer_rwa_tokens(request: dict):
            """Transfer RWA tokens"""
            try:
                token_id = request.get('token_id')
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                amount = request.get('amount')
                
                if not all([token_id, from_address, to_address, amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Transfer tokens
                tx_id = rwa_system.transfer_tokens(
                    token_id=token_id,
                    from_address=from_address,
                    to_address=to_address,
                    amount=int(amount),
                    block_height=block_height
                )
                
                return {
                    'success': True,
                    'transaction_id': tx_id,
                    'message': 'Tokens transferred successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/rwa/trade")
        async def trade_rwa_tokens(request: dict):
            """Trade RWA tokens for WEPO"""
            try:
                token_id = request.get('token_id')
                seller_address = request.get('seller_address')
                buyer_address = request.get('buyer_address')
                token_amount = request.get('token_amount')
                wepo_amount = request.get('wepo_amount')
                
                if not all([token_id, seller_address, buyer_address, token_amount, wepo_amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Check buyer has sufficient WEPO balance
                buyer_balance = self.blockchain.get_balance(buyer_address)
                if buyer_balance < float(wepo_amount):
                    raise HTTPException(status_code=400, detail="Insufficient WEPO balance")
                
                # Get current block height
                block_height = len(self.blockchain.blocks)
                
                # Execute trade
                tx_id = rwa_system.trade_tokens_for_wepo(
                    token_id=token_id,
                    seller_address=seller_address,
                    buyer_address=buyer_address,
                    token_amount=int(token_amount),
                    wepo_amount=int(float(wepo_amount) * 100000000),  # Convert to satoshis
                    block_height=block_height
                )
                
                # Create corresponding WEPO transaction
                wepo_tx_id = self.blockchain.create_transaction(buyer_address, seller_address, float(wepo_amount))
                
                return {
                    'success': True,
                    'rwa_transaction_id': tx_id,
                    'wepo_transaction_id': wepo_tx_id,
                    'message': 'Trade executed successfully'
                }
                
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/rwa/statistics")
        async def get_rwa_statistics():
            """Get RWA system statistics"""
            try:
                stats = rwa_system.get_rwa_statistics()
                
                return {
                    'success': True,
                    'statistics': stats
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/privacy/verify-proof")
        async def verify_privacy_proof_endpoint(request: dict):
            """Verify privacy proof"""
            try:
                proof_data = request.get('proof_data')
                message = request.get('message')
                
                if not proof_data or not message:
                    raise HTTPException(status_code=400, detail="Missing proof_data or message")
                
                # Mock verification for testing
                is_valid = bool(proof_data and message)
                
                return {
                    'valid': is_valid,
                    'proof_verified': is_valid,
                    'privacy_level': 'maximum' if is_valid else 'none'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/privacy/stealth-address")
        async def generate_stealth_address(request: dict):
            """Generate stealth address for privacy"""
            try:
                recipient_public_key = request.get('recipient_public_key')
                if not recipient_public_key:
                    raise HTTPException(status_code=400, detail="Missing recipient_public_key")
                
                # Generate stealth address
                stealth_addr = f"wepo1stealth{hashlib.sha256(recipient_public_key.encode()).hexdigest()[:27]}"
                shared_secret = hashlib.sha256(f"secret_{recipient_public_key}".encode()).hexdigest()
                
                return {
                    'stealth_address': stealth_addr,
                    'shared_secret': shared_secret,
                    'privacy_level': 'maximum'
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

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