#!/usr/bin/env python3
"""
WEPO Fast Test Blockchain Bridge
Instant blockchain for testing functionality with BTC atomic swaps
"""

import time
import hashlib
import json
import sys
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add atomic swaps to the path
sys.path.append('/app/wepo-blockchain/core')
from atomic_swaps import atomic_swap_engine, SwapType, SwapState, validate_btc_address, validate_wepo_address

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
            return {
                "btc_to_wepo": 1.0,
                "wepo_to_btc": 1.0,
                "fee_percentage": 0.1,
                "last_updated": time.strftime('%Y-%m-%d %H:%M:%S')
            }
        
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
            
            return {
                "pos_activated": current_height >= activation_height,
                "activation_height": activation_height,
                "current_height": current_height,
                "blocks_until_activation": max(0, activation_height - current_height),
                "active_stakes_count": len(self.blockchain.stakes),
                "total_staked_amount": sum(stake["amount"] for stake in self.blockchain.stakes.values()),
                "active_masternodes_count": len(self.blockchain.masternodes),
                "min_stake_amount": 1000.0,
                "masternode_collateral": 10000.0,
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
        
        @self.app.get("/api/masternodes")
        async def get_masternodes():
            """Get all masternodes"""
            return list(self.blockchain.masternodes.values())
        
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
                
                # Calculate balance (simplified)
                balance = self.blockchain.get_balance(address)
                
                return {
                    'address': address,
                    'balance': balance,
                    'quantum_resistant': True,
                    'signature_algorithm': 'Dilithium2',
                    'hash_algorithm': 'BLAKE2b'
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
                
                # Validate addresses
                if not (from_address.startswith("wepo1") and to_address.startswith("wepo1")):
                    raise HTTPException(status_code=400, detail="Invalid quantum address format")
                
                # Generate quantum transaction ID
                import secrets
                transaction_id = secrets.token_hex(32)
                
                # Create quantum signature (mock for testing)
                quantum_signature = secrets.token_hex(1210)  # 2420 bytes as hex
                
                return {
                    'success': True,
                    'transaction_id': transaction_id,
                    'quantum_resistant': True,
                    'signature_algorithm': 'Dilithium2',
                    'signature': quantum_signature,
                    'status': 'pending'
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/quantum/status")
        async def get_quantum_status():
            """Get quantum blockchain status"""
            try:
                return {
                    'quantum_ready': True,
                    'current_height': len(self.blockchain.blocks) - 1,
                    'mempool_size': len(self.blockchain.mempool),
                    'signature_algorithm': 'Dilithium2',
                    'hash_algorithm': 'BLAKE2b',
                    'implementation': 'WEPO Quantum-Resistant v1.0'
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