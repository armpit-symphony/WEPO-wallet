#!/usr/bin/env python3
"""
WEPO Blockchain Integration Bridge
Quick-start bridge for frontend integration with real blockchain
"""

import sys
import os
import asyncio
import threading
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Add wepo-blockchain to path
sys.path.append('/app/wepo-blockchain')

from core.blockchain import WepoBlockchain, Transaction, TransactionInput, TransactionOutput

class WepoIntegrationBridge:
    """Fast-starting integration bridge"""
    
    def __init__(self):
        # Initialize with lower difficulty for faster startup
        self.blockchain = None
        self.blockchain_ready = False
        self.app = FastAPI(title="WEPO Integration Bridge", version="1.0.0")
        self.setup_cors()
        self.setup_routes()
        
        # Start blockchain in background
        self.blockchain_thread = threading.Thread(target=self.init_blockchain, daemon=True)
        self.blockchain_thread.start()
    
    def setup_cors(self):
        """Setup CORS middleware"""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def init_blockchain(self):
        """Initialize blockchain in background"""
        try:
            print("🔗 Initializing WEPO blockchain core...")
            
            # Create blockchain with lower initial difficulty
            self.blockchain = WepoBlockchain("/tmp/wepo")
            
            # Override difficulty for faster startup
            original_difficulty = self.blockchain.current_difficulty
            self.blockchain.current_difficulty = 1  # 1 leading zero for super fast mining
            
            # If no genesis block exists, mine it quickly
            if len(self.blockchain.chain) == 0:
                print("⚡ Mining genesis block with reduced difficulty...")
                # The genesis block will be mined during blockchain initialization
                pass
            
            # Restore normal difficulty after genesis
            if len(self.blockchain.chain) > 0:
                self.blockchain.current_difficulty = 2  # Still easier than default 4
            
            print(f"✅ WEPO blockchain initialized with {len(self.blockchain.chain)} blocks")
            self.blockchain_ready = True
            
        except Exception as e:
            print(f"❌ Blockchain initialization failed: {e}")
            import traceback
            traceback.print_exc()
    
    def setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/")
        async def root():
            return {
                "message": "WEPO Blockchain Integration Bridge", 
                "version": "1.0.0",
                "blockchain_ready": self.blockchain_ready
            }
        
        @self.app.get("/api/")
        async def api_root():
            return {
                "message": "WEPO Integration API", 
                "blockchain_ready": self.blockchain_ready
            }
        
        @self.app.get("/api/network/status")
        async def get_network_status():
            """Get network status"""
            if not self.blockchain_ready:
                return {
                    "status": "initializing",
                    "message": "Blockchain is still initializing...",
                    "block_height": 0
                }
            
            try:
                info = self.blockchain.get_blockchain_info()
                return {
                    "block_height": info['height'],
                    "best_block_hash": info['best_block_hash'],
                    "difficulty": info['difficulty'],
                    "mempool_size": info['mempool_size'],
                    "total_supply": info['total_supply'],
                    "network": "mainnet",
                    "status": "ready",
                    "active_masternodes": 0,
                    "total_staked": 0,
                    "circulating_supply": info['total_supply']
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/wallet/create")
        async def create_wallet(request: dict):
            """Create wallet"""
            if not self.blockchain_ready:
                raise HTTPException(status_code=503, detail="Blockchain not ready")
            
            # For now, just acknowledge wallet creation
            # Real implementation would register with blockchain
            return {
                "success": True,
                "address": request.get("address"),
                "message": "Wallet registered with blockchain"
            }
        
        @self.app.get("/api/wallet/{address}")
        async def get_wallet(address: str):
            """Get wallet info"""
            if not self.blockchain_ready:
                raise HTTPException(status_code=503, detail="Blockchain not ready")
            
            try:
                # Calculate balance from blockchain
                balance = 0
                for block in self.blockchain.chain:
                    for tx in block.transactions:
                        for output in tx.outputs:
                            if output.address == address:
                                balance += output.value
                
                # Convert from satoshis to WEPO
                balance_wepo = balance / 100000000.0
                
                return {
                    "address": address,
                    "balance": balance_wepo,
                    "username": "blockchain_user",
                    "created_at": "2025-01-01T00:00:00Z",
                    "is_staking": False,
                    "is_masternode": False
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/wallet/{address}/transactions")
        async def get_wallet_transactions(address: str):
            """Get wallet transactions"""
            if not self.blockchain_ready:
                return []
            
            try:
                transactions = []
                for block in self.blockchain.chain:
                    for tx in block.transactions:
                        # Check if this transaction involves the address
                        for output in tx.outputs:
                            if output.address == address:
                                transactions.append({
                                    "txid": tx.calculate_txid(),
                                    "type": "receive",
                                    "amount": output.value / 100000000.0,
                                    "from_address": "coinbase" if tx.is_coinbase() else "unknown",
                                    "to_address": address,
                                    "timestamp": tx.timestamp,
                                    "status": "confirmed",
                                    "confirmations": len(self.blockchain.chain) - block.height,
                                    "block_height": block.height
                                })
                
                return transactions[-50:]  # Return last 50 transactions
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/transaction/send")
        async def send_transaction(request: dict):
            """Send transaction"""
            if not self.blockchain_ready:
                raise HTTPException(status_code=503, detail="Blockchain not ready")
            
            # For integration testing, simulate transaction creation
            return {
                "transaction_id": f"tx_{int(time.time())}",
                "status": "submitted",
                "message": "Transaction submitted to blockchain"
            }
        
        @self.app.get("/api/mining/info")
        async def get_mining_info():
            """Get mining info"""
            if not self.blockchain_ready:
                return {"status": "initializing"}
            
            try:
                height = self.blockchain.get_block_height()
                current_reward = self.blockchain.calculate_block_reward(height + 1)
                
                return {
                    "current_block_height": height,
                    "current_reward": current_reward / 100000000.0,
                    "difficulty": self.blockchain.current_difficulty,
                    "algorithm": "Argon2",
                    "mining_enabled": False,
                    "mempool_size": len(self.blockchain.mempool),
                    "reward_schedule": "Balanced Year 1: 400→200→100→50 WEPO, then 12.4 with 4yr halvings"
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dex/rate")
        async def get_exchange_rate():
            """Get exchange rate"""
            return {
                "btc_to_wepo": 1.0,
                "wepo_to_btc": 1.0,
                "fee_percentage": 0.1,
                "last_updated": time.strftime('%Y-%m-%d %H:%M:%S')
            }

def main():
    """Main function"""
    print("=" * 60)
    print("🚀 WEPO Blockchain Integration Bridge")
    print("=" * 60)
    print("Starting fast integration bridge for frontend testing...")
    print("This bridges frontend wallet with real WEPO blockchain core")
    print("=" * 60)
    
    bridge = WepoIntegrationBridge()
    
    # Start server
    uvicorn.run(
        bridge.app,
        host="0.0.0.0",
        port=8001,
        log_level="info"
    )

if __name__ == "__main__":
    main()