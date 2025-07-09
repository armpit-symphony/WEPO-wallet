#!/usr/bin/env python3
"""
WEPO Wallet Daemon
Bridges blockchain core with wallet interfaces (web, desktop, mobile)
"""

import asyncio
import json
import time
import hashlib
import os
import sys
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import sqlite3
import threading

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.blockchain import WepoBlockchain, Transaction, TransactionInput, TransactionOutput

# Wallet Daemon Constants
DEFAULT_WALLETD_PORT = 8002
DEFAULT_NODE_PORT = 8001
WALLET_DB_PATH = "/tmp/wepo/wallets.db"
SYNC_INTERVAL = 10  # seconds

@dataclass
class WalletInfo:
    """Wallet information"""
    address: str
    username: str
    balance: float
    created_at: str
    last_activity: str
    is_staking: bool = False
    stake_amount: float = 0.0
    is_masternode: bool = False
    masternode_collateral: float = 0.0

@dataclass
class TransactionHistory:
    """Transaction history entry"""
    txid: str
    type: str  # 'send', 'receive', 'stake', 'masternode'
    amount: float
    from_address: str
    to_address: str
    timestamp: str
    status: str
    confirmations: int
    block_height: Optional[int] = None

class WepoWalletDaemon:
    """WEPO Wallet Daemon"""
    
    def __init__(self, node_host: str = "localhost", node_port: int = DEFAULT_NODE_PORT,
                 walletd_port: int = DEFAULT_WALLETD_PORT):
        self.node_host = node_host
        self.node_port = node_port
        self.walletd_port = walletd_port
        self.node_url = f"http://{node_host}:{node_port}"
        
        # FastAPI app
        self.app = FastAPI(title="WEPO Wallet Daemon", version="1.0.0")
        
        # WebSocket connections for real-time updates
        self.websocket_connections: List[WebSocket] = []
        
        # Wallet database
        self.wallet_db_path = WALLET_DB_PATH
        self.init_wallet_db()
        
        # Sync state
        self.last_sync_height = 0
        self.sync_running = False
        
        # Setup CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup routes
        self.setup_routes()
        
        print(f"WEPO Wallet Daemon initialized")
        print(f"Node URL: {self.node_url}")
        print(f"Wallet DB: {self.wallet_db_path}")
    
    def init_wallet_db(self):
        """Initialize wallet database"""
        os.makedirs(os.path.dirname(self.wallet_db_path), exist_ok=True)
        
        self.wallet_conn = sqlite3.connect(self.wallet_db_path, check_same_thread=False)
        self.wallet_conn.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                balance REAL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                is_staking BOOLEAN DEFAULT FALSE,
                stake_amount REAL DEFAULT 0.0,
                is_masternode BOOLEAN DEFAULT FALSE,
                masternode_collateral REAL DEFAULT 0.0
            )
        ''')
        
        self.wallet_conn.execute('''
            CREATE TABLE IF NOT EXISTS wallet_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wallet_address TEXT NOT NULL,
                txid TEXT NOT NULL,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                from_address TEXT NOT NULL,
                to_address TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                confirmations INTEGER DEFAULT 0,
                block_height INTEGER,
                FOREIGN KEY(wallet_address) REFERENCES wallets(address)
            )
        ''')
        
        self.wallet_conn.commit()
        print("Wallet database initialized")
    
    def setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.get("/")
        async def root():
            return {"message": "WEPO Wallet Daemon", "version": "1.0.0"}
        
        @self.app.get("/api/")
        async def api_root():
            return {"message": "WEPO Wallet API", "version": "1.0.0"}
        
        # Network status
        @self.app.get("/api/network/status")
        async def get_network_status():
            """Get network status from blockchain node"""
            try:
                response = requests.get(f"{self.node_url}/api/network/status", timeout=10)
                if response.status_code == 200:
                    return response.json()
                else:
                    raise HTTPException(status_code=503, detail="Node unavailable")
            except Exception as e:
                raise HTTPException(status_code=503, detail=f"Node connection failed: {e}")
        
        # Wallet management
        @self.app.post("/api/wallet/create")
        async def create_wallet(request: dict):
            """Create a new wallet"""
            try:
                username = request.get('username')
                address = request.get('address')
                encrypted_private_key = request.get('encrypted_private_key')
                
                if not all([username, address, encrypted_private_key]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Check if wallet already exists
                cursor = self.wallet_conn.execute(
                    "SELECT address FROM wallets WHERE username = ? OR address = ?",
                    (username, address)
                )
                if cursor.fetchone():
                    raise HTTPException(status_code=400, detail="Wallet already exists")
                
                # Create wallet
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                self.wallet_conn.execute('''
                    INSERT INTO wallets (address, username, encrypted_private_key, created_at, last_activity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (address, username, encrypted_private_key, now, now))
                self.wallet_conn.commit()
                
                # Notify WebSocket clients
                await self.broadcast_wallet_update(address, "wallet_created")
                
                return {"success": True, "address": address}
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/wallet/{address}")
        async def get_wallet(address: str):
            """Get wallet information with proper validation"""
            try:
                # Validate address format
                if not address or not address.startswith("wepo1") or len(address) < 30:
                    raise HTTPException(status_code=400, detail="Invalid address format")
                
                cursor = self.wallet_conn.execute(
                    "SELECT * FROM wallets WHERE address = ?", (address,)
                )
                wallet_row = cursor.fetchone()
                
                if not wallet_row:
                    # Check if address has any activity on blockchain
                    try:
                        response = requests.get(f"{self.node_url}/api/wallet/{address}", timeout=10)
                        if response.status_code == 200:
                            # Address exists on blockchain but not in wallet DB
                            # Return blockchain data
                            blockchain_data = response.json()
                            return {
                                'address': address,
                                'username': 'unknown',
                                'balance': blockchain_data.get('balance', 0),
                                'created_at': '2025-01-01T00:00:00Z',
                                'last_activity': '2025-01-01T00:00:00Z',
                                'is_staking': False,
                                'stake_amount': 0,
                                'is_masternode': False,
                                'masternode_collateral': 0
                            }
                        else:
                            raise HTTPException(status_code=404, detail="Wallet not found")
                    except requests.RequestException:
                        raise HTTPException(status_code=503, detail="Blockchain node unavailable")
                
                # Parse wallet data
                wallet_data = {
                    'address': wallet_row[0],
                    'username': wallet_row[1],
                    'balance': wallet_row[3],
                    'created_at': wallet_row[4],
                    'last_activity': wallet_row[5],
                    'is_staking': bool(wallet_row[6]),
                    'stake_amount': wallet_row[7],
                    'is_masternode': bool(wallet_row[8]),
                    'masternode_collateral': wallet_row[9]
                }
                
                # Update balance from blockchain
                await self.update_wallet_balance(address)
                
                return wallet_data
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/wallet/{address}/transactions")
        async def get_wallet_transactions(address: str, limit: int = 50):
            """Get wallet transaction history"""
            try:
                cursor = self.wallet_conn.execute('''
                    SELECT txid, type, amount, from_address, to_address, timestamp, 
                           status, confirmations, block_height
                    FROM wallet_transactions 
                    WHERE wallet_address = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (address, limit))
                
                transactions = []
                for row in cursor.fetchall():
                    transactions.append({
                        'txid': row[0],
                        'type': row[1],
                        'amount': row[2],
                        'from_address': row[3],
                        'to_address': row[4],
                        'timestamp': row[5],
                        'status': row[6],
                        'confirmations': row[7],
                        'block_height': row[8]
                    })
                
                return transactions
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Transaction operations
        @self.app.post("/api/transaction/send")
        async def send_transaction(request: dict):
            """Send WEPO transaction with comprehensive validation"""
            try:
                from_address = request.get('from_address')
                to_address = request.get('to_address')
                amount = request.get('amount')
                password_hash = request.get('password_hash')
                
                # Input validation
                if not all([from_address, to_address, amount]):
                    raise HTTPException(status_code=400, detail="Missing required fields: from_address, to_address, amount")
                
                # Validate addresses
                if not from_address.startswith("wepo1") or len(from_address) < 30:
                    raise HTTPException(status_code=400, detail="Invalid sender address format")
                
                if not to_address.startswith("wepo1") or len(to_address) < 30:
                    raise HTTPException(status_code=400, detail="Invalid recipient address format")
                
                # Validate amount
                if not isinstance(amount, (int, float)) or amount <= 0:
                    raise HTTPException(status_code=400, detail="Amount must be a positive number")
                
                # Verify wallet exists and has sufficient balance
                try:
                    wallet_info = await self.get_wallet(from_address)
                    required_amount = amount + 0.0001  # Include fee
                    
                    if wallet_info['balance'] < required_amount:
                        raise HTTPException(
                            status_code=400, 
                            detail=f"Insufficient balance. Available: {wallet_info['balance']:.8f} WEPO, Required: {required_amount:.8f} WEPO"
                        )
                except HTTPException as he:
                    if he.status_code == 404:
                        raise HTTPException(status_code=400, detail="Sender wallet not found")
                    raise
                
                # Create transaction data
                tx_data = {
                    'from_address': from_address,
                    'to_address': to_address,
                    'amount': amount,
                    'fee': 0.0001,
                    'timestamp': time.time()
                }
                
                # Forward to blockchain node
                try:
                    response = requests.post(f"{self.node_url}/api/transaction/send", 
                                           json=tx_data, timeout=30)
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # Add to wallet transaction history
                        await self.add_wallet_transaction(
                            from_address, result['transaction_id'], 'send',
                            amount, from_address, to_address, 'pending'
                        )
                        
                        # Notify WebSocket clients
                        await self.broadcast_wallet_update(from_address, "transaction_sent")
                        
                        return result
                    
                    elif response.status_code == 400:
                        # Parse blockchain error and return appropriate message
                        error_data = response.json()
                        raise HTTPException(status_code=400, detail=error_data.get('detail', 'Transaction validation failed'))
                    
                    else:
                        raise HTTPException(status_code=500, detail="Blockchain node error")
                        
                except requests.Timeout:
                    raise HTTPException(status_code=503, detail="Blockchain node timeout")
                except requests.RequestException as e:
                    raise HTTPException(status_code=503, detail=f"Blockchain node unavailable: {str(e)}")
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
        
        # Staking operations
        @self.app.post("/api/stake")
        async def create_stake(request: dict):
            """Create staking position"""
            try:
                wallet_address = request.get('wallet_address')
                amount = request.get('amount')
                lock_period_months = request.get('lock_period_months')
                
                if not all([wallet_address, amount, lock_period_months]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Forward to blockchain node
                response = requests.post(f"{self.node_url}/api/stake", 
                                       json=request, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    
                    # Update wallet staking status
                    self.wallet_conn.execute('''
                        UPDATE wallets 
                        SET is_staking = TRUE, stake_amount = ?, balance = balance - ?
                        WHERE address = ?
                    ''', (amount, amount, wallet_address))
                    self.wallet_conn.commit()
                    
                    # Add transaction record
                    await self.add_wallet_transaction(
                        wallet_address, f"stake_{result['stake_id']}", 'stake',
                        amount, wallet_address, wallet_address, 'confirmed'
                    )
                    
                    # Notify WebSocket clients
                    await self.broadcast_wallet_update(wallet_address, "stake_created")
                    
                    return result
                else:
                    raise HTTPException(status_code=400, detail="Staking failed")
                    
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Masternode operations
        @self.app.post("/api/masternode")
        async def setup_masternode(request: dict):
            """Setup masternode"""
            try:
                wallet_address = request.get('wallet_address')
                server_ip = request.get('server_ip')
                server_port = request.get('server_port', 22567)
                
                if not all([wallet_address, server_ip]):
                    raise HTTPException(status_code=400, detail="Missing required fields")
                
                # Forward to blockchain node
                response = requests.post(f"{self.node_url}/api/masternode", 
                                       json=request, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    
                    # Update wallet masternode status
                    self.wallet_conn.execute('''
                        UPDATE wallets 
                        SET is_masternode = TRUE, masternode_collateral = 10000, balance = balance - 10000
                        WHERE address = ?
                    ''', (wallet_address,))
                    self.wallet_conn.commit()
                    
                    # Add transaction record
                    await self.add_wallet_transaction(
                        wallet_address, f"masternode_{result['masternode_id']}", 'masternode',
                        10000, wallet_address, wallet_address, 'confirmed'
                    )
                    
                    # Notify WebSocket clients
                    await self.broadcast_wallet_update(wallet_address, "masternode_created")
                    
                    return result
                else:
                    raise HTTPException(status_code=400, detail="Masternode setup failed")
                    
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # DEX operations
        @self.app.post("/api/dex/swap")
        async def create_btc_swap(request: dict):
            """Create BTC-WEPO atomic swap"""
            try:
                # Forward to blockchain node
                response = requests.post(f"{self.node_url}/api/dex/swap", 
                                       json=request, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    
                    # Add swap transaction record
                    wepo_address = request.get('wepo_address')
                    amount = request.get('wepo_amount', 0)
                    swap_type = request.get('swap_type')
                    
                    await self.add_wallet_transaction(
                        wepo_address, f"swap_{result['swap_id']}", f'dex_{swap_type}',
                        amount, wepo_address, "btc_address", 'pending'
                    )
                    
                    # Notify WebSocket clients
                    await self.broadcast_wallet_update(wepo_address, "swap_created")
                    
                    return result
                else:
                    raise HTTPException(status_code=400, detail="Swap creation failed")
                    
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dex/rate")
        async def get_exchange_rate():
            """Get BTC-WEPO exchange rate"""
            try:
                response = requests.get(f"{self.node_url}/api/dex/rate", timeout=10)
                if response.status_code == 200:
                    return response.json()
                else:
                    # Return default rate if node unavailable
                    return {
                        "btc_to_wepo": 1.0,
                        "wepo_to_btc": 1.0,
                        "fee_percentage": 0.1,
                        "last_updated": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
            except Exception:
                # Fallback rate
                return {
                    "btc_to_wepo": 1.0,
                    "wepo_to_btc": 1.0,
                    "fee_percentage": 0.1,
                    "last_updated": time.strftime('%Y-%m-%d %H:%M:%S')
                }
        
        # WebSocket endpoint for real-time updates
        @self.app.websocket("/api/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                while True:
                    # Keep connection alive
                    await websocket.receive_text()
            except WebSocketDisconnect:
                self.websocket_connections.remove(websocket)
    
    async def add_wallet_transaction(self, wallet_address: str, txid: str, tx_type: str,
                                   amount: float, from_address: str, to_address: str, 
                                   status: str, block_height: Optional[int] = None):
        """Add transaction to wallet history"""
        try:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.wallet_conn.execute('''
                INSERT INTO wallet_transactions 
                (wallet_address, txid, type, amount, from_address, to_address, timestamp, status, block_height)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (wallet_address, txid, tx_type, amount, from_address, to_address, now, status, block_height))
            self.wallet_conn.commit()
            
        except Exception as e:
            print(f"Error adding wallet transaction: {e}")
    
    async def update_wallet_balance(self, address: str):
        """Update wallet balance from blockchain"""
        try:
            # Get balance from blockchain node
            response = requests.get(f"{self.node_url}/api/wallet/{address}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                balance = data.get('balance', 0)
                
                # Update in database
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                self.wallet_conn.execute(
                    "UPDATE wallets SET balance = ?, last_activity = ? WHERE address = ?",
                    (balance, now, address)
                )
                self.wallet_conn.commit()
                
        except Exception as e:
            print(f"Error updating wallet balance for {address}: {e}")
    
    async def broadcast_wallet_update(self, address: str, event_type: str):
        """Broadcast wallet update to WebSocket clients"""
        message = {
            'type': 'wallet_update',
            'address': address,
            'event': event_type,
            'timestamp': time.time()
        }
        
        # Remove disconnected clients
        connected_clients = []
        for websocket in self.websocket_connections:
            try:
                await websocket.send_text(json.dumps(message))
                connected_clients.append(websocket)
            except:
                pass  # Client disconnected
        
        self.websocket_connections = connected_clients
    
    async def sync_with_blockchain(self):
        """Sync wallet data with blockchain"""
        try:
            # Get latest block height from node
            response = requests.get(f"{self.node_url}/api/network/status", timeout=10)
            if response.status_code == 200:
                data = response.json()
                current_height = data.get('block_height', 0)
                
                if current_height > self.last_sync_height:
                    print(f"Syncing from block {self.last_sync_height} to {current_height}")
                    
                    # Update all wallet balances
                    cursor = self.wallet_conn.execute("SELECT address FROM wallets")
                    for (address,) in cursor.fetchall():
                        await self.update_wallet_balance(address)
                    
                    self.last_sync_height = current_height
                    
        except Exception as e:
            print(f"Sync error: {e}")
    
    def start_sync_worker(self):
        """Start background sync worker"""
        async def sync_worker():
            while self.sync_running:
                await self.sync_with_blockchain()
                await asyncio.sleep(SYNC_INTERVAL)
        
        self.sync_running = True
        asyncio.create_task(sync_worker())
    
    def run(self):
        """Run the wallet daemon"""
        print(f"Starting WEPO Wallet Daemon on port {self.walletd_port}")
        
        # Start sync worker
        self.start_sync_worker()
        
        # Run FastAPI server
        uvicorn.run(
            self.app,
            host="0.0.0.0",
            port=self.walletd_port,
            log_level="info"
        )
    
    def stop(self):
        """Stop the wallet daemon"""
        self.sync_running = False
        if self.wallet_conn:
            self.wallet_conn.close()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='WEPO Wallet Daemon')
    parser.add_argument('--node-host', default='localhost',
                       help='Blockchain node host')
    parser.add_argument('--node-port', type=int, default=DEFAULT_NODE_PORT,
                       help='Blockchain node port')
    parser.add_argument('--port', type=int, default=DEFAULT_WALLETD_PORT,
                       help='Wallet daemon port')
    parser.add_argument('--wallet-db', default=WALLET_DB_PATH,
                       help='Wallet database path')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("🚀 WEPO Wallet Daemon")
    print("=" * 50)
    print(f"Version: 1.0.0")
    print(f"Node: {args.node_host}:{args.node_port}")
    print(f"Daemon Port: {args.port}")
    print(f"Wallet DB: {args.wallet_db}")
    print("=" * 50)
    
    # Create wallet daemon
    daemon = WepoWalletDaemon(
        node_host=args.node_host,
        node_port=args.node_port,
        walletd_port=args.port
    )
    
    try:
        daemon.run()
    except KeyboardInterrupt:
        print("\nShutting down wallet daemon...")
        daemon.stop()

if __name__ == "__main__":
    main()