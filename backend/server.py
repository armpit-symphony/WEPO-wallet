from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
import hashlib
import time
import json
from datetime import datetime, timedelta
from enum import Enum
import secrets

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI(title="WEPO Blockchain API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBasic()

# WEPO Blockchain Models
class TransactionType(str, Enum):
    SEND = "send"
    RECEIVE = "receive"
    STAKE = "stake"
    MASTERNODE = "masternode"
    DEX_SWAP = "dex_swap"

class TransactionStatus(str, Enum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    FAILED = "failed"

class ConsensusType(str, Enum):
    POW = "pow"
    POS = "pos"
    MASTERNODE = "masternode"

# Blockchain Models
class WepoAddress(BaseModel):
    address: str
    public_key: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class WepoTransaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tx_hash: str = Field(default_factory=lambda: secrets.token_hex(32))
    from_address: str
    to_address: str
    amount: float
    fee: float = 0.0001  # Standard WEPO fee
    transaction_type: TransactionType
    status: TransactionStatus = TransactionStatus.PENDING
    block_height: Optional[int] = None
    confirmations: int = 0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    privacy_proof: Optional[str] = None  # zk-STARK proof
    ring_signature: Optional[str] = None  # Privacy signature

class WepoBlock(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    height: int
    hash: str
    previous_hash: str
    merkle_root: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    nonce: int = 0
    difficulty: float = 1.0
    consensus_type: ConsensusType
    miner_address: Optional[str] = None
    validator_address: Optional[str] = None
    reward: float = 0.0
    transactions: List[str] = []  # Transaction IDs
    size: int = 0

class WepoWallet(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    address: str
    balance: float = 0.0
    encrypted_private_key: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    is_staking: bool = False
    stake_amount: float = 0.0
    is_masternode: bool = False
    masternode_collateral: float = 0.0

class StakePosition(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    wallet_address: str
    amount: float
    lock_period_months: int
    apr: float
    start_date: datetime = Field(default_factory=datetime.utcnow)
    end_date: datetime
    rewards_earned: float = 0.0
    is_active: bool = True

class Masternode(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    wallet_address: str
    server_ip: str
    server_port: int = 22567
    collateral_amount: float = 10000.0
    status: str = "active"  # active, inactive, banned
    uptime_percentage: float = 0.0
    last_ping: datetime = Field(default_factory=datetime.utcnow)
    total_rewards: float = 0.0
    mixing_count: int = 0

class BtcSwap(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    wepo_address: str
    btc_address: str
    btc_amount: float
    wepo_amount: float
    exchange_rate: float
    swap_type: str  # "buy" or "sell"
    status: str = "pending"  # pending, completed, failed
    atomic_swap_hash: str = Field(default_factory=lambda: secrets.token_hex(32))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

# Request/Response Models
class CreateWalletRequest(BaseModel):
    username: str
    address: str
    encrypted_private_key: str

class SendTransactionRequest(BaseModel):
    from_address: str
    to_address: str
    amount: float
    password_hash: str

class StakeRequest(BaseModel):
    wallet_address: str
    amount: float
    lock_period_months: int

class MasternodeRequest(BaseModel):
    wallet_address: str
    server_ip: str
    server_port: int = 22567

class BtcSwapRequest(BaseModel):
    wepo_address: str
    btc_address: str
    btc_amount: float
    swap_type: str

# Blockchain Simulation Functions
def generate_wepo_address() -> str:
    """Generate a WEPO address"""
    random_data = secrets.token_bytes(32)
    address_hash = hashlib.sha256(random_data).hexdigest()
    return f"wepo1{address_hash[:32]}"

def calculate_transaction_hash(transaction: WepoTransaction) -> str:
    """Calculate transaction hash"""
    data = f"{transaction.from_address}{transaction.to_address}{transaction.amount}{transaction.timestamp}"
    return hashlib.sha256(data.encode()).hexdigest()

def generate_zk_proof() -> str:
    """Simulate zk-STARK proof generation"""
    return f"zk_proof_{secrets.token_hex(64)}"

def generate_ring_signature() -> str:
    """Simulate ring signature generation"""
    return f"ring_sig_{secrets.token_hex(64)}"

async def get_current_block_height() -> int:
    """Get current blockchain height"""
    latest_block = await db.blocks.find_one(sort=[("height", -1)])
    return latest_block["height"] if latest_block else 0

async def create_block(transactions: List[WepoTransaction], consensus_type: ConsensusType) -> WepoBlock:
    """Create a new block"""
    height = await get_current_block_height() + 1
    previous_block = await db.blocks.find_one(sort=[("height", -1)])
    previous_hash = previous_block["hash"] if previous_block else "0" * 64
    
    # Calculate block reward based on WEPO economics
    if consensus_type == ConsensusType.POW:
        # Year 1: 121.6 WEPO/block, then transitions to 12.4 WEPO/block
        if height <= 52560:  # First year (10-min blocks)
            reward = 121.6
        else:
            # Calculate based on halving schedule
            years_since_year_2 = (height - 52560) // 262800  # 2-minute blocks per year
            reward = 12.4 / (2 ** (years_since_year_2 // 4))
    else:
        reward = 0.1  # PoS/Masternode rewards are lower

    block_data = f"{height}{previous_hash}{time.time()}"
    block_hash = hashlib.sha256(block_data.encode()).hexdigest()
    
    block = WepoBlock(
        height=height,
        hash=block_hash,
        previous_hash=previous_hash,
        merkle_root=hashlib.sha256("".join([tx.tx_hash for tx in transactions]).encode()).hexdigest(),
        consensus_type=consensus_type,
        reward=reward,
        transactions=[tx.id for tx in transactions]
    )
    
    await db.blocks.insert_one(block.dict())
    return block

# API Endpoints

@api_router.get("/")
async def root():
    return {"message": "WEPO Blockchain API", "version": "1.0.0", "network": "mainnet"}

@api_router.get("/network/status")
async def get_network_status():
    """Get WEPO network status"""
    block_height = await get_current_block_height()
    total_masternodes = await db.masternodes.count_documents({"status": "active"})
    total_staked = await db.stakes.aggregate([
        {"$match": {"is_active": True}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    
    total_staked_amount = total_staked[0]["total"] if total_staked else 0
    
    return {
        "block_height": block_height,
        "network_hashrate": "123.45 TH/s",  # Simulated
        "active_masternodes": total_masternodes,
        "total_staked": total_staked_amount,
        "total_supply": 63900006,
        "circulating_supply": min(block_height * 121.6 if block_height <= 52560 else 6390000 + (block_height - 52560) * 12.4, 31950000)
    }

@api_router.post("/wallet/create")
async def create_wallet(request: CreateWalletRequest):
    """Create a new WEPO wallet"""
    existing = await db.wallets.find_one({"username": request.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    existing_address = await db.wallets.find_one({"address": request.address})
    if existing_address:
        raise HTTPException(status_code=400, detail="Address already exists")
    
    wallet = WepoWallet(
        username=request.username,
        address=request.address,
        encrypted_private_key=request.encrypted_private_key
    )
    
    await db.wallets.insert_one(wallet.dict())
    return {"success": True, "address": wallet.address}

@api_router.get("/wallet/{address}")
async def get_wallet(address: str):
    """Get wallet information"""
    wallet = await db.wallets.find_one({"address": address})
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    # Calculate balance from transactions
    received = await db.transactions.aggregate([
        {"$match": {"to_address": address, "status": "confirmed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    
    sent = await db.transactions.aggregate([
        {"$match": {"from_address": address, "status": "confirmed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    
    received_amount = received[0]["total"] if received else 0
    sent_amount = sent[0]["total"] if sent else 0
    balance = received_amount - sent_amount
    
    # Update wallet balance
    await db.wallets.update_one(
        {"address": address},
        {"$set": {"balance": balance, "last_activity": datetime.utcnow()}}
    )
    
    return {
        "address": wallet["address"],
        "balance": balance,
        "username": wallet["username"],
        "created_at": wallet["created_at"],
        "is_staking": wallet.get("is_staking", False),
        "is_masternode": wallet.get("is_masternode", False)
    }

@api_router.get("/wallet/{address}/transactions")
async def get_wallet_transactions(address: str, limit: int = 50):
    """Get wallet transaction history"""
    transactions = await db.transactions.find({
        "$or": [
            {"from_address": address},
            {"to_address": address}
        ]
    }).sort("timestamp", -1).limit(limit).to_list(limit)
    
    return transactions

@api_router.post("/transaction/send")
async def send_transaction(request: SendTransactionRequest):
    """Send WEPO transaction"""
    # Verify wallet exists and has sufficient balance
    wallet = await db.wallets.find_one({"address": request.from_address})
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet["balance"] < request.amount + 0.0001:  # Include fee
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Create transaction with privacy features
    transaction = WepoTransaction(
        from_address=request.from_address,
        to_address=request.to_address,
        amount=request.amount,
        transaction_type=TransactionType.SEND,
        privacy_proof=generate_zk_proof(),
        ring_signature=generate_ring_signature()
    )
    
    transaction.tx_hash = calculate_transaction_hash(transaction)
    
    await db.transactions.insert_one(transaction.dict())
    
    # Simulate transaction confirmation after delay
    # In real implementation, this would be handled by miners/validators
    
    return {
        "transaction_id": transaction.id,
        "tx_hash": transaction.tx_hash,
        "status": transaction.status,
        "privacy_protected": True
    }

@api_router.post("/stake")
async def create_stake(request: StakeRequest):
    """Create a staking position"""
    # Check if PoS is enabled (18 months after launch)
    # For demo, we'll allow it
    
    wallet = await db.wallets.find_one({"address": request.wallet_address})
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet["balance"] < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance for staking")
    
    if request.amount < 1000:
        raise HTTPException(status_code=400, detail="Minimum stake is 1000 WEPO")
    
    # Calculate APR based on lock period
    base_apr = 1.0
    lock_bonus = 0.5 * (request.lock_period_months / 12)
    apr = base_apr + lock_bonus
    
    stake = StakePosition(
        wallet_address=request.wallet_address,
        amount=request.amount,
        lock_period_months=request.lock_period_months,
        apr=apr,
        end_date=datetime.utcnow() + timedelta(days=30 * request.lock_period_months)
    )
    
    await db.stakes.insert_one(stake.dict())
    
    # Update wallet
    await db.wallets.update_one(
        {"address": request.wallet_address},
        {
            "$set": {"is_staking": True, "stake_amount": request.amount},
            "$inc": {"balance": -request.amount}
        }
    )
    
    return {"success": True, "stake_id": stake.id, "apr": apr}

@api_router.post("/masternode")
async def setup_masternode(request: MasternodeRequest):
    """Setup a masternode"""
    wallet = await db.wallets.find_one({"address": request.wallet_address})
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    
    if wallet["balance"] < 10000:
        raise HTTPException(status_code=400, detail="Insufficient balance. 10,000 WEPO required for masternode")
    
    # Check if IP is already used
    existing = await db.masternodes.find_one({"server_ip": request.server_ip})
    if existing:
        raise HTTPException(status_code=400, detail="Server IP already in use")
    
    masternode = Masternode(
        wallet_address=request.wallet_address,
        server_ip=request.server_ip,
        server_port=request.server_port
    )
    
    await db.masternodes.insert_one(masternode.dict())
    
    # Update wallet
    await db.wallets.update_one(
        {"address": request.wallet_address},
        {
            "$set": {"is_masternode": True, "masternode_collateral": 10000},
            "$inc": {"balance": -10000}
        }
    )
    
    return {"success": True, "masternode_id": masternode.id}

@api_router.post("/dex/swap")
async def create_btc_swap(request: BtcSwapRequest):
    """Create BTC-WEPO atomic swap"""
    wallet = await db.wallets.find_one({"address": request.wepo_address})
    if not wallet:
        raise HTTPException(status_code=404, detail="WEPO wallet not found")
    
    # Calculate exchange rate (1:1 for demo)
    exchange_rate = 1.0
    wepo_amount = request.btc_amount * exchange_rate
    
    if request.swap_type == "sell" and wallet["balance"] < wepo_amount:
        raise HTTPException(status_code=400, detail="Insufficient WEPO balance")
    
    swap = BtcSwap(
        wepo_address=request.wepo_address,
        btc_address=request.btc_address,
        btc_amount=request.btc_amount,
        wepo_amount=wepo_amount,
        exchange_rate=exchange_rate,
        swap_type=request.swap_type
    )
    
    await db.btc_swaps.insert_one(swap.dict())
    
    return {
        "swap_id": swap.id,
        "atomic_swap_hash": swap.atomic_swap_hash,
        "wepo_amount": wepo_amount,
        "exchange_rate": exchange_rate,
        "status": swap.status
    }

@api_router.get("/dex/rate")
async def get_exchange_rate():
    """Get current BTC-WEPO exchange rate"""
    return {
        "btc_to_wepo": 1.0,
        "wepo_to_btc": 1.0,
        "fee_percentage": 0.1,
        "last_updated": datetime.utcnow()
    }

@api_router.get("/blocks/latest")
async def get_latest_blocks(limit: int = 10):
    """Get latest blocks"""
    blocks = await db.blocks.find().sort("height", -1).limit(limit).to_list(limit)
    return blocks

@api_router.get("/mining/info")
async def get_mining_info():
    """Get mining information"""
    height = await get_current_block_height()
    
    # Calculate current reward based on height
    if height <= 52560:  # First year
        current_reward = 121.6
        next_halving = 52560
    else:
        years_since_year_2 = (height - 52560) // 262800
        current_reward = 12.4 / (2 ** (years_since_year_2 // 4))
        next_halving = 52560 + ((years_since_year_2 // 4) + 1) * 1051200
    
    return {
        "current_block_height": height,
        "current_reward": current_reward,
        "next_halving_block": next_halving,
        "blocks_until_halving": max(0, next_halving - height),
        "difficulty": 1.0,
        "algorithm": "Argon2",
        "block_time": "2 minutes" if height > 52560 else "10 minutes"
    }

# Community-Driven AMM System (No Admin)
import math
from typing import Dict, Optional

class LiquidityPool:
    """Community-driven liquidity pool with no admin control"""
    
    def __init__(self):
        self.btc_reserve = 0.0
        self.wepo_reserve = 0.0
        self.total_shares = 0.0
        self.lp_positions = {}  # user_address: shares
        self.fee_rate = 0.003  # 0.3% trading fee
    
    def get_price(self) -> Optional[float]:
        """Get current WEPO per BTC price"""
        if self.btc_reserve == 0:
            return None
        return self.wepo_reserve / self.btc_reserve
    
    def get_output_amount(self, input_amount: float, input_is_btc: bool) -> float:
        """Calculate output amount using constant product formula"""
        if input_is_btc:
            # BTC → WEPO
            input_reserve = self.btc_reserve
            output_reserve = self.wepo_reserve
        else:
            # WEPO → BTC  
            input_reserve = self.wepo_reserve
            output_reserve = self.btc_reserve
        
        # Apply fee to input
        input_after_fee = input_amount * (1 - self.fee_rate)
        
        # Constant product formula: x * y = k
        # (x + input_after_fee) * (y - output) = x * y
        # output = (y * input_after_fee) / (x + input_after_fee)
        output_amount = (output_reserve * input_after_fee) / (input_reserve + input_after_fee)
        
        return output_amount
    
    def bootstrap_pool(self, user_address: str, btc_amount: float, wepo_amount: float):
        """First user creates the market - no admin required"""
        if self.total_shares > 0:
            raise Exception("Pool already exists")
        
        if btc_amount <= 0 or wepo_amount <= 0:
            raise Exception("Invalid amounts")
        
        # Set initial reserves (user determines initial price)
        self.btc_reserve = btc_amount
        self.wepo_reserve = wepo_amount
        
        # Initial shares = geometric mean of reserves
        self.total_shares = math.sqrt(btc_amount * wepo_amount)
        self.lp_positions[user_address] = self.total_shares
        
        return {
            "initial_price": wepo_amount / btc_amount,
            "shares_minted": self.total_shares,
            "pool_created": True,
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve
        }
    
    def add_liquidity(self, user_address: str, btc_amount: float, wepo_amount: float):
        """Add liquidity to existing pool"""
        if self.total_shares == 0:
            return self.bootstrap_pool(user_address, btc_amount, wepo_amount)
        
        # Calculate required ratio
        current_ratio = self.wepo_reserve / self.btc_reserve
        provided_ratio = wepo_amount / btc_amount
        
        # Allow small tolerance for ratio mismatch
        if abs(current_ratio - provided_ratio) / current_ratio > 0.02:  # 2% tolerance
            raise Exception(f"Ratio mismatch. Current: {current_ratio:.6f}, Provided: {provided_ratio:.6f}")
        
        # Calculate shares to mint proportionally
        btc_share = btc_amount / self.btc_reserve
        shares_to_mint = self.total_shares * btc_share
        
        # Update reserves
        self.btc_reserve += btc_amount
        self.wepo_reserve += wepo_amount
        self.total_shares += shares_to_mint
        
        # Update user position
        if user_address in self.lp_positions:
            self.lp_positions[user_address] += shares_to_mint
        else:
            self.lp_positions[user_address] = shares_to_mint
        
        return {
            "shares_minted": shares_to_mint,
            "total_shares": self.total_shares,
            "new_price": self.get_price(),
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve
        }
    
    def execute_swap(self, input_amount: float, input_is_btc: bool) -> Dict:
        """Execute swap and update reserves"""
        if self.total_shares == 0:
            raise Exception("No liquidity in pool")
        
        output_amount = self.get_output_amount(input_amount, input_is_btc)
        fee_amount = input_amount * self.fee_rate
        
        # Update reserves
        if input_is_btc:
            self.btc_reserve += input_amount
            self.wepo_reserve -= output_amount
        else:
            self.wepo_reserve += input_amount
            self.btc_reserve -= output_amount
        
        return {
            "input_amount": input_amount,
            "output_amount": output_amount,
            "fee_amount": fee_amount,
            "new_price": self.get_price(),
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve
        }

# Global pool instance (in production, this would be in database)
btc_wepo_pool = LiquidityPool()

# Community-Driven AMM Endpoints
@api_router.get("/swap/rate")
async def get_market_rate():
    """Get current market-determined BTC/WEPO rate"""
    try:
        price = btc_wepo_pool.get_price()
        
        if price is None:
            return {
                "pool_exists": False,
                "message": "No liquidity pool exists yet. Any user can create the market.",
                "btc_reserve": 0,
                "wepo_reserve": 0,
                "can_bootstrap": True
            }
        
        return {
            "pool_exists": True,
            "btc_to_wepo": price,
            "wepo_to_btc": 1 / price,
            "btc_reserve": btc_wepo_pool.btc_reserve,
            "wepo_reserve": btc_wepo_pool.wepo_reserve,
            "total_liquidity_shares": btc_wepo_pool.total_shares,
            "fee_rate": btc_wepo_pool.fee_rate,
            "last_updated": int(time.time())
        }
    except Exception as e:
        logger.error(f"Error getting market rate: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/swap/execute")
async def execute_market_swap(request: dict):
    """Execute swap using community-driven AMM"""
    try:
        wallet_address = request.get("wallet_address")
        from_currency = request.get("from_currency")  # BTC or WEPO
        input_amount = float(request.get("input_amount", 0))
        
        if not wallet_address or not from_currency or input_amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid request parameters")
        
        if from_currency not in ["BTC", "WEPO"]:
            raise HTTPException(status_code=400, detail="Invalid currency")
        
        # Check if pool exists
        if btc_wepo_pool.total_shares == 0:
            raise HTTPException(status_code=400, detail="No liquidity pool exists. Create market first.")
        
        # Execute swap
        input_is_btc = (from_currency == "BTC")
        swap_result = btc_wepo_pool.execute_swap(input_amount, input_is_btc)
        
        # Calculate fee redistribution (goes to existing 3-way system)
        fee_amount = swap_result["fee_amount"]
        
        # Add to redistribution pool (integrate with existing system)
        await add_fee_to_redistribution_pool(fee_amount, "swap_fee")
        
        # Record swap transaction
        swap_record = {
            "swap_id": f"swap_{int(time.time())}_{wallet_address[:8]}",
            "wallet_address": wallet_address,
            "from_currency": from_currency,
            "to_currency": "WEPO" if from_currency == "BTC" else "BTC",
            "input_amount": input_amount,
            "output_amount": swap_result["output_amount"],
            "fee_amount": fee_amount,
            "price": swap_result["new_price"],
            "status": "completed",
            "timestamp": int(time.time()),
            "created_at": datetime.now()
        }
        
        await db.market_swaps.insert_one(swap_record)
        
        return {
            "swap_id": swap_record["swap_id"],
            "status": "completed",
            "from_currency": from_currency,
            "to_currency": swap_record["to_currency"],
            "input_amount": input_amount,
            "output_amount": swap_result["output_amount"],
            "fee_amount": fee_amount,
            "market_price": swap_result["new_price"],
            "btc_reserve": swap_result["btc_reserve"],
            "wepo_reserve": swap_result["wepo_reserve"],
            "timestamp": swap_record["timestamp"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing market swap: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/liquidity/add")
async def add_liquidity_to_pool(request: dict):
    """Add liquidity to BTC-WEPO pool (or create if first)"""
    try:
        wallet_address = request.get("wallet_address")
        btc_amount = float(request.get("btc_amount", 0))
        wepo_amount = float(request.get("wepo_amount", 0))
        
        if not wallet_address or btc_amount <= 0 or wepo_amount <= 0:
            raise HTTPException(status_code=400, detail="Invalid amounts")
        
        # TODO: Verify user has sufficient balance
        # user_btc_balance = await get_user_btc_balance(wallet_address)
        # user_wepo_balance = await get_user_wepo_balance(wallet_address)
        
        # Add liquidity
        result = btc_wepo_pool.add_liquidity(wallet_address, btc_amount, wepo_amount)
        
        # Record liquidity provision
        lp_record = {
            "lp_id": f"lp_{int(time.time())}_{wallet_address[:8]}",
            "wallet_address": wallet_address,
            "btc_amount": btc_amount,
            "wepo_amount": wepo_amount,
            "shares_minted": result["shares_minted"],
            "pool_created": result.get("pool_created", False),
            "timestamp": int(time.time()),
            "created_at": datetime.now()
        }
        
        await db.liquidity_positions.insert_one(lp_record)
        
        return {
            "lp_id": lp_record["lp_id"],
            "status": "success",
            "btc_amount": btc_amount,
            "wepo_amount": wepo_amount,
            "shares_minted": result["shares_minted"],
            "total_shares": result["total_shares"],
            "market_price": result.get("new_price") or result.get("initial_price"),
            "pool_created": result.get("pool_created", False),
            "btc_reserve": result["btc_reserve"],
            "wepo_reserve": result["wepo_reserve"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding liquidity: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/liquidity/stats")
async def get_liquidity_stats():
    """Get current pool statistics"""
    try:
        if btc_wepo_pool.total_shares == 0:
            return {
                "pool_exists": False,
                "message": "No liquidity pool exists. Any user can create the market."
            }
        
        return {
            "pool_exists": True,
            "btc_reserve": btc_wepo_pool.btc_reserve,
            "wepo_reserve": btc_wepo_pool.wepo_reserve,
            "total_shares": btc_wepo_pool.total_shares,
            "current_price": btc_wepo_pool.get_price(),
            "fee_rate": btc_wepo_pool.fee_rate,
            "total_lp_count": len(btc_wepo_pool.lp_positions)
        }
    except Exception as e:
        logger.error(f"Error getting liquidity stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def add_fee_to_redistribution_pool(fee_amount: float, fee_type: str):
    """Integrate swap fees with existing 3-way redistribution system"""
    try:
        # This integrates with the existing fee redistribution system
        # All swap fees go to the same pool as RWA fees
        redistribution_record = {
            "fee_amount": fee_amount,
            "fee_type": fee_type,
            "timestamp": int(time.time()),
            "redistributed": False,
            "created_at": datetime.now()
        }
        
        await db.fee_redistribution_pool.insert_one(redistribution_record)
        
        # Fees will be distributed by existing system:
        # 60% to masternodes, 25% to miners, 15% to stakers
        
    except Exception as e:
        logger.error(f"Error adding fee to redistribution pool: {str(e)}")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    logger.info("WEPO Blockchain API started")
    
    # Create indexes for better performance
    await db.wallets.create_index("address", unique=True)
    await db.wallets.create_index("username", unique=True)
    await db.transactions.create_index([("from_address", 1), ("to_address", 1)])
    await db.transactions.create_index("timestamp")
    await db.blocks.create_index("height", unique=True)
    await db.stakes.create_index("wallet_address")
    await db.masternodes.create_index("wallet_address")
    await db.btc_swaps.create_index("wepo_address")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
    logger.info("WEPO Blockchain API stopped")