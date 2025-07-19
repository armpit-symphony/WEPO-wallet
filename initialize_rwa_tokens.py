#!/usr/bin/env python3
"""
Initialize sample RWA tokens for testing
"""
import asyncio
import motor.motor_asyncio
import os
import time
from datetime import datetime

async def initialize_rwa_tokens():
    """Initialize sample RWA tokens in database"""
    
    # Connect to MongoDB
    MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017/')
    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URL)
    db = client.wepo_database
    
    # Sample RWA tokens for testing
    sample_tokens = [
        {
            "_id": "rwa_btc_property_001",
            "symbol": "BTCRE1",
            "asset_name": "Bitcoin-backed Real Estate Token #1",
            "asset_type": "bitcoin",  # Bitcoin-backed for privacy mixing testing
            "total_supply": 100,
            "available_supply": 100,
            "creator": "wepo1creator123456789",
            "created_date": datetime.now().isoformat(),
            "verified": True,
            "trading_enabled": True,
            "decimals": 8,
            "status": "active",
            "description": "Real estate token backed by Bitcoin reserves"
        },
        {
            "_id": "rwa_gold_token_001", 
            "symbol": "GOLDTKN",
            "asset_name": "Digital Gold Token",
            "asset_type": "commodity",
            "total_supply": 50,
            "available_supply": 50,
            "creator": "wepo1creator123456789",
            "created_date": datetime.now().isoformat(),
            "verified": True,
            "trading_enabled": True,
            "decimals": 8,
            "status": "active",
            "description": "Gold-backed commodity token"
        },
        {
            "_id": "rwa_property_mansion",
            "symbol": "MANSION1",
            "asset_name": "Luxury Mansion Token",
            "asset_type": "property",
            "total_supply": 10,
            "available_supply": 10,
            "creator": "wepo1creator123456789",
            "created_date": datetime.now().isoformat(),
            "verified": True,
            "trading_enabled": True,
            "decimals": 8,
            "status": "active",
            "description": "Fractional ownership of luxury mansion"
        },
        {
            "_id": "rwa_btc_art_collection",
            "symbol": "BTCART",
            "asset_name": "Bitcoin Art Collection Token",
            "asset_type": "bitcoin",  # Bitcoin-backed for privacy mixing testing
            "total_supply": 25,
            "available_supply": 25,
            "creator": "wepo1creator123456789", 
            "created_date": datetime.now().isoformat(),
            "verified": True,
            "trading_enabled": True,
            "decimals": 8,
            "status": "active",
            "description": "Fine art collection backed by Bitcoin"
        },
        {
            "_id": "rwa_car_collection",
            "symbol": "CARTKN",
            "asset_name": "Classic Car Collection",
            "asset_type": "vehicle",
            "total_supply": 15,
            "available_supply": 15,
            "creator": "wepo1creator123456789",
            "created_date": datetime.now().isoformat(),
            "verified": True,
            "trading_enabled": True,
            "decimals": 8,
            "status": "active",
            "description": "Fractional ownership of classic car collection"
        }
    ]
    
    try:
        # Insert sample tokens (replace existing)
        for token in sample_tokens:
            await db.rwa_tokens.replace_one(
                {"_id": token["_id"]},
                token,
                upsert=True
            )
            print(f"✅ Initialized RWA token: {token['symbol']} ({token['asset_name']})")
        
        # Create initial test balances for testing user
        test_user = "wepo1test123456789"
        for token in sample_tokens:
            # Give test user some tokens for testing
            await db.rwa_balances.update_one(
                {"token_id": token["_id"], "address": test_user},
                {"$set": {"balance": 10.0}},
                upsert=True
            )
            print(f"✅ Set test balance for {token['symbol']}: 10.0 tokens")
        
        print(f"\n🎉 Successfully initialized {len(sample_tokens)} RWA tokens!")
        print("📊 Token types:")
        print("   - 2 Bitcoin-backed tokens (for privacy mixing testing)")
        print("   - 1 Gold commodity token")  
        print("   - 1 Property token")
        print("   - 1 Vehicle token")
        print(f"💰 Test user {test_user} has 10.0 of each token")
        
        # Verify the tokens were created
        count = await db.rwa_tokens.count_documents({"status": "active"})
        print(f"🔍 Database verification: {count} active RWA tokens")
        
        return True
        
    except Exception as e:
        print(f"❌ Error initializing RWA tokens: {str(e)}")
        return False
    
    finally:
        client.close()

if __name__ == "__main__":
    print("🚀 Initializing sample RWA tokens for WEPO Unified Exchange testing...")
    success = asyncio.run(initialize_rwa_tokens())
    
    if success:
        print("\n✅ RWA token initialization complete!")
        print("🔄 Restart backend service to ensure endpoints are functional")
    else:
        print("\n❌ RWA token initialization failed!")