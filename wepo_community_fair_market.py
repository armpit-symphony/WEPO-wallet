#!/usr/bin/env python3
"""
WEPO Community-Driven Fair Market DEX - Original Design
Simple community price discovery without external oracles or complex incentives

This implements what was actually requested:
1. Community-driven fair market price DEX
2. BTC/WEPO on/off ramping without central control
3. No external oracle dependency (community determines price)
4. Original WEPO dynamic collateral schedule (already in blockchain.py)
"""

import math
from typing import Dict, Optional
from datetime import datetime

class CommunityFairMarketDEX:
    """
    Simple community-driven DEX for fair price discovery
    - No external oracles
    - No bootstrap bonuses  
    - No USD targeting
    - Community determines all prices through trading
    """
    
    def __init__(self):
        self.btc_reserve = 0.0
        self.wepo_reserve = 0.0
        self.total_shares = 0.0
        self.lp_positions = {}  # user_address: shares
        self.fee_rate = 0.003  # 0.3% trading fee
        self.creation_timestamp = None
        self.total_volume_btc = 0.0
        self.total_swaps = 0
    
    def get_price(self) -> Optional[float]:
        """Get current WEPO per BTC price determined by community trading"""
        if self.btc_reserve <= 0:
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
        output_amount = (output_reserve * input_after_fee) / (input_reserve + input_after_fee)
        
        return output_amount
    
    def bootstrap_pool(self, user_address: str, btc_amount: float, wepo_amount: float):
        """First user creates the market - community determines initial price"""
        if self.total_shares > 0:
            raise Exception("Pool already exists")
        
        if btc_amount <= 0 or wepo_amount <= 0:
            raise Exception("Invalid amounts")
        
        # Set initial reserves (user determines initial price - this is key!)
        self.btc_reserve = btc_amount
        self.wepo_reserve = wepo_amount
        self.creation_timestamp = datetime.now()
        
        # Initial shares = geometric mean of reserves
        self.total_shares = math.sqrt(btc_amount * wepo_amount)
        self.lp_positions[user_address] = self.total_shares
        
        # Community price discovery starts here
        initial_price = wepo_amount / btc_amount
        
        return {
            "initial_price": initial_price,
            "shares_minted": self.total_shares,
            "pool_created": True,
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve,
            "market_created_by": user_address,
            "creation_time": self.creation_timestamp.isoformat(),
            "message": "Community fair market created! Price determined by initial liquidity provider."
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
    
    def execute_swap(self, input_amount: float, input_is_btc: bool, user_address: str = None) -> Dict:
        """Execute swap and update reserves"""
        if self.total_shares == 0:
            raise Exception("No liquidity in pool")
        
        output_amount = self.get_output_amount(input_amount, input_is_btc)
        fee_amount = input_amount * self.fee_rate
        
        # Update reserves
        if input_is_btc:
            self.btc_reserve += input_amount
            self.wepo_reserve -= output_amount
            volume_btc = input_amount
        else:
            self.wepo_reserve += input_amount
            self.btc_reserve -= output_amount
            volume_btc = input_amount / self.get_price()  # Convert WEPO to BTC equivalent
        
        # Update stats
        self.total_volume_btc += volume_btc
        self.total_swaps += 1
        
        return {
            "input_amount": input_amount,
            "output_amount": output_amount,
            "fee_amount": fee_amount,
            "new_price": self.get_price(),
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve,
            "total_volume_btc": self.total_volume_btc,
            "swap_count": self.total_swaps,
            "message": "Community fair market price updated through trading"
        }
    
    def get_market_stats(self) -> Dict:
        """Get basic market statistics"""
        return {
            "pool_exists": self.total_shares > 0,
            "current_price": self.get_price(),  # WEPO per BTC - community determined
            "btc_reserve": self.btc_reserve,
            "wepo_reserve": self.wepo_reserve,
            "total_liquidity_shares": self.total_shares,
            "fee_rate": self.fee_rate,
            "total_volume_btc": self.total_volume_btc,
            "total_swaps": self.total_swaps,
            "liquidity_providers": len(self.lp_positions),
            "creation_time": self.creation_timestamp.isoformat() if self.creation_timestamp else None,
            "philosophy": "Community creates the market, community determines the price"
        }

# Global market instance 
community_fair_market = CommunityFairMarketDEX()

# Export for integration
__all__ = ['CommunityFairMarketDEX', 'community_fair_market']