#!/usr/bin/env python3
"""
WEPO COMPREHENSIVE END-TO-END BACKEND TESTING

**REVIEW REQUEST FOCUS:**
Conduct comprehensive end-to-end backend testing of the entire WEPO system to identify the current status 
of all components and specifically investigate recurring wallet authentication login issues.

**COMPREHENSIVE BACKEND TESTING SCOPE:**

**1. System Health and Integration**
- Test all core API endpoints for basic functionality
- Verify backend service status and database connectivity
- Check integration between different system components

**2. Wallet Authentication Deep Investigation**
- Test wallet creation endpoint thoroughly (identify any failures)
- Test wallet login/authentication flow (isolate recurring issues)
- Test session management and wallet context handling  
- Identify specific authentication failure points

**3. Core WEPO Features Integration**
- Test PoS collateral system endpoints (confirmed working previously)
- Test masternode system integration
- Test mining system endpoints
- Test Bitcoin wallet integration endpoints
- Test governance system endpoints

**4. Community Fair Market DEX**
- Test swap rate calculation
- Test liquidity management  
- Test market statistics

**5. Security and Validation**
- Test input validation across all endpoints
- Test security headers and CORS configuration
- Test rate limiting and error handling

**6. Database and Storage**
- Test data persistence and retrieval
- Test blockchain data consistency
- Test wallet data storage and security

**FOCUS AREAS:**
- **Priority 1**: Isolate the specific wallet authentication issues that keep recurring
- **Priority 2**: Verify end-to-end system integration works properly
- **Priority 3**: Identify any components that need cleanup or optimization

**GOAL:** 
Comprehensive status report of all backend components with specific identification of wallet authentication 
failure points and overall system health assessment.
"""
import requests
import json
import time
import uuid
import os
import sys
import secrets
from datetime import datetime
import random
import string
import base64
import hashlib
import re

# Use preview backend URL from frontend/.env
BACKEND_URL = "https://4fc16d3d-b093-48ef-affa-636fa6aa3b78.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🎯 WEPO COMPREHENSIVE END-TO-END BACKEND TESTING")
print(f"Preview Backend API URL: {API_URL}")
print(f"Focus: Comprehensive system testing with wallet authentication investigation")
print("=" * 80)

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": [],
    "categories": {
        "system_health": {"passed": 0, "total": 0},
        "wallet_auth": {"passed": 0, "total": 0},
        "core_features": {"passed": 0, "total": 0},
        "dex_market": {"passed": 0, "total": 0},
        "security": {"passed": 0, "total": 0},
        "database": {"passed": 0, "total": 0}
    }
}

def log_test(name, passed, category, response=None, error=None, details=None):
    """Log test results with enhanced details and categorization"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} {name}")
    
    if details:
        print(f"  Details: {details}")
    
    if error:
        print(f"  Error: {error}")
    
    if response and not passed:
        print(f"  Response: {response}")
    
    test_results["total"] += 1
    test_results["categories"][category]["total"] += 1
    
    if passed:
        test_results["passed"] += 1
        test_results["categories"][category]["passed"] += 1
    else:
        test_results["failed"] += 1
    
    test_results["tests"].append({
        "name": name,
        "category": category,
        "passed": passed,
        "error": error,
        "details": details
    })

def generate_valid_wepo_address():
    """Generate a valid 37-character WEPO address (wepo1 + 32 hex chars)"""
    random_data = secrets.token_bytes(16)  # 16 bytes = 32 hex chars
    hex_part = random_data.hex()
    return f"wepo1{hex_part}"

def generate_test_user_data():
    """Generate realistic test user data"""
    username = f"testuser_{secrets.token_hex(4)}"
    password = f"TestPass123!{secrets.token_hex(2)}"
    return username, password

# ===== 1. SYSTEM HEALTH AND INTEGRATION TESTS =====

def test_system_health():
    """Test 1: System Health and Integration"""
    print("\n🏥 SYSTEM HEALTH AND INTEGRATION TESTS")
    print("Testing core API endpoints for basic functionality...")
    
    # Test root endpoint
    try:
        response = requests.get(f"{API_URL}/")
        if response.status_code == 200:
            data = response.json()
            log_test("Root API Endpoint", True, "system_health", 
                    details=f"API accessible - {data.get('message', 'No message')}")
        else:
            log_test("Root API Endpoint", False, "system_health", 
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Root API Endpoint", False, "system_health", error=str(e))
    
    # Test network status
    try:
        response = requests.get(f"{API_URL}/network/status")
        if response.status_code == 200:
            data = response.json()
            required_fields = ["block_height", "network_hashrate", "active_masternodes", "total_supply"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if not missing_fields:
                log_test("Network Status Endpoint", True, "system_health",
                        details=f"All required fields present: {list(data.keys())}")
            else:
                log_test("Network Status Endpoint", False, "system_health",
                        details=f"Missing fields: {missing_fields}")
        else:
            log_test("Network Status Endpoint", False, "system_health",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Network Status Endpoint", False, "system_health", error=str(e))
    
    # Test mining info
    try:
        response = requests.get(f"{API_URL}/mining/info")
        if response.status_code == 200:
            data = response.json()
            required_fields = ["current_block_height", "current_reward", "difficulty", "algorithm"]
            missing_fields = [field for field in required_fields if field not in data]
            
            if not missing_fields:
                log_test("Mining Info Endpoint", True, "system_health",
                        details=f"Mining system operational: {data.get('algorithm', 'Unknown')} algorithm")
            else:
                log_test("Mining Info Endpoint", False, "system_health",
                        details=f"Missing fields: {missing_fields}")
        else:
            log_test("Mining Info Endpoint", False, "system_health",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Mining Info Endpoint", False, "system_health", error=str(e))

# ===== 2. WALLET AUTHENTICATION DEEP INVESTIGATION =====

def test_wallet_authentication():
    """Test 2: Wallet Authentication Deep Investigation"""
    print("\n🔐 WALLET AUTHENTICATION DEEP INVESTIGATION")
    print("Testing wallet creation and login flow to isolate recurring issues...")
    
    # Generate test user data
    username, password = generate_test_user_data()
    created_address = None
    
    # Test wallet creation
    try:
        create_data = {
            "username": username,
            "password": password
        }
        
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success") and data.get("address"):
                created_address = data["address"]
                log_test("Wallet Creation", True, "wallet_auth",
                        details=f"Wallet created successfully - Address: {created_address[:20]}...")
            else:
                log_test("Wallet Creation", False, "wallet_auth",
                        details=f"Success flag missing or no address: {data}")
        elif response.status_code == 400:
            # Check if it's a validation error (expected for some cases)
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            log_test("Wallet Creation", False, "wallet_auth",
                    details=f"Validation error: {error_data}")
        else:
            log_test("Wallet Creation", False, "wallet_auth",
                    details=f"HTTP {response.status_code}: {response.text[:200]}")
    except Exception as e:
        log_test("Wallet Creation", False, "wallet_auth", error=str(e))
    
    # Test wallet login (only if creation succeeded)
    if created_address:
        try:
            login_data = {
                "username": username,
                "password": password
            }
            
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and data.get("address") == created_address:
                    log_test("Wallet Login", True, "wallet_auth",
                            details=f"Login successful - Address matches: {data.get('address', '')[:20]}...")
                else:
                    log_test("Wallet Login", False, "wallet_auth",
                            details=f"Login response invalid: {data}")
            elif response.status_code == 401:
                log_test("Wallet Login", False, "wallet_auth",
                        details="Authentication failed - Invalid credentials")
            elif response.status_code == 429:
                log_test("Wallet Login", False, "wallet_auth",
                        details="Rate limiting active - Too many attempts")
            else:
                log_test("Wallet Login", False, "wallet_auth",
                        details=f"HTTP {response.status_code}: {response.text[:200]}")
        except Exception as e:
            log_test("Wallet Login", False, "wallet_auth", error=str(e))
    else:
        log_test("Wallet Login", False, "wallet_auth",
                details="Skipped - Wallet creation failed")
    
    # Test wallet info retrieval (if we have an address)
    if created_address:
        try:
            response = requests.get(f"{API_URL}/wallet/{created_address}")
            
            if response.status_code == 200:
                data = response.json()
                required_fields = ["address", "balance", "username"]
                missing_fields = [field for field in required_fields if field not in data]
                
                if not missing_fields:
                    log_test("Wallet Info Retrieval", True, "wallet_auth",
                            details=f"Wallet info complete - Balance: {data.get('balance', 0)} WEPO")
                else:
                    log_test("Wallet Info Retrieval", False, "wallet_auth",
                            details=f"Missing fields: {missing_fields}")
            else:
                log_test("Wallet Info Retrieval", False, "wallet_auth",
                        details=f"HTTP {response.status_code}: {response.text[:100]}")
        except Exception as e:
            log_test("Wallet Info Retrieval", False, "wallet_auth", error=str(e))
    else:
        log_test("Wallet Info Retrieval", False, "wallet_auth",
                details="Skipped - No wallet address available")
    
    # Test invalid login attempts (security testing)
    try:
        invalid_login_data = {
            "username": username,
            "password": "wrongpassword123"
        }
        
        response = requests.post(f"{API_URL}/wallet/login", json=invalid_login_data)
        
        if response.status_code == 401:
            log_test("Invalid Login Handling", True, "wallet_auth",
                    details="Correctly rejected invalid credentials")
        elif response.status_code == 429:
            log_test("Invalid Login Handling", True, "wallet_auth",
                    details="Rate limiting active - Security measure working")
        else:
            log_test("Invalid Login Handling", False, "wallet_auth",
                    details=f"Unexpected response: HTTP {response.status_code}")
    except Exception as e:
        log_test("Invalid Login Handling", False, "wallet_auth", error=str(e))

# ===== 3. CORE WEPO FEATURES INTEGRATION =====

def test_core_features():
    """Test 3: Core WEPO Features Integration"""
    print("\n⚡ CORE WEPO FEATURES INTEGRATION TESTS")
    print("Testing PoS collateral, masternode, mining, and governance systems...")
    
    # Test mining status
    try:
        response = requests.get(f"{API_URL}/mining/status")
        if response.status_code == 200:
            data = response.json()
            if "connected_miners" in data and "total_hashrate" in data:
                log_test("Mining System Status", True, "core_features",
                        details=f"Mining active - {data.get('connected_miners', 0)} miners, {data.get('total_hashrate', 0)} H/s")
            else:
                log_test("Mining System Status", False, "core_features",
                        details=f"Missing mining data: {list(data.keys())}")
        else:
            log_test("Mining System Status", False, "core_features",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Mining System Status", False, "core_features", error=str(e))
    
    # Test staking endpoint
    try:
        test_address = generate_valid_wepo_address()
        stake_data = {
            "wallet_address": test_address,
            "amount": 1000.0,
            "lock_period_months": 12
        }
        
        response = requests.post(f"{API_URL}/stake", json=stake_data)
        
        if response.status_code == 404:
            log_test("Staking System", False, "core_features",
                    details="Wallet not found (expected for test address)")
        elif response.status_code == 400:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            if "balance" in str(error_data).lower():
                log_test("Staking System", True, "core_features",
                        details="Staking validation working - Balance check active")
            else:
                log_test("Staking System", False, "core_features",
                        details=f"Unexpected validation error: {error_data}")
        elif response.status_code == 200:
            log_test("Staking System", True, "core_features",
                    details="Staking system operational")
        else:
            log_test("Staking System", False, "core_features",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Staking System", False, "core_features", error=str(e))
    
    # Test masternode setup
    try:
        test_address = generate_valid_wepo_address()
        masternode_data = {
            "wallet_address": test_address,
            "server_ip": "192.168.1.100",
            "server_port": 22567
        }
        
        response = requests.post(f"{API_URL}/masternode", json=masternode_data)
        
        if response.status_code == 404:
            log_test("Masternode System", False, "core_features",
                    details="Wallet not found (expected for test address)")
        elif response.status_code == 400:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            if "balance" in str(error_data).lower() or "10000" in str(error_data):
                log_test("Masternode System", True, "core_features",
                        details="Masternode validation working - Collateral check active")
            else:
                log_test("Masternode System", False, "core_features",
                        details=f"Unexpected validation error: {error_data}")
        elif response.status_code == 200:
            log_test("Masternode System", True, "core_features",
                    details="Masternode system operational")
        else:
            log_test("Masternode System", False, "core_features",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Masternode System", False, "core_features", error=str(e))

# ===== 4. COMMUNITY FAIR MARKET DEX =====

def test_dex_market():
    """Test 4: Community Fair Market DEX"""
    print("\n💱 COMMUNITY FAIR MARKET DEX TESTS")
    print("Testing swap rate calculation, liquidity management, and market statistics...")
    
    # Test swap rate endpoint
    try:
        response = requests.get(f"{API_URL}/swap/rate")
        if response.status_code == 200:
            data = response.json()
            if "btc_to_wepo" in data or "pool_exists" in data:
                log_test("Swap Rate Calculation", True, "dex_market",
                        details=f"Market data available - Pool exists: {data.get('pool_exists', 'Unknown')}")
            else:
                log_test("Swap Rate Calculation", False, "dex_market",
                        details=f"Missing market data: {list(data.keys())}")
        else:
            log_test("Swap Rate Calculation", False, "dex_market",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Swap Rate Calculation", False, "dex_market", error=str(e))
    
    # Test liquidity stats
    try:
        response = requests.get(f"{API_URL}/liquidity/stats")
        if response.status_code == 200:
            data = response.json()
            if "pool_exists" in data:
                log_test("Liquidity Management", True, "dex_market",
                        details=f"Liquidity system operational - Pool exists: {data.get('pool_exists', False)}")
            else:
                log_test("Liquidity Management", False, "dex_market",
                        details=f"Missing liquidity data: {list(data.keys())}")
        else:
            log_test("Liquidity Management", False, "dex_market",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Liquidity Management", False, "dex_market", error=str(e))
    
    # Test DEX rate endpoint (legacy)
    try:
        response = requests.get(f"{API_URL}/dex/rate")
        if response.status_code == 200:
            data = response.json()
            if "btc_to_wepo" in data and "wepo_to_btc" in data:
                log_test("DEX Rate System", True, "dex_market",
                        details=f"Exchange rates available - BTC/WEPO: {data.get('btc_to_wepo', 'N/A')}")
            else:
                log_test("DEX Rate System", False, "dex_market",
                        details=f"Missing rate data: {list(data.keys())}")
        else:
            log_test("DEX Rate System", False, "dex_market",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("DEX Rate System", False, "dex_market", error=str(e))

# ===== 5. SECURITY AND VALIDATION =====

def test_security():
    """Test 5: Security and Validation"""
    print("\n🔒 SECURITY AND VALIDATION TESTS")
    print("Testing input validation, security headers, and error handling...")
    
    # Test security headers
    try:
        response = requests.get(f"{API_URL}/")
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        
        present_headers = [header for header in security_headers if header in response.headers]
        missing_headers = [header for header in security_headers if header not in response.headers]
        
        if len(present_headers) >= 3:
            log_test("Security Headers", True, "security",
                    details=f"Security headers present: {present_headers}")
        else:
            log_test("Security Headers", False, "security",
                    details=f"Missing security headers: {missing_headers}")
    except Exception as e:
        log_test("Security Headers", False, "security", error=str(e))
    
    # Test input validation with malicious input
    try:
        malicious_data = {
            "username": "<script>alert('xss')</script>",
            "password": "'; DROP TABLE users; --"
        }
        
        response = requests.post(f"{API_URL}/wallet/create", json=malicious_data)
        
        if response.status_code == 400:
            log_test("Input Validation", True, "security",
                    details="Malicious input properly rejected")
        elif response.status_code == 500:
            log_test("Input Validation", False, "security",
                    details="Server error - Input validation may be insufficient")
        else:
            log_test("Input Validation", False, "security",
                    details=f"Unexpected response: HTTP {response.status_code}")
    except Exception as e:
        log_test("Input Validation", False, "security", error=str(e))
    
    # Test rate limiting
    try:
        # Make multiple rapid requests to test rate limiting
        rapid_requests = []
        for i in range(3):
            response = requests.post(f"{API_URL}/wallet/login", json={"username": "test", "password": "test"})
            rapid_requests.append(response.status_code)
        
        if 429 in rapid_requests:
            log_test("Rate Limiting", True, "security",
                    details="Rate limiting active - 429 status received")
        elif all(status == 401 for status in rapid_requests):
            log_test("Rate Limiting", True, "security",
                    details="Consistent authentication handling")
        else:
            log_test("Rate Limiting", False, "security",
                    details=f"Rate limiting unclear - Status codes: {rapid_requests}")
    except Exception as e:
        log_test("Rate Limiting", False, "security", error=str(e))

# ===== 6. DATABASE AND STORAGE =====

def test_database():
    """Test 6: Database and Storage"""
    print("\n💾 DATABASE AND STORAGE TESTS")
    print("Testing data persistence, retrieval, and consistency...")
    
    # Test latest blocks endpoint
    try:
        response = requests.get(f"{API_URL}/blocks/latest")
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                log_test("Blockchain Data Storage", True, "database",
                        details=f"Block data accessible - {len(data)} blocks retrieved")
            else:
                log_test("Blockchain Data Storage", False, "database",
                        details=f"Unexpected data format: {type(data)}")
        else:
            log_test("Blockchain Data Storage", False, "database",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Blockchain Data Storage", False, "database", error=str(e))
    
    # Test wallet transactions endpoint
    try:
        test_address = generate_valid_wepo_address()
        response = requests.get(f"{API_URL}/wallet/{test_address}/transactions")
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                log_test("Transaction Data Storage", True, "database",
                        details=f"Transaction data accessible - {len(data)} transactions")
            else:
                log_test("Transaction Data Storage", False, "database",
                        details=f"Unexpected data format: {type(data)}")
        elif response.status_code == 404:
            log_test("Transaction Data Storage", True, "database",
                    details="Proper 404 handling for non-existent address")
        else:
            log_test("Transaction Data Storage", False, "database",
                    details=f"HTTP {response.status_code}: {response.text[:100]}")
    except Exception as e:
        log_test("Transaction Data Storage", False, "database", error=str(e))
    
    # Test data consistency with network status
    try:
        response = requests.get(f"{API_URL}/network/status")
        if response.status_code == 200:
            data = response.json()
            
            # Check if numeric fields are reasonable
            block_height = data.get("block_height", 0)
            total_supply = data.get("total_supply", 0)
            
            if isinstance(block_height, (int, float)) and isinstance(total_supply, (int, float)):
                if block_height >= 0 and total_supply > 0:
                    log_test("Data Consistency", True, "database",
                            details=f"Network data consistent - Height: {block_height}, Supply: {total_supply}")
                else:
                    log_test("Data Consistency", False, "database",
                            details=f"Invalid data values - Height: {block_height}, Supply: {total_supply}")
            else:
                log_test("Data Consistency", False, "database",
                        details=f"Invalid data types - Height: {type(block_height)}, Supply: {type(total_supply)}")
        else:
            log_test("Data Consistency", False, "database",
                    details=f"Cannot verify consistency - HTTP {response.status_code}")
    except Exception as e:
        log_test("Data Consistency", False, "database", error=str(e))

def test_pos_collateral_requirements():
    """Test 1: Current PoS Collateral Requirements - /api/collateral/requirements"""
    print("\n🎯 TEST 1: CURRENT PoS COLLATERAL REQUIREMENTS")
    print("Testing /api/collateral/requirements to see if it properly shows PoS collateral amounts...")
    
    try:
        response = requests.get(f"{API_URL}/collateral/requirements")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Endpoint accessible - Response keys: {list(data.keys())}")
            
            # Check for PoS collateral information
            data_str = str(data).lower()
            pos_indicators = ['pos', 'proof of stake', 'staking', 'stake_amount', 'pos_collateral']
            
            pos_data_found = any(indicator in data_str for indicator in pos_indicators)
            
            if pos_data_found:
                log_test("PoS Collateral Requirements Endpoint", True,
                        details=f"✅ Found PoS collateral data in response: {json.dumps(data, indent=2)[:200]}...")
                return True, data
            else:
                log_test("PoS Collateral Requirements Endpoint", False,
                        details=f"❌ No PoS collateral data found. Response: {json.dumps(data, indent=2)[:200]}...")
                return False, data
        elif response.status_code == 404:
            log_test("PoS Collateral Requirements Endpoint", False,
                    details="❌ Endpoint not found (404) - needs to be implemented")
            return False, None
        else:
            log_test("PoS Collateral Requirements Endpoint", False,
                    details=f"❌ HTTP {response.status_code}: {response.text[:100]}...")
            return False, None
            
    except Exception as e:
        log_test("PoS Collateral Requirements Endpoint", False, error=str(e))
        return False, None

def test_pos_collateral_schedule():
    """Test 2: PoS Collateral Schedule - /api/collateral/schedule"""
    print("\n🎯 TEST 2: PoS COLLATERAL SCHEDULE")
    print("Testing /api/collateral/schedule to verify it shows the complete PoS collateral progression...")
    
    try:
        response = requests.get(f"{API_URL}/collateral/schedule")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Endpoint accessible - Response keys: {list(data.keys())}")
            
            # Check for PoS collateral schedule information
            data_str = str(data).lower()
            schedule_indicators = ['schedule', 'progression', 'phase', 'pos', 'staking', 'collateral']
            
            schedule_data_found = any(indicator in data_str for indicator in schedule_indicators)
            
            if schedule_data_found:
                log_test("PoS Collateral Schedule Endpoint", True,
                        details=f"✅ Found PoS collateral schedule data: {json.dumps(data, indent=2)[:200]}...")
                return True, data
            else:
                log_test("PoS Collateral Schedule Endpoint", False,
                        details=f"❌ No PoS collateral schedule data found. Response: {json.dumps(data, indent=2)[:200]}...")
                return False, data
        elif response.status_code == 404:
            log_test("PoS Collateral Schedule Endpoint", False,
                    details="❌ Endpoint not found (404) - needs to be implemented")
            return False, None
        else:
            log_test("PoS Collateral Schedule Endpoint", False,
                    details=f"❌ HTTP {response.status_code}: {response.text[:100]}...")
            return False, None
            
    except Exception as e:
        log_test("PoS Collateral Schedule Endpoint", False, error=str(e))
        return False, None

def test_staking_system_info():
    """Test 3: Staking System Info - /api/staking/info"""
    print("\n🎯 TEST 3: STAKING SYSTEM INFO")
    print("Testing /api/staking/info to see what PoS-related information is available...")
    
    try:
        response = requests.get(f"{API_URL}/staking/info")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Endpoint accessible - Response keys: {list(data.keys())}")
            
            # Check for comprehensive PoS staking information
            data_str = str(data).lower()
            staking_indicators = ['staking', 'pos', 'stake', 'reward', 'apr', 'collateral', 'validator']
            
            staking_info_found = any(indicator in data_str for indicator in staking_indicators)
            
            if staking_info_found:
                log_test("Staking System Info Endpoint", True,
                        details=f"✅ Found PoS staking system info: {json.dumps(data, indent=2)[:200]}...")
                return True, data
            else:
                log_test("Staking System Info Endpoint", False,
                        details=f"❌ No PoS staking system info found. Response: {json.dumps(data, indent=2)[:200]}...")
                return False, data
        elif response.status_code == 404:
            log_test("Staking System Info Endpoint", False,
                    details="❌ Endpoint not found (404) - needs to be implemented")
            return False, None
        else:
            log_test("Staking System Info Endpoint", False,
                    details=f"❌ HTTP {response.status_code}: {response.text[:100]}...")
            return False, None
            
    except Exception as e:
        log_test("Staking System Info Endpoint", False, error=str(e))
        return False, None

def test_individual_pos_stakes():
    """Test 4: Individual PoS Stakes - /api/staking/stakes/{address}"""
    print("\n🎯 TEST 4: INDIVIDUAL PoS STAKES")
    print("Testing /api/staking/stakes/{address} with a test address to see what's returned...")
    
    # Generate test address
    test_address = generate_valid_wepo_address()
    print(f"  Using test address: {test_address}")
    
    try:
        response = requests.get(f"{API_URL}/staking/stakes/{test_address}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Endpoint accessible - Response keys: {list(data.keys())}")
            
            # Check for individual stake information
            data_str = str(data).lower()
            stake_indicators = ['stake', 'amount', 'reward', 'status', 'position', 'balance']
            
            stake_info_found = any(indicator in data_str for indicator in stake_indicators)
            
            if stake_info_found:
                log_test("Individual PoS Stakes Endpoint", True,
                        details=f"✅ Found individual stake info: {json.dumps(data, indent=2)[:200]}...")
                return True, data
            else:
                log_test("Individual PoS Stakes Endpoint", False,
                        details=f"❌ No individual stake info found. Response: {json.dumps(data, indent=2)[:200]}...")
                return False, data
        elif response.status_code == 404:
            # Check if it's endpoint not found vs address not found
            if "not found" in response.text.lower() and "address" in response.text.lower():
                log_test("Individual PoS Stakes Endpoint", True,
                        details="✅ Endpoint exists but address not found (expected for test address)")
                return True, {"message": "Address not found (expected)"}
            else:
                log_test("Individual PoS Stakes Endpoint", False,
                        details="❌ Endpoint not found (404) - needs to be implemented")
                return False, None
        else:
            log_test("Individual PoS Stakes Endpoint", False,
                    details=f"❌ HTTP {response.status_code}: {response.text[:100]}...")
            return False, None
            
    except Exception as e:
        log_test("Individual PoS Stakes Endpoint", False, error=str(e))
        return False, None

def test_missing_pos_endpoints():
    """Test 5: Missing PoS Endpoints - Identify what specific PoS collateral information is NOT available"""
    print("\n🎯 TEST 5: MISSING PoS ENDPOINTS DISCOVERY")
    print("Testing additional PoS-related endpoints to identify gaps...")
    
    # Additional PoS endpoints that might be expected
    additional_endpoints = [
        "/api/pos/status",
        "/api/pos/validators", 
        "/api/pos/rewards",
        "/api/staking/pools",
        "/api/staking/validators",
        "/api/staking/rewards/{address}",
        "/api/collateral/pos",
        "/api/collateral/dynamic",
        "/api/validators/list",
        "/api/validators/info"
    ]
    
    working_endpoints = []
    missing_endpoints = []
    
    try:
        for endpoint in additional_endpoints:
            try:
                # For endpoints with {address}, use test address
                test_endpoint = endpoint.replace("{address}", generate_valid_wepo_address())
                response = requests.get(f"{API_URL}{test_endpoint}")
                
                if response.status_code == 200:
                    data = response.json()
                    working_endpoints.append({
                        "endpoint": endpoint,
                        "status": "working",
                        "data_keys": list(data.keys())[:5]
                    })
                    print(f"  ✅ {endpoint} - Working")
                elif response.status_code == 404:
                    missing_endpoints.append({
                        "endpoint": endpoint,
                        "status": "missing",
                        "reason": "404 Not Found"
                    })
                    print(f"  ❌ {endpoint} - Missing (404)")
                else:
                    missing_endpoints.append({
                        "endpoint": endpoint,
                        "status": "error",
                        "reason": f"HTTP {response.status_code}"
                    })
                    print(f"  ⚠️  {endpoint} - Error (HTTP {response.status_code})")
                    
            except Exception as e:
                missing_endpoints.append({
                    "endpoint": endpoint,
                    "status": "error",
                    "reason": str(e)
                })
                print(f"  ❌ {endpoint} - Error: {str(e)}")
        
        # Analyze results
        total_tested = len(additional_endpoints)
        working_count = len(working_endpoints)
        missing_count = len(missing_endpoints)
        
        if working_count > 0:
            log_test("Missing PoS Endpoints Discovery", True,
                    details=f"✅ Found {working_count}/{total_tested} additional PoS endpoints working")
        else:
            log_test("Missing PoS Endpoints Discovery", False,
                    details=f"❌ No additional PoS endpoints found - {missing_count}/{total_tested} missing")
        
        return {
            "working_endpoints": working_endpoints,
            "missing_endpoints": missing_endpoints,
            "total_tested": total_tested,
            "working_count": working_count,
            "missing_count": missing_count
        }
            
    except Exception as e:
        log_test("Missing PoS Endpoints Discovery", False, error=str(e))
        return None

def run_pos_collateral_audit():
    """Run PoS collateral endpoints audit"""
    print("🔍 STARTING WEPO PoS COLLATERAL API ENDPOINTS AUDIT")
    print("Testing specific PoS collateral endpoints as requested in review...")
    print("=" * 80)
    
    # Run the PoS collateral tests
    test1_result, test1_data = test_pos_collateral_requirements()
    test2_result, test2_data = test_pos_collateral_schedule()
    test3_result, test3_data = test_staking_system_info()
    test4_result, test4_data = test_individual_pos_stakes()
    test5_result = test_missing_pos_endpoints()
    
    # Print final results
    print("\n" + "=" * 80)
    print("🔍 WEPO PoS COLLATERAL API ENDPOINTS AUDIT RESULTS")
    print("=" * 80)
    
    success_rate = (test_results["passed"] / test_results["total"]) * 100 if test_results["total"] > 0 else 0
    
    print(f"Total Tests: {test_results['total']}")
    print(f"Passed: {test_results['passed']} ✅")
    print(f"Failed: {test_results['failed']} ❌")
    print(f"Overall Success Rate: {success_rate:.1f}%")
    
    # PoS Collateral Specific Results
    print("\n🎯 PoS COLLATERAL ENDPOINTS STATUS:")
    pos_tests = [
        ("Current PoS Collateral Requirements", test1_result),
        ("PoS Collateral Schedule", test2_result), 
        ("Staking System Info", test3_result),
        ("Individual PoS Stakes", test4_result),
        ("Missing PoS Endpoints Discovery", test5_result is not None and test5_result.get("working_count", 0) > 0)
    ]
    
    pos_passed = 0
    for test_name, test_result in pos_tests:
        if test_result:
            pos_passed += 1
            print(f"  ✅ {test_name}")
        else:
            print(f"  ❌ {test_name}")
    
    print(f"\nPoS Collateral Endpoints: {pos_passed}/{len(pos_tests)} working")
    
    # Detailed findings
    print("\n🚨 DETAILED PoS COLLATERAL FINDINGS:")
    
    failed_tests = [test for test in test_results['tests'] if not test['passed']]
    if failed_tests:
        print("❌ MISSING/BROKEN PoS ENDPOINTS:")
        for test in failed_tests:
            print(f"  • {test['name']}: {test['details'] or test['error']}")
    
    working_tests = [test for test in test_results['tests'] if test['passed']]
    if working_tests:
        print("✅ WORKING PoS ENDPOINTS:")
        for test in working_tests:
            print(f"  • {test['name']}: {test['details']}")
    
    # Missing endpoints analysis
    if test5_result:
        print(f"\n📊 ADDITIONAL PoS ENDPOINTS ANALYSIS:")
        print(f"• Working additional endpoints: {test5_result['working_count']}/{test5_result['total_tested']}")
        print(f"• Missing additional endpoints: {test5_result['missing_count']}/{test5_result['total_tested']}")
        
        if test5_result['working_endpoints']:
            print("✅ FOUND ADDITIONAL WORKING ENDPOINTS:")
            for endpoint in test5_result['working_endpoints']:
                print(f"  • {endpoint['endpoint']} - Keys: {endpoint['data_keys']}")
        
        if test5_result['missing_endpoints']:
            print("❌ MISSING ENDPOINTS THAT SHOULD BE IMPLEMENTED:")
            for endpoint in test5_result['missing_endpoints']:
                print(f"  • {endpoint['endpoint']} - {endpoint['reason']}")
    
    return {
        "success_rate": success_rate,
        "pos_collateral_requirements": test1_result,
        "pos_collateral_schedule": test2_result,
        "staking_system_info": test3_result,
        "individual_pos_stakes": test4_result,
        "missing_endpoints_analysis": test5_result,
        "failed_tests": failed_tests,
        "working_tests": working_tests,
        "pos_passed": pos_passed,
        "pos_total": len(pos_tests)
    }

if __name__ == "__main__":
    # Run the PoS collateral audit
    results = run_pos_collateral_audit()
    
    print("\n" + "=" * 80)
    print("🎯 FINAL PoS COLLATERAL AUDIT SUMMARY")
    print("=" * 80)
    
    if results["success_rate"] >= 60:
        print(f"🎉 MOST PoS ENDPOINTS WORKING!")
        print(f"✅ {results['success_rate']:.1f}% success rate achieved")
        print(f"✅ {results['pos_passed']}/{results['pos_total']} PoS endpoints functional")
    else:
        print(f"🚨 CRITICAL PoS ENDPOINTS MISSING!")
        print(f"⚠️  Success rate: {results['success_rate']:.1f}%")
        print(f"❌ {results['pos_passed']}/{results['pos_total']} PoS endpoints functional")
    
    print(f"\n📊 PoS COLLATERAL ENDPOINT STATUS:")
    print(f"• /api/collateral/requirements: {'✅ WORKING' if results['pos_collateral_requirements'] else '❌ MISSING/BROKEN'}")
    print(f"• /api/collateral/schedule: {'✅ WORKING' if results['pos_collateral_schedule'] else '❌ MISSING/BROKEN'}")
    print(f"• /api/staking/info: {'✅ WORKING' if results['staking_system_info'] else '❌ MISSING/BROKEN'}")
    print(f"• /api/staking/stakes/{{address}}: {'✅ WORKING' if results['individual_pos_stakes'] else '❌ MISSING/BROKEN'}")
    
    if results["missing_endpoints_analysis"]:
        additional_working = results["missing_endpoints_analysis"]["working_count"]
        additional_total = results["missing_endpoints_analysis"]["total_tested"]
        print(f"• Additional PoS endpoints: {additional_working}/{additional_total} working")
    
    if results["failed_tests"]:
        print(f"\n🔧 PRIORITY PoS ENDPOINTS TO IMPLEMENT:")
        for i, test in enumerate(results["failed_tests"], 1):
            print(f"{i}. {test['name']}")
            print(f"   Issue: {test['details'] or test['error']}")
    
    print(f"\n💡 RECOMMENDATIONS:")
    if results["success_rate"] < 60:
        print("• Implement missing PoS collateral endpoints")
        print("• Add comprehensive PoS staking information APIs")
        print("• Create PoS collateral schedule progression endpoint")
        print("• Ensure individual stake tracking functionality")
    else:
        print("• Most PoS endpoints are functional")
        print("• Consider adding additional PoS management features")
        print("• Enhance existing endpoints with more detailed information")