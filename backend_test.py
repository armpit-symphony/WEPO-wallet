#!/usr/bin/env python3
"""
WEPO BACKEND TESTING - PoS COLLATERAL API ENDPOINTS AUDIT

**REVIEW REQUEST FOCUS:**
Test the current PoS (Proof of Stake) collateral API endpoints to identify what's missing or not working properly.

**SPECIFIC ENDPOINTS TO TEST:**
1. **Current PoS Collateral Requirements**: Test `/api/collateral/requirements` to see if it properly shows PoS collateral amounts
2. **PoS Collateral Schedule**: Test `/api/collateral/schedule` to verify it shows the complete PoS collateral progression
3. **Staking System Info**: Test `/api/staking/info` to see what PoS-related information is available
4. **Individual PoS Stakes**: Test `/api/staking/stakes/{address}` with a test address to see what's returned
5. **Missing PoS Endpoints**: Identify what specific PoS collateral information is NOT available through existing endpoints

**GOAL:** 
Understand exactly what PoS collateral functionality is missing so we can implement the specific endpoints needed.
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

print(f"🎯 WEPO BACKEND TESTING - PoS COLLATERAL API ENDPOINTS AUDIT")
print(f"Preview Backend API URL: {API_URL}")
print(f"Focus: Testing PoS collateral endpoints to identify gaps")
print("=" * 80)

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": []
}

def log_test(name, passed, response=None, error=None, details=None):
    """Log test results with enhanced details"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} {name}")
    
    if details:
        print(f"  Details: {details}")
    
    if error:
        print(f"  Error: {error}")
    
    if response and not passed:
        print(f"  Response: {response}")
    
    test_results["total"] += 1
    if passed:
        test_results["passed"] += 1
    else:
        test_results["failed"] += 1
    
    test_results["tests"].append({
        "name": name,
        "passed": passed,
        "error": error,
        "details": details
    })

def generate_valid_wepo_address():
    """Generate a valid 37-character WEPO address (wepo1 + 32 hex chars)"""
    random_data = secrets.token_bytes(16)  # 16 bytes = 32 hex chars
    hex_part = random_data.hex()
    return f"wepo1{hex_part}"

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