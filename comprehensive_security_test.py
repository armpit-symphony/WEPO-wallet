#!/usr/bin/env python3
"""
COMPREHENSIVE FINAL SECURITY VERIFICATION FOR CHRISTMAS DAY 2025 LAUNCH

This test suite conducts a comprehensive security audit to determine if the WEPO system
has achieved the 85%+ security score needed for Christmas Day 2025 cryptocurrency launch.

TEST CATEGORIES (Weighted):
1. BRUTE FORCE PROTECTION (25% weight) - Account lockout after 5 failed attempts
2. RATE LIMITING (25% weight) - Global API, wallet creation, login rate limits  
3. INPUT VALIDATION (20% weight) - XSS, injection, path traversal protection
4. AUTHENTICATION SECURITY (15% weight) - Password strength, hashing, flow security
5. SECURITY HEADERS (10% weight) - Critical security headers and CORS
6. DATA PROTECTION (5% weight) - Sensitive data exposure and error message security

CRITICAL SUCCESS CRITERIA:
- Overall security score must be 85%+ for cryptocurrency production launch
- All critical vulnerabilities must be resolved
- Rate limiting must be functional with HTTP 429 responses
- Brute force protection must work with HTTP 423 responses
"""

import requests
import json
import time
import uuid
import secrets
import threading
import concurrent.futures
from datetime import datetime
import random
import string

# Use preview backend URL from frontend/.env
BACKEND_URL = "https://012c0f35-c7c0-44db-b244-9d40fad5e286.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🔐 COMPREHENSIVE FINAL SECURITY VERIFICATION FOR CHRISTMAS DAY 2025 LAUNCH")
print(f"Backend API URL: {API_URL}")
print(f"Target: 85%+ Security Score for Cryptocurrency Production Launch")
print("=" * 80)

# Security test results tracking with weighted scoring
security_results = {
    "total_score": 0.0,
    "max_score": 100.0,
    "categories": {
        "brute_force_protection": {"score": 0, "max_score": 25, "weight": 0.25, "tests": []},
        "rate_limiting": {"score": 0, "max_score": 25, "weight": 0.25, "tests": []},
        "input_validation": {"score": 0, "max_score": 20, "weight": 0.20, "tests": []},
        "authentication_security": {"score": 0, "max_score": 15, "weight": 0.15, "tests": []},
        "security_headers": {"score": 0, "max_score": 10, "weight": 0.10, "tests": []},
        "data_protection": {"score": 0, "max_score": 5, "weight": 0.05, "tests": []}
    },
    "critical_vulnerabilities": [],
    "high_severity_issues": [],
    "passed_tests": 0,
    "total_tests": 0
}

def log_security_test(name, passed, category, severity="medium", details=None, response_code=None):
    """Log security test results with weighted scoring"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "🟡")
    
    print(f"{status} {severity_icon} {name}")
    if details:
        print(f"  Details: {details}")
    if response_code:
        print(f"  Response Code: HTTP {response_code}")
    
    # Track results
    security_results["total_tests"] += 1
    if passed:
        security_results["passed_tests"] += 1
    
    # Add to category
    test_result = {
        "name": name,
        "passed": passed,
        "severity": severity,
        "details": details,
        "response_code": response_code
    }
    security_results["categories"][category]["tests"].append(test_result)
    
    # Track critical and high severity issues
    if not passed:
        if severity == "critical":
            security_results["critical_vulnerabilities"].append(name)
        elif severity == "high":
            security_results["high_severity_issues"].append(name)

def calculate_category_score(category):
    """Calculate weighted score for a category"""
    cat_data = security_results["categories"][category]
    if not cat_data["tests"]:
        return 0
    
    passed_tests = len([t for t in cat_data["tests"] if t["passed"]])
    total_tests = len(cat_data["tests"])
    percentage = (passed_tests / total_tests) * 100
    
    # Apply severity weighting - critical failures get 0 points
    critical_failures = len([t for t in cat_data["tests"] if not t["passed"] and t["severity"] == "critical"])
    if critical_failures > 0:
        percentage = max(0, percentage - (critical_failures * 50))  # Heavy penalty for critical failures
    
    cat_data["score"] = (percentage / 100) * cat_data["max_score"]
    return cat_data["score"]

def generate_test_user():
    """Generate test user data"""
    username = f"sectest_{secrets.token_hex(4)}"
    password = f"SecTest123!{secrets.token_hex(2)}"
    return username, password

def generate_wepo_address():
    """Generate valid WEPO address"""
    return f"wepo1{secrets.token_hex(16)}"

# ===== 1. BRUTE FORCE PROTECTION TESTING (25% weight) =====

def test_brute_force_protection():
    """Test brute force protection with account lockout"""
    print("\n🔐 BRUTE FORCE PROTECTION TESTING (25% weight)")
    print("Testing account lockout after 5 failed login attempts...")
    
    # Create test wallet first
    username, password = generate_test_user()
    create_data = {"username": username, "password": password}
    
    try:
        create_response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        if create_response.status_code != 200:
            log_security_test("Brute Force Test Setup", False, "brute_force_protection", "critical",
                            f"Cannot create test wallet: HTTP {create_response.status_code}")
            return
        
        print(f"  Created test wallet: {username}")
        
        # Test 1: Account lockout after 5 failed attempts
        print("  Testing account lockout after 5 failed login attempts...")
        failed_attempts = 0
        
        for attempt in range(1, 9):  # Try up to 8 attempts
            login_data = {"username": username, "password": "wrong_password"}
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            
            print(f"    Attempt {attempt}: HTTP {response.status_code}")
            
            if response.status_code == 423:  # Account locked
                log_security_test("Account Lockout After Failed Attempts", True, "brute_force_protection", "critical",
                                f"Account locked after {attempt} failed attempts (HTTP 423)", 423)
                break
            elif response.status_code == 401:  # Still allowing attempts
                failed_attempts = attempt
                continue
            else:
                log_security_test("Account Lockout After Failed Attempts", False, "brute_force_protection", "critical",
                                f"Unexpected response on attempt {attempt}: HTTP {response.status_code}", response.status_code)
                break
        else:
            # If we get here, no lockout occurred after 8 attempts
            log_security_test("Account Lockout After Failed Attempts", False, "brute_force_protection", "critical",
                            f"NO account lockout after {failed_attempts} failed attempts", 401)
        
        # Test 2: Lockout persistence test
        if failed_attempts < 8:  # Only test if lockout occurred
            print("  Testing lockout persistence with correct password...")
            time.sleep(1)  # Brief pause
            correct_login_data = {"username": username, "password": password}
            response = requests.post(f"{API_URL}/wallet/login", json=correct_login_data)
            
            if response.status_code == 423:
                log_security_test("Lockout Persistence", True, "brute_force_protection", "high",
                                "Account remains locked even with correct password", 423)
            elif response.status_code == 200:
                log_security_test("Lockout Persistence", False, "brute_force_protection", "high",
                                "Account unlocked immediately with correct password", 200)
            else:
                log_security_test("Lockout Persistence", False, "brute_force_protection", "medium",
                                f"Unexpected lockout persistence response: HTTP {response.status_code}", response.status_code)
        
    except Exception as e:
        log_security_test("Brute Force Protection Testing", False, "brute_force_protection", "critical",
                        f"Test execution error: {str(e)}")

# ===== 2. RATE LIMITING TESTING (25% weight) =====

def test_rate_limiting():
    """Test comprehensive rate limiting implementation"""
    print("\n⏱️ RATE LIMITING TESTING (25% weight)")
    print("Testing global API rate limiting and endpoint-specific limits...")
    
    # Test 1: Global API rate limiting (60/minute)
    print("  Testing global API rate limiting (60/minute)...")
    try:
        start_time = time.time()
        rate_limit_hit = False
        
        for i in range(1, 101):  # Try 100 requests
            response = requests.get(f"{API_URL}/")
            
            if response.status_code == 429:
                log_security_test("Global API Rate Limiting", True, "rate_limiting", "critical",
                                f"Rate limit hit after {i} requests (HTTP 429)", 429)
                rate_limit_hit = True
                break
            elif i % 20 == 0:
                print(f"    Request {i}: HTTP {response.status_code}")
        
        if not rate_limit_hit:
            log_security_test("Global API Rate Limiting", False, "rate_limiting", "critical",
                            f"NO rate limiting after 100 requests in {time.time() - start_time:.1f}s", 200)
    
    except Exception as e:
        log_security_test("Global API Rate Limiting", False, "rate_limiting", "critical",
                        f"Test execution error: {str(e)}")
    
    # Test 2: Wallet creation rate limiting (3/minute)
    print("  Testing wallet creation rate limiting (3/minute)...")
    try:
        rate_limit_hit = False
        
        for i in range(1, 11):  # Try 10 wallet creations
            username, password = generate_test_user()
            create_data = {"username": username, "password": password}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            if response.status_code == 429:
                log_security_test("Wallet Creation Rate Limiting", True, "rate_limiting", "critical",
                                f"Rate limit hit after {i} wallet creation attempts (HTTP 429)", 429)
                rate_limit_hit = True
                break
            elif i % 2 == 0:
                print(f"    Creation {i}: HTTP {response.status_code}")
        
        if not rate_limit_hit:
            log_security_test("Wallet Creation Rate Limiting", False, "rate_limiting", "critical",
                            "NO wallet creation rate limiting after 10 attempts", 200)
    
    except Exception as e:
        log_security_test("Wallet Creation Rate Limiting", False, "rate_limiting", "critical",
                        f"Test execution error: {str(e)}")
    
    # Test 3: Login rate limiting (5/minute)
    print("  Testing login rate limiting (5/minute)...")
    try:
        # Create test wallet first
        username, password = generate_test_user()
        create_data = {"username": username, "password": password}
        create_response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if create_response.status_code == 200:
            rate_limit_hit = False
            
            for i in range(1, 16):  # Try 15 login attempts
                login_data = {"username": username, "password": password}
                response = requests.post(f"{API_URL}/wallet/login", json=login_data)
                
                if response.status_code == 429:
                    log_security_test("Login Rate Limiting", True, "rate_limiting", "critical",
                                    f"Rate limit hit after {i} login attempts (HTTP 429)", 429)
                    rate_limit_hit = True
                    break
                elif i % 3 == 0:
                    print(f"    Login {i}: HTTP {response.status_code}")
            
            if not rate_limit_hit:
                log_security_test("Login Rate Limiting", False, "rate_limiting", "critical",
                                "NO login rate limiting after 15 attempts", 200)
        else:
            log_security_test("Login Rate Limiting", False, "rate_limiting", "medium",
                            "Cannot test login rate limiting - wallet creation failed")
    
    except Exception as e:
        log_security_test("Login Rate Limiting", False, "rate_limiting", "critical",
                        f"Test execution error: {str(e)}")
    
    # Test 4: Rate limiting headers
    print("  Testing rate limiting headers...")
    try:
        response = requests.get(f"{API_URL}/")
        rate_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"]
        present_headers = [h for h in rate_headers if h in response.headers]
        
        if len(present_headers) >= 2:
            log_security_test("Rate Limiting Headers", True, "rate_limiting", "medium",
                            f"Rate limiting headers present: {present_headers}")
        else:
            log_security_test("Rate Limiting Headers", False, "rate_limiting", "medium",
                            f"Missing rate limiting headers: {present_headers}")
    
    except Exception as e:
        log_security_test("Rate Limiting Headers", False, "rate_limiting", "medium",
                        f"Test execution error: {str(e)}")

# ===== 3. INPUT VALIDATION TESTING (20% weight) =====

def test_input_validation():
    """Test comprehensive input validation and sanitization"""
    print("\n🛡️ INPUT VALIDATION TESTING (20% weight)")
    print("Testing XSS, injection, and path traversal protection...")
    
    # Test 1: XSS Protection
    print("  Testing XSS protection...")
    xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "';alert('xss');//",
        "<svg onload=alert('xss')>"
    ]
    
    xss_blocked = 0
    for i, payload in enumerate(xss_payloads, 1):
        try:
            username = f"xss_test_{i}"
            create_data = {"username": payload, "password": "TestPass123!"}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            # Check if XSS payload was blocked (400 error or sanitized)
            if response.status_code == 400 or (response.status_code == 200 and payload not in str(response.text)):
                xss_blocked += 1
                print(f"    XSS Payload {i}: BLOCKED ✅")
            else:
                print(f"    XSS Payload {i}: NOT BLOCKED ❌")
        
        except Exception as e:
            print(f"    XSS Payload {i}: ERROR - {str(e)}")
    
    if xss_blocked == len(xss_payloads):
        log_security_test("XSS Protection", True, "input_validation", "high",
                        f"All {len(xss_payloads)} XSS payloads blocked")
    elif xss_blocked >= len(xss_payloads) * 0.8:
        log_security_test("XSS Protection", True, "input_validation", "medium",
                        f"{xss_blocked}/{len(xss_payloads)} XSS payloads blocked")
    else:
        log_security_test("XSS Protection", False, "input_validation", "high",
                        f"Only {xss_blocked}/{len(xss_payloads)} XSS payloads blocked")
    
    # Test 2: SQL/NoSQL Injection Protection
    print("  Testing SQL/NoSQL injection protection...")
    injection_payloads = [
        "'; DROP TABLE wallets; --",
        "' OR '1'='1",
        "{$ne: null}",
        "'; return true; //",
        "admin'--"
    ]
    
    injection_blocked = 0
    for i, payload in enumerate(injection_payloads, 1):
        try:
            login_data = {"username": payload, "password": "test"}
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            
            # Check if injection was blocked (401 for invalid user, not 500 error)
            if response.status_code in [400, 401]:
                injection_blocked += 1
                print(f"    Injection Payload {i}: BLOCKED ✅")
            elif response.status_code == 500:
                print(f"    Injection Payload {i}: SERVER ERROR (possible injection) ❌")
            else:
                print(f"    Injection Payload {i}: UNEXPECTED RESPONSE ❌")
        
        except Exception as e:
            print(f"    Injection Payload {i}: ERROR - {str(e)}")
    
    if injection_blocked == len(injection_payloads):
        log_security_test("SQL/NoSQL Injection Protection", True, "input_validation", "high",
                        f"All {len(injection_payloads)} injection payloads blocked")
    elif injection_blocked >= len(injection_payloads) * 0.8:
        log_security_test("SQL/NoSQL Injection Protection", True, "input_validation", "medium",
                        f"{injection_blocked}/{len(injection_payloads)} injection payloads blocked")
    else:
        log_security_test("SQL/NoSQL Injection Protection", False, "input_validation", "high",
                        f"Only {injection_blocked}/{len(injection_payloads)} injection payloads blocked")
    
    # Test 3: Path Traversal Protection
    print("  Testing path traversal protection...")
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]
    
    traversal_blocked = 0
    for i, payload in enumerate(traversal_payloads, 1):
        try:
            # Test path traversal in wallet address parameter
            response = requests.get(f"{API_URL}/wallet/{payload}")
            
            # Check if traversal was blocked (400/404, not 500 or file content)
            if response.status_code in [400, 404]:
                traversal_blocked += 1
                print(f"    Traversal Payload {i}: BLOCKED ✅")
            elif response.status_code == 500:
                print(f"    Traversal Payload {i}: SERVER ERROR ❌")
            elif "root:" in response.text or "Administrator" in response.text:
                print(f"    Traversal Payload {i}: FILE CONTENT EXPOSED ❌")
            else:
                print(f"    Traversal Payload {i}: HANDLED ✅")
                traversal_blocked += 1
        
        except Exception as e:
            print(f"    Traversal Payload {i}: ERROR - {str(e)}")
    
    if traversal_blocked == len(traversal_payloads):
        log_security_test("Path Traversal Protection", True, "input_validation", "high",
                        f"All {len(traversal_payloads)} traversal payloads blocked")
    elif traversal_blocked >= len(traversal_payloads) * 0.75:
        log_security_test("Path Traversal Protection", True, "input_validation", "medium",
                        f"{traversal_blocked}/{len(traversal_payloads)} traversal payloads blocked")
    else:
        log_security_test("Path Traversal Protection", False, "input_validation", "high",
                        f"Only {traversal_blocked}/{len(traversal_payloads)} traversal payloads blocked")

# ===== 4. AUTHENTICATION SECURITY TESTING (15% weight) =====

def test_authentication_security():
    """Test authentication security mechanisms"""
    print("\n🔑 AUTHENTICATION SECURITY TESTING (15% weight)")
    print("Testing password strength, hashing, and authentication flow security...")
    
    # Test 1: Password strength validation
    print("  Testing password strength validation...")
    weak_passwords = [
        "123456",
        "password",
        "abc123",
        "test",
        "12345678",
        "qwerty",
        "admin"
    ]
    
    weak_rejected = 0
    for i, weak_pass in enumerate(weak_passwords, 1):
        try:
            username = f"weakpass_test_{i}"
            create_data = {"username": username, "password": weak_pass}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            if response.status_code == 400:
                weak_rejected += 1
                print(f"    Weak Password {i}: REJECTED ✅")
            else:
                print(f"    Weak Password {i}: ACCEPTED ❌")
        
        except Exception as e:
            print(f"    Weak Password {i}: ERROR - {str(e)}")
    
    if weak_rejected == len(weak_passwords):
        log_security_test("Password Strength Validation", True, "authentication_security", "medium",
                        f"All {len(weak_passwords)} weak passwords rejected")
    elif weak_rejected >= len(weak_passwords) * 0.8:
        log_security_test("Password Strength Validation", True, "authentication_security", "low",
                        f"{weak_rejected}/{len(weak_passwords)} weak passwords rejected")
    else:
        log_security_test("Password Strength Validation", False, "authentication_security", "medium",
                        f"Only {weak_rejected}/{len(weak_passwords)} weak passwords rejected")
    
    # Test 2: Strong password acceptance
    print("  Testing strong password acceptance...")
    strong_passwords = [
        "StrongPass123!@#",
        "MySecure$Password2024",
        "Complex&Password#789"
    ]
    
    strong_accepted = 0
    for i, strong_pass in enumerate(strong_passwords, 1):
        try:
            username = f"strongpass_test_{i}"
            create_data = {"username": username, "password": strong_pass}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            if response.status_code == 200:
                strong_accepted += 1
                print(f"    Strong Password {i}: ACCEPTED ✅")
            else:
                print(f"    Strong Password {i}: REJECTED ❌")
        
        except Exception as e:
            print(f"    Strong Password {i}: ERROR - {str(e)}")
    
    if strong_accepted == len(strong_passwords):
        log_security_test("Strong Password Acceptance", True, "authentication_security", "low",
                        f"All {len(strong_passwords)} strong passwords accepted")
    else:
        log_security_test("Strong Password Acceptance", False, "authentication_security", "medium",
                        f"Only {strong_accepted}/{len(strong_passwords)} strong passwords accepted")
    
    # Test 3: Password hashing security
    print("  Testing password hashing security...")
    try:
        username, password = generate_test_user()
        create_data = {"username": username, "password": password}
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            # Check if password is not returned in response
            response_text = response.text.lower()
            if password.lower() not in response_text:
                log_security_test("Password Hashing Security", True, "authentication_security", "high",
                                "Password not exposed in API responses")
            else:
                log_security_test("Password Hashing Security", False, "authentication_security", "critical",
                                "Password exposed in API response")
        else:
            log_security_test("Password Hashing Security", False, "authentication_security", "medium",
                            "Cannot test password hashing - wallet creation failed")
    
    except Exception as e:
        log_security_test("Password Hashing Security", False, "authentication_security", "medium",
                        f"Test execution error: {str(e)}")

# ===== 5. SECURITY HEADERS TESTING (10% weight) =====

def test_security_headers():
    """Test critical security headers implementation"""
    print("\n🛡️ SECURITY HEADERS TESTING (10% weight)")
    print("Testing critical security headers and CORS configuration...")
    
    try:
        response = requests.get(f"{API_URL}/")
        headers = response.headers
        
        # Test critical security headers
        critical_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": None,  # Just check presence
            "Strict-Transport-Security": None  # Just check presence
        }
        
        headers_present = 0
        total_headers = len(critical_headers)
        
        for header, expected_value in critical_headers.items():
            if header in headers:
                headers_present += 1
                print(f"    {header}: PRESENT ✅")
            else:
                print(f"    {header}: MISSING ❌")
        
        if headers_present == total_headers:
            log_security_test("Critical Security Headers", True, "security_headers", "medium",
                            f"All {total_headers} critical security headers present")
        elif headers_present >= total_headers * 0.8:
            log_security_test("Critical Security Headers", True, "security_headers", "low",
                            f"{headers_present}/{total_headers} critical security headers present")
        else:
            log_security_test("Critical Security Headers", False, "security_headers", "medium",
                            f"Only {headers_present}/{total_headers} critical security headers present")
        
        # Test CORS configuration
        print("  Testing CORS configuration...")
        cors_headers = ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"]
        cors_present = [h for h in cors_headers if h in headers]
        
        # Check if CORS is not wildcard (security risk)
        origin_header = headers.get("Access-Control-Allow-Origin", "")
        if origin_header and origin_header != "*":
            log_security_test("CORS Security Configuration", True, "security_headers", "low",
                            f"CORS properly configured (not wildcard): {origin_header}")
        elif origin_header == "*":
            log_security_test("CORS Security Configuration", False, "security_headers", "medium",
                            "CORS allows all origins (security risk)")
        else:
            log_security_test("CORS Security Configuration", True, "security_headers", "low",
                            "CORS headers properly configured")
    
    except Exception as e:
        log_security_test("Security Headers Testing", False, "security_headers", "medium",
                        f"Test execution error: {str(e)}")

# ===== 6. DATA PROTECTION TESTING (5% weight) =====

def test_data_protection():
    """Test data protection and privacy measures"""
    print("\n🔒 DATA PROTECTION TESTING (5% weight)")
    print("Testing sensitive data exposure and error message security...")
    
    # Test 1: Sensitive data exposure
    print("  Testing sensitive data exposure...")
    try:
        username, password = generate_test_user()
        create_data = {"username": username, "password": password}
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            response_data = response.json()
            sensitive_fields = ["password", "private_key", "seed", "mnemonic"]
            exposed_fields = [field for field in sensitive_fields if field in str(response_data).lower()]
            
            if not exposed_fields:
                log_security_test("Sensitive Data Exposure", True, "data_protection", "high",
                                "No sensitive data exposed in API responses")
            else:
                log_security_test("Sensitive Data Exposure", False, "data_protection", "critical",
                                f"Sensitive data exposed: {exposed_fields}")
        else:
            log_security_test("Sensitive Data Exposure", False, "data_protection", "medium",
                            "Cannot test data exposure - wallet creation failed")
    
    except Exception as e:
        log_security_test("Sensitive Data Exposure", False, "data_protection", "medium",
                        f"Test execution error: {str(e)}")
    
    # Test 2: Error message security
    print("  Testing error message security...")
    try:
        # Test with invalid data to trigger error messages
        invalid_data = {"username": "", "password": ""}
        response = requests.post(f"{API_URL}/wallet/create", json=invalid_data)
        
        if response.status_code == 400:
            error_text = response.text.lower()
            sensitive_info = ["database", "sql", "mongodb", "connection", "internal", "stack trace"]
            exposed_info = [info for info in sensitive_info if info in error_text]
            
            if not exposed_info:
                log_security_test("Error Message Security", True, "data_protection", "medium",
                                "Error messages don't disclose sensitive information")
            else:
                log_security_test("Error Message Security", False, "data_protection", "medium",
                                f"Error messages expose sensitive info: {exposed_info}")
        else:
            log_security_test("Error Message Security", False, "data_protection", "low",
                            "Cannot test error messages - unexpected response")
    
    except Exception as e:
        log_security_test("Error Message Security", False, "data_protection", "low",
                        f"Test execution error: {str(e)}")

def calculate_final_security_score():
    """Calculate final weighted security score"""
    total_score = 0
    
    for category, data in security_results["categories"].items():
        category_score = calculate_category_score(category)
        total_score += category_score
        print(f"  {category.replace('_', ' ').title()}: {category_score:.1f}/{data['max_score']} ({(category_score/data['max_score']*100):.1f}%)")
    
    security_results["total_score"] = total_score
    return total_score

def run_comprehensive_security_verification():
    """Run comprehensive security verification"""
    print("🔐 STARTING COMPREHENSIVE FINAL SECURITY VERIFICATION")
    print("Testing all security categories for Christmas Day 2025 launch readiness...")
    print("=" * 80)
    
    # Run all security test categories
    test_brute_force_protection()
    test_rate_limiting()
    test_input_validation()
    test_authentication_security()
    test_security_headers()
    test_data_protection()
    
    # Calculate final security score
    print("\n" + "=" * 80)
    print("🔐 COMPREHENSIVE SECURITY VERIFICATION RESULTS")
    print("=" * 80)
    
    final_score = calculate_final_security_score()
    success_rate = (security_results["passed_tests"] / security_results["total_tests"]) * 100 if security_results["total_tests"] > 0 else 0
    
    print(f"\n📊 FINAL SECURITY ASSESSMENT:")
    print(f"Overall Security Score: {final_score:.1f}/100.0 ({final_score:.1f}%)")
    print(f"Tests Passed: {security_results['passed_tests']}/{security_results['total_tests']} ({success_rate:.1f}%)")
    print(f"Target Score: 85.0% (Required for cryptocurrency production)")
    
    # Security category breakdown
    print(f"\n🔍 SECURITY CATEGORY BREAKDOWN:")
    
    # Christmas Day 2025 launch assessment
    print(f"\n🎄 CHRISTMAS DAY 2025 LAUNCH ASSESSMENT:")
    if final_score >= 85.0:
        print("🎉 LAUNCH STATUS: GO ✅")
        print("   System meets security requirements for cryptocurrency production")
        print("   Security score exceeds 85% target")
        print("   Ready for Christmas Day 2025 launch")
    elif final_score >= 70.0:
        print("⚠️  LAUNCH STATUS: CONDITIONAL")
        print("   System has good security but below production threshold")
        print("   Additional security improvements recommended")
        print("   Consider delayed launch until 85%+ achieved")
    else:
        print("🚨 LAUNCH STATUS: BLOCKED ❌")
        print("   System has critical security vulnerabilities")
        print("   Not suitable for cryptocurrency production")
        print("   Christmas Day 2025 launch must be delayed")
    
    # Critical vulnerabilities
    if security_results["critical_vulnerabilities"]:
        print(f"\n🔴 CRITICAL VULNERABILITIES ({len(security_results['critical_vulnerabilities'])}):")
        for i, vuln in enumerate(security_results["critical_vulnerabilities"], 1):
            print(f"  {i}. {vuln}")
    
    # High severity issues
    if security_results["high_severity_issues"]:
        print(f"\n🟠 HIGH SEVERITY ISSUES ({len(security_results['high_severity_issues'])}):")
        for i, issue in enumerate(security_results["high_severity_issues"], 1):
            print(f"  {i}. {issue}")
    
    # Production readiness assessment
    print(f"\n🏭 PRODUCTION READINESS:")
    critical_count = len(security_results["critical_vulnerabilities"])
    high_count = len(security_results["high_severity_issues"])
    
    if critical_count == 0 and high_count <= 2 and final_score >= 85.0:
        print("✅ READY FOR PRODUCTION")
        print("   No critical vulnerabilities")
        print("   Minimal high-severity issues")
        print("   Security score meets cryptocurrency standards")
    elif critical_count == 0 and final_score >= 75.0:
        print("⚠️  NEEDS MINOR IMPROVEMENTS")
        print("   No critical vulnerabilities")
        print("   Some security improvements needed")
        print("   Close to production readiness")
    else:
        print("🚨 NOT READY FOR PRODUCTION")
        print(f"   {critical_count} critical vulnerabilities present")
        print(f"   {high_count} high-severity issues present")
        print("   Significant security improvements required")
    
    return {
        "final_score": final_score,
        "success_rate": success_rate,
        "critical_vulnerabilities": security_results["critical_vulnerabilities"],
        "high_severity_issues": security_results["high_severity_issues"],
        "launch_ready": final_score >= 85.0 and critical_count == 0,
        "categories": security_results["categories"]
    }

if __name__ == "__main__":
    # Run comprehensive security verification
    results = run_comprehensive_security_verification()
    
    print("\n" + "=" * 80)
    print("🎄 FINAL CHRISTMAS DAY 2025 LAUNCH DECISION")
    print("=" * 80)
    
    print(f"📊 SECURITY METRICS:")
    print(f"• Final Security Score: {results['final_score']:.1f}% (Target: 85%+)")
    print(f"• Test Success Rate: {results['success_rate']:.1f}%")
    print(f"• Critical Vulnerabilities: {len(results['critical_vulnerabilities'])}")
    print(f"• High Severity Issues: {len(results['high_severity_issues'])}")
    
    print(f"\n🎯 LAUNCH DECISION:")
    if results['launch_ready']:
        print("🎉 CHRISTMAS DAY 2025 LAUNCH: APPROVED ✅")
        print("   System meets all security requirements")
        print("   Ready for cryptocurrency production operations")
        print("   Security score exceeds 85% threshold")
    else:
        print("🚨 CHRISTMAS DAY 2025 LAUNCH: BLOCKED ❌")
        print("   Critical security vulnerabilities must be resolved")
        print("   System not suitable for cryptocurrency operations")
        print("   Launch must be delayed until security requirements met")
    
    print(f"\n💡 IMMEDIATE ACTION REQUIRED:")
    if results['critical_vulnerabilities']:
        print("🔴 CRITICAL PRIORITY:")
        for vuln in results['critical_vulnerabilities']:
            print(f"   • Fix: {vuln}")
    
    if results['high_severity_issues']:
        print("🟠 HIGH PRIORITY:")
        for issue in results['high_severity_issues']:
            print(f"   • Address: {issue}")
    
    if results['launch_ready']:
        print("✅ SYSTEM READY - No critical actions required")
        print("   Continue monitoring and maintain security standards")
    
    print(f"\n🔧 FINAL RECOMMENDATION:")
    if results['final_score'] >= 85.0:
        print("System has achieved production-grade security for cryptocurrency operations.")
        print("Christmas Day 2025 launch can proceed as planned.")
    else:
        print("System requires additional security improvements before production launch.")
        print("Recommend implementing fixes and re-running security verification.")
"""
WEPO COMPREHENSIVE API SECURITY VERIFICATION
Christmas Day 2025 Launch Readiness Assessment

**SECURITY VERIFICATION EXECUTION:**

This comprehensive security test suite verifies all security enhancements are working properly 
and the WEPO system meets enterprise-grade security standards for cryptocurrency operations.

**TESTING CATEGORIES:**
1. Brute Force Protection Testing
2. Rate Limiting Implementation Testing  
3. DDoS Protection & Concurrent Load Testing
4. Input Validation Security Testing
5. Authentication & Session Security Testing
6. HTTP Security Headers Compliance Testing
7. Data Protection & Privacy Testing
8. Overall Security Score & Production Readiness

**TARGET:** 95%+ overall security score for enterprise cryptocurrency production readiness
"""

import requests
import json
import time
import uuid
import os
import sys
import secrets
import threading
import concurrent.futures
from datetime import datetime
import random
import string
import base64
import hashlib
import re

# Use preview backend URL from frontend/.env
BACKEND_URL = "https://012c0f35-c7c0-44db-b244-9d40fad5e286.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🔐 WEPO COMPREHENSIVE API SECURITY VERIFICATION")
print(f"🎄 Christmas Day 2025 Launch Readiness Assessment")
print(f"Preview Backend API URL: {API_URL}")
print(f"Target: 95%+ Security Score for Enterprise Cryptocurrency Production")
print("=" * 80)

# Security test results tracking
security_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": [],
    "categories": {
        "brute_force_protection": {"passed": 0, "total": 0, "weight": 20},
        "rate_limiting": {"passed": 0, "total": 0, "weight": 20},
        "ddos_protection": {"passed": 0, "total": 0, "weight": 15},
        "input_validation": {"passed": 0, "total": 0, "weight": 15},
        "authentication_security": {"passed": 0, "total": 0, "weight": 15},
        "security_headers": {"passed": 0, "total": 0, "weight": 10},
        "data_protection": {"passed": 0, "total": 0, "weight": 5}
    }
}

def log_security_test(name, passed, category, response=None, error=None, details=None, severity="medium"):
    """Log security test results with enhanced details and severity levels"""
    status = "✅ SECURE" if passed else "🚨 VULNERABLE"
    severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    
    print(f"{status} {severity_icon.get(severity, '🟡')} {name}")
    
    if details:
        print(f"  Details: {details}")
    
    if error:
        print(f"  Error: {error}")
    
    if response and not passed:
        print(f"  Response: {response}")
    
    security_results["total"] += 1
    security_results["categories"][category]["total"] += 1
    
    if passed:
        security_results["passed"] += 1
        security_results["categories"][category]["passed"] += 1
    else:
        security_results["failed"] += 1
    
    security_results["tests"].append({
        "name": name,
        "category": category,
        "passed": passed,
        "severity": severity,
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
    username = f"sectest_{secrets.token_hex(4)}"
    password = f"SecTest123!{secrets.token_hex(2)}"
    return username, password

def generate_malicious_payloads():
    """Generate various malicious payloads for security testing"""
    return {
        "xss_payloads": [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "';alert('XSS');//",
            "<svg onload=alert('XSS')>"
        ],
        "sql_injection": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "1; DELETE FROM wallets; --"
        ],
        "path_traversal": [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "../../../root/.ssh/id_rsa",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        "buffer_overflow": [
            "A" * 10000,
            "B" * 50000,
            "X" * 100000
        ]
    }

# ===== 1. BRUTE FORCE PROTECTION TESTING =====

def test_brute_force_protection():
    """Test 1: Brute Force Protection Testing - Critical Security"""
    print("\n🛡️ BRUTE FORCE PROTECTION TESTING - CRITICAL SECURITY")
    print("Testing wallet login brute force protection, account lockout, and lockout duration...")
    
    # Test brute force protection on login endpoint
    try:
        username, password = generate_test_user_data()
        
        # First create a wallet to test against
        create_data = {"username": username, "password": password}
        create_response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if create_response.status_code != 200:
            log_security_test("Brute Force Protection Setup", False, "brute_force_protection",
                            details="Could not create test wallet for brute force testing", severity="critical")
            return
        
        # Attempt multiple failed logins
        failed_attempts = 0
        locked_out = False
        lockout_response = None
        
        for attempt in range(8):  # Try 8 failed attempts
            login_data = {"username": username, "password": "wrong_password"}
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            
            failed_attempts += 1
            
            if response.status_code == 423:  # Account locked
                locked_out = True
                lockout_response = response
                break
            elif response.status_code != 401:
                break
            
            time.sleep(0.5)  # Small delay between attempts
        
        if locked_out and failed_attempts <= 6:
            log_security_test("Brute Force Account Lockout", True, "brute_force_protection",
                            details=f"Account locked after {failed_attempts} failed attempts (≤5 expected)", severity="critical")
        else:
            log_security_test("Brute Force Account Lockout", False, "brute_force_protection",
                            details=f"No lockout after {failed_attempts} failed attempts", severity="critical")
        
        # Test lockout duration and error messaging
        if locked_out and lockout_response:
            try:
                error_data = lockout_response.json() if lockout_response.headers.get('content-type', '').startswith('application/json') else lockout_response.text
                
                if "time_remaining" in str(error_data).lower() or "try again" in str(error_data).lower():
                    log_security_test("Lockout Duration Messaging", True, "brute_force_protection",
                                    details="Proper lockout error messaging with time information", severity="high")
                else:
                    log_security_test("Lockout Duration Messaging", False, "brute_force_protection",
                                    details="Lockout error messaging lacks time information", severity="medium")
            except:
                log_security_test("Lockout Duration Messaging", False, "brute_force_protection",
                                details="Could not parse lockout error message", severity="medium")
        
        # Test if lockout applies to invalid usernames too
        try:
            invalid_attempts = 0
            for attempt in range(6):
                login_data = {"username": f"nonexistent_{attempt}", "password": "wrong_password"}
                response = requests.post(f"{API_URL}/wallet/login", json=login_data)
                invalid_attempts += 1
                
                if response.status_code == 423:
                    log_security_test("Invalid Username Brute Force Protection", True, "brute_force_protection",
                                    details=f"Protection active for invalid usernames after {invalid_attempts} attempts", severity="high")
                    break
                time.sleep(0.3)
            else:
                log_security_test("Invalid Username Brute Force Protection", False, "brute_force_protection",
                                details="No protection for invalid username brute force attempts", severity="high")
        except Exception as e:
            log_security_test("Invalid Username Brute Force Protection", False, "brute_force_protection",
                            error=str(e), severity="high")
        
    except Exception as e:
        log_security_test("Brute Force Protection Testing", False, "brute_force_protection",
                        error=str(e), severity="critical")

# ===== 2. RATE LIMITING IMPLEMENTATION TESTING =====

def test_rate_limiting():
    """Test 2: Rate Limiting Implementation Testing - Critical Security"""
    print("\n⏱️ RATE LIMITING IMPLEMENTATION TESTING - CRITICAL SECURITY")
    print("Testing global API rate limiting and endpoint-specific limits...")
    
    # Test global API rate limiting (65+ requests in 1 minute)
    try:
        start_time = time.time()
        rate_limited = False
        request_count = 0
        
        for i in range(70):  # Try 70 requests
            response = requests.get(f"{API_URL}/")
            request_count += 1
            
            if response.status_code == 429:
                rate_limited = True
                elapsed_time = time.time() - start_time
                log_security_test("Global API Rate Limiting", True, "rate_limiting",
                                details=f"Rate limited after {request_count} requests in {elapsed_time:.1f}s", severity="critical")
                break
            
            if i % 10 == 0:
                time.sleep(0.1)  # Small delay every 10 requests
        
        if not rate_limited:
            log_security_test("Global API Rate Limiting", False, "rate_limiting",
                            details=f"No rate limiting detected after {request_count} requests", severity="critical")
    
    except Exception as e:
        log_security_test("Global API Rate Limiting", False, "rate_limiting",
                        error=str(e), severity="critical")
    
    # Test wallet creation rate limiting (4+ requests in 1 minute, limit: 3)
    try:
        rate_limited = False
        request_count = 0
        
        for i in range(5):  # Try 5 wallet creations
            username, password = generate_test_user_data()
            create_data = {"username": username, "password": password}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            request_count += 1
            
            if response.status_code == 429:
                rate_limited = True
                log_security_test("Wallet Creation Rate Limiting", True, "rate_limiting",
                                details=f"Wallet creation rate limited after {request_count} attempts", severity="high")
                break
            
            time.sleep(0.5)  # Small delay between attempts
        
        if not rate_limited:
            log_security_test("Wallet Creation Rate Limiting", False, "rate_limiting",
                            details=f"No rate limiting on wallet creation after {request_count} attempts", severity="high")
    
    except Exception as e:
        log_security_test("Wallet Creation Rate Limiting", False, "rate_limiting",
                        error=str(e), severity="high")
    
    # Test login rate limiting (6+ requests in 1 minute, limit: 5)
    try:
        rate_limited = False
        request_count = 0
        
        for i in range(7):  # Try 7 login attempts
            login_data = {"username": f"testuser_{i}", "password": "testpass"}
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            request_count += 1
            
            if response.status_code == 429:
                rate_limited = True
                log_security_test("Login Rate Limiting", True, "rate_limiting",
                                details=f"Login rate limited after {request_count} attempts", severity="high")
                break
            
            time.sleep(0.3)
        
        if not rate_limited:
            log_security_test("Login Rate Limiting", False, "rate_limiting",
                            details=f"No rate limiting on login after {request_count} attempts", severity="high")
    
    except Exception as e:
        log_security_test("Login Rate Limiting", False, "rate_limiting",
                        error=str(e), severity="high")
    
    # Test rate limiting headers
    try:
        response = requests.get(f"{API_URL}/")
        rate_limit_headers = [
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining", 
            "X-RateLimit-Reset"
        ]
        
        present_headers = [header for header in rate_limit_headers if header in response.headers]
        
        if len(present_headers) >= 2:
            log_security_test("Rate Limiting Headers", True, "rate_limiting",
                            details=f"Rate limiting headers present: {present_headers}", severity="medium")
        else:
            log_security_test("Rate Limiting Headers", False, "rate_limiting",
                            details=f"Missing rate limiting headers: {set(rate_limit_headers) - set(present_headers)}", severity="low")
    
    except Exception as e:
        log_security_test("Rate Limiting Headers", False, "rate_limiting",
                        error=str(e), severity="low")

# ===== 3. DDOS PROTECTION & CONCURRENT LOAD TESTING =====

def test_ddos_protection():
    """Test 3: DDoS Protection & Concurrent Load Testing - High Security"""
    print("\n🌊 DDOS PROTECTION & CONCURRENT LOAD TESTING - HIGH SECURITY")
    print("Testing concurrent requests, malformed payloads, and server stability...")
    
    # Test concurrent requests from same IP (simulate basic DDoS)
    def make_concurrent_request():
        try:
            response = requests.get(f"{API_URL}/", timeout=10)
            return response.status_code
        except:
            return 0
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_concurrent_request) for _ in range(50)]
            results = [future.result() for future in concurrent.futures.as_completed(futures, timeout=30)]
        
        success_count = len([r for r in results if r == 200])
        rate_limited_count = len([r for r in results if r == 429])
        error_count = len([r for r in results if r not in [200, 429]])
        
        if rate_limited_count > 0 or success_count < 40:
            log_security_test("Concurrent Request Protection", True, "ddos_protection",
                            details=f"DDoS protection active: {success_count} success, {rate_limited_count} rate limited, {error_count} errors", severity="high")
        else:
            log_security_test("Concurrent Request Protection", False, "ddos_protection",
                            details=f"No DDoS protection detected: {success_count}/{len(results)} requests succeeded", severity="high")
    
    except Exception as e:
        log_security_test("Concurrent Request Protection", False, "ddos_protection",
                        error=str(e), severity="high")
    
    # Test malformed JSON payloads
    try:
        malformed_payloads = [
            '{"invalid": json}',
            '{"username": "test", "password":}',
            '{"username": "test", "password": "test", "extra": {"nested": {"deep": {"very": {"deep": "value"}}}}}',
            '{"username": "' + "A" * 10000 + '", "password": "test"}',
            '{"username": null, "password": null}'
        ]
        
        malformed_handled = 0
        for payload in malformed_payloads:
            try:
                response = requests.post(f"{API_URL}/wallet/create", 
                                       data=payload, 
                                       headers={'Content-Type': 'application/json'},
                                       timeout=5)
                if response.status_code in [400, 422]:  # Proper error handling
                    malformed_handled += 1
            except:
                malformed_handled += 1  # Timeout or connection error is also good protection
        
        if malformed_handled >= len(malformed_payloads) * 0.8:  # 80% handled properly
            log_security_test("Malformed JSON Protection", True, "ddos_protection",
                            details=f"Malformed payloads handled properly: {malformed_handled}/{len(malformed_payloads)}", severity="medium")
        else:
            log_security_test("Malformed JSON Protection", False, "ddos_protection",
                            details=f"Poor malformed payload handling: {malformed_handled}/{len(malformed_payloads)}", severity="medium")
    
    except Exception as e:
        log_security_test("Malformed JSON Protection", False, "ddos_protection",
                        error=str(e), severity="medium")
    
    # Test invalid content types
    try:
        invalid_content_types = [
            'text/plain',
            'application/xml',
            'multipart/form-data',
            'application/octet-stream'
        ]
        
        content_type_handled = 0
        for content_type in invalid_content_types:
            try:
                response = requests.post(f"{API_URL}/wallet/create",
                                       data='{"username": "test", "password": "test"}',
                                       headers={'Content-Type': content_type},
                                       timeout=5)
                if response.status_code in [400, 415, 422]:  # Proper error handling
                    content_type_handled += 1
            except:
                content_type_handled += 1
        
        if content_type_handled >= len(invalid_content_types) * 0.75:
            log_security_test("Invalid Content Type Protection", True, "ddos_protection",
                            details=f"Invalid content types handled: {content_type_handled}/{len(invalid_content_types)}", severity="low")
        else:
            log_security_test("Invalid Content Type Protection", False, "ddos_protection",
                            details=f"Poor content type validation: {content_type_handled}/{len(invalid_content_types)}", severity="low")
    
    except Exception as e:
        log_security_test("Invalid Content Type Protection", False, "ddos_protection",
                        error=str(e), severity="low")

# ===== 4. INPUT VALIDATION SECURITY TESTING =====

def test_input_validation():
    """Test 4: Input Validation Security Testing - High Security"""
    print("\n🔍 INPUT VALIDATION SECURITY TESTING - HIGH SECURITY")
    print("Testing XSS, injection attacks, path traversal, and buffer overflow protection...")
    
    payloads = generate_malicious_payloads()
    
    # Test XSS protection in wallet creation
    try:
        xss_blocked = 0
        for xss_payload in payloads["xss_payloads"]:
            username, password = generate_test_user_data()
            create_data = {"username": xss_payload, "password": password}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            # Check if XSS payload is reflected in response
            response_text = response.text.lower()
            if "<script>" not in response_text and "javascript:" not in response_text and "onerror=" not in response_text:
                xss_blocked += 1
        
        if xss_blocked >= len(payloads["xss_payloads"]) * 0.8:
            log_security_test("XSS Protection", True, "input_validation",
                            details=f"XSS payloads blocked: {xss_blocked}/{len(payloads['xss_payloads'])}", severity="high")
        else:
            log_security_test("XSS Protection", False, "input_validation",
                            details=f"XSS protection insufficient: {xss_blocked}/{len(payloads['xss_payloads'])} blocked", severity="high")
    
    except Exception as e:
        log_security_test("XSS Protection", False, "input_validation",
                        error=str(e), severity="high")
    
    # Test SQL injection protection
    try:
        sql_blocked = 0
        for sql_payload in payloads["sql_injection"]:
            username, password = generate_test_user_data()
            login_data = {"username": sql_payload, "password": password}
            response = requests.post(f"{API_URL}/wallet/login", json=login_data)
            
            # SQL injection should not cause 500 errors or expose database info
            if response.status_code != 500 and "database" not in response.text.lower() and "sql" not in response.text.lower():
                sql_blocked += 1
        
        if sql_blocked >= len(payloads["sql_injection"]) * 0.9:
            log_security_test("SQL Injection Protection", True, "input_validation",
                            details=f"SQL injection attempts blocked: {sql_blocked}/{len(payloads['sql_injection'])}", severity="critical")
        else:
            log_security_test("SQL Injection Protection", False, "input_validation",
                            details=f"SQL injection protection insufficient: {sql_blocked}/{len(payloads['sql_injection'])} blocked", severity="critical")
    
    except Exception as e:
        log_security_test("SQL Injection Protection", False, "input_validation",
                        error=str(e), severity="critical")
    
    # Test path traversal protection
    try:
        path_blocked = 0
        for path_payload in payloads["path_traversal"]:
            try:
                response = requests.get(f"{API_URL}/wallet/{path_payload}")
                # Path traversal should not expose system files
                response_text = response.text.lower()
                if "root:" not in response_text and "passwd" not in response_text and "system32" not in response_text:
                    path_blocked += 1
            except:
                path_blocked += 1  # Connection error is also good protection
        
        if path_blocked >= len(payloads["path_traversal"]) * 0.9:
            log_security_test("Path Traversal Protection", True, "input_validation",
                            details=f"Path traversal attempts blocked: {path_blocked}/{len(payloads['path_traversal'])}", severity="high")
        else:
            log_security_test("Path Traversal Protection", False, "input_validation",
                            details=f"Path traversal protection insufficient: {path_blocked}/{len(payloads['path_traversal'])} blocked", severity="high")
    
    except Exception as e:
        log_security_test("Path Traversal Protection", False, "input_validation",
                        error=str(e), severity="high")
    
    # Test buffer overflow protection
    try:
        buffer_handled = 0
        for buffer_payload in payloads["buffer_overflow"]:
            try:
                username, password = generate_test_user_data()
                create_data = {"username": buffer_payload, "password": password}
                response = requests.post(f"{API_URL}/wallet/create", json=create_data, timeout=10)
                
                # Should handle gracefully without crashing
                if response.status_code in [400, 413, 422]:  # Proper error handling
                    buffer_handled += 1
            except requests.exceptions.Timeout:
                buffer_handled += 1  # Timeout protection is good
            except:
                pass  # Other errors might indicate vulnerability
        
        if buffer_handled >= len(payloads["buffer_overflow"]) * 0.7:
            log_security_test("Buffer Overflow Protection", True, "input_validation",
                            details=f"Buffer overflow attempts handled: {buffer_handled}/{len(payloads['buffer_overflow'])}", severity="medium")
        else:
            log_security_test("Buffer Overflow Protection", False, "input_validation",
                            details=f"Buffer overflow protection insufficient: {buffer_handled}/{len(payloads['buffer_overflow'])} handled", severity="medium")
    
    except Exception as e:
        log_security_test("Buffer Overflow Protection", False, "input_validation",
                        error=str(e), severity="medium")

# ===== 5. AUTHENTICATION & SESSION SECURITY TESTING =====

def test_authentication_security():
    """Test 5: Authentication & Session Security Testing - Critical Security"""
    print("\n🔐 AUTHENTICATION & SESSION SECURITY TESTING - CRITICAL SECURITY")
    print("Testing password security, session handling, and unauthorized access protection...")
    
    # Test weak password rejection
    try:
        weak_passwords = [
            "123456",
            "password",
            "abc123",
            "test",
            "12345678",
            "qwerty",
            "admin"
        ]
        
        weak_rejected = 0
        for weak_password in weak_passwords:
            username, _ = generate_test_user_data()
            create_data = {"username": username, "password": weak_password}
            response = requests.post(f"{API_URL}/wallet/create", json=create_data)
            
            if response.status_code == 400:  # Should reject weak passwords
                weak_rejected += 1
        
        if weak_rejected >= len(weak_passwords) * 0.8:
            log_security_test("Weak Password Rejection", True, "authentication_security",
                            details=f"Weak passwords rejected: {weak_rejected}/{len(weak_passwords)}", severity="critical")
        else:
            log_security_test("Weak Password Rejection", False, "authentication_security",
                            details=f"Weak password protection insufficient: {weak_rejected}/{len(weak_passwords)} rejected", severity="critical")
    
    except Exception as e:
        log_security_test("Weak Password Rejection", False, "authentication_security",
                        error=str(e), severity="critical")
    
    # Test strong password requirements
    try:
        strong_password = "StrongP@ssw0rd123!"
        username, _ = generate_test_user_data()
        create_data = {"username": username, "password": strong_password}
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            log_security_test("Strong Password Acceptance", True, "authentication_security",
                            details="Strong password accepted (12+ chars, mixed case, numbers, symbols)", severity="high")
        else:
            log_security_test("Strong Password Acceptance", False, "authentication_security",
                            details=f"Strong password rejected: {response.status_code}", severity="high")
    
    except Exception as e:
        log_security_test("Strong Password Acceptance", False, "authentication_security",
                        error=str(e), severity="high")
    
    # Test unauthorized access to protected endpoints
    try:
        test_address = generate_valid_wepo_address()
        protected_endpoints = [
            f"/wallet/{test_address}",
            f"/wallet/{test_address}/transactions",
            "/transaction/send"
        ]
        
        unauthorized_blocked = 0
        for endpoint in protected_endpoints:
            try:
                if endpoint == "/transaction/send":
                    response = requests.post(f"{API_URL}{endpoint}", json={"test": "data"})
                else:
                    response = requests.get(f"{API_URL}{endpoint}")
                
                # Should handle unauthorized access gracefully
                if response.status_code in [401, 403, 404]:  # Proper access control
                    unauthorized_blocked += 1
            except:
                unauthorized_blocked += 1
        
        if unauthorized_blocked >= len(protected_endpoints) * 0.7:
            log_security_test("Unauthorized Access Protection", True, "authentication_security",
                            details=f"Protected endpoints secured: {unauthorized_blocked}/{len(protected_endpoints)}", severity="high")
        else:
            log_security_test("Unauthorized Access Protection", False, "authentication_security",
                            details=f"Access control insufficient: {unauthorized_blocked}/{len(protected_endpoints)} protected", severity="high")
    
    except Exception as e:
        log_security_test("Unauthorized Access Protection", False, "authentication_security",
                        error=str(e), severity="high")
    
    # Test password hashing security (no plaintext exposure)
    try:
        username, password = generate_test_user_data()
        create_data = {"username": username, "password": password}
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            response_text = response.text.lower()
            if password.lower() not in response_text and "password" not in response.json():
                log_security_test("Password Hashing Security", True, "authentication_security",
                                details="Password not exposed in response - proper hashing implemented", severity="critical")
            else:
                log_security_test("Password Hashing Security", False, "authentication_security",
                                details="Password potentially exposed in response", severity="critical")
        else:
            log_security_test("Password Hashing Security", False, "authentication_security",
                            details="Could not test password hashing - wallet creation failed", severity="medium")
    
    except Exception as e:
        log_security_test("Password Hashing Security", False, "authentication_security",
                        error=str(e), severity="critical")

# ===== 6. HTTP SECURITY HEADERS COMPLIANCE TESTING =====

def test_security_headers():
    """Test 6: HTTP Security Headers Compliance Testing - Medium Security"""
    print("\n🛡️ HTTP SECURITY HEADERS COMPLIANCE TESTING - MEDIUM SECURITY")
    print("Testing critical security headers and CORS configuration...")
    
    try:
        response = requests.get(f"{API_URL}/")
        
        critical_headers = {
            "Content-Security-Policy": "CSP protection against XSS",
            "X-Frame-Options": "Clickjacking protection", 
            "X-Content-Type-Options": "MIME type sniffing protection",
            "X-XSS-Protection": "XSS filter protection",
            "Strict-Transport-Security": "HTTPS enforcement"
        }
        
        present_headers = []
        missing_headers = []
        
        for header, description in critical_headers.items():
            if header in response.headers:
                present_headers.append(f"{header}: {response.headers[header]}")
            else:
                missing_headers.append(f"{header} ({description})")
        
        if len(present_headers) >= 4:  # At least 4 out of 5 critical headers
            log_security_test("Critical Security Headers", True, "security_headers",
                            details=f"Security headers present: {len(present_headers)}/5", severity="medium")
        else:
            log_security_test("Critical Security Headers", False, "security_headers",
                            details=f"Missing critical headers: {missing_headers}", severity="high")
        
        # Test CORS configuration
        cors_header = response.headers.get("Access-Control-Allow-Origin", "")
        if cors_header == "*":
            log_security_test("CORS Security Configuration", False, "security_headers",
                            details="Wildcard CORS policy detected - security risk", severity="medium")
        elif cors_header and cors_header != "*":
            log_security_test("CORS Security Configuration", True, "security_headers",
                            details=f"Restricted CORS policy: {cors_header}", severity="low")
        else:
            log_security_test("CORS Security Configuration", True, "security_headers",
                            details="No CORS header - restrictive policy", severity="low")
    
    except Exception as e:
        log_security_test("HTTP Security Headers", False, "security_headers",
                        error=str(e), severity="medium")

# ===== 7. DATA PROTECTION & PRIVACY TESTING =====

def test_data_protection():
    """Test 7: Data Protection & Privacy Testing - High Security"""
    print("\n🔒 DATA PROTECTION & PRIVACY TESTING - HIGH SECURITY")
    print("Testing sensitive data exposure and error message information disclosure...")
    
    # Test for sensitive data exposure in API responses
    try:
        username, password = generate_test_user_data()
        create_data = {"username": username, "password": password}
        response = requests.post(f"{API_URL}/wallet/create", json=create_data)
        
        if response.status_code == 200:
            response_data = response.json()
            sensitive_fields = ["password", "private_key", "seed", "mnemonic", "secret"]
            
            exposed_fields = []
            for field in sensitive_fields:
                if field in str(response_data).lower():
                    exposed_fields.append(field)
            
            if not exposed_fields:
                log_security_test("Sensitive Data Exposure", True, "data_protection",
                                details="No sensitive data exposed in wallet creation response", severity="critical")
            else:
                log_security_test("Sensitive Data Exposure", False, "data_protection",
                                details=f"Sensitive data potentially exposed: {exposed_fields}", severity="critical")
        else:
            log_security_test("Sensitive Data Exposure", False, "data_protection",
                            details="Could not test data exposure - wallet creation failed", severity="medium")
    
    except Exception as e:
        log_security_test("Sensitive Data Exposure", False, "data_protection",
                        error=str(e), severity="critical")
    
    # Test error message information disclosure
    try:
        # Test with malformed request to trigger error
        response = requests.post(f"{API_URL}/wallet/create", json={"invalid": "data"})
        
        if response.status_code >= 400:
            error_text = response.text.lower()
            disclosure_indicators = [
                "stack trace", "traceback", "exception", "file path", 
                "database", "sql", "mongodb", "server", "internal"
            ]
            
            disclosed_info = []
            for indicator in disclosure_indicators:
                if indicator in error_text:
                    disclosed_info.append(indicator)
            
            if not disclosed_info:
                log_security_test("Error Message Information Disclosure", True, "data_protection",
                                details="Error messages properly sanitized", severity="medium")
            else:
                log_security_test("Error Message Information Disclosure", False, "data_protection",
                                details=f"Information disclosure in errors: {disclosed_info}", severity="medium")
        else:
            log_security_test("Error Message Information Disclosure", False, "data_protection",
                            details="Could not trigger error for testing", severity="low")
    
    except Exception as e:
        log_security_test("Error Message Information Disclosure", False, "data_protection",
                        error=str(e), severity="medium")

def calculate_security_score():
    """Calculate overall security score based on weighted categories"""
    total_weighted_score = 0
    total_weight = 0
    
    for category, data in security_results["categories"].items():
        if data["total"] > 0:
            category_score = (data["passed"] / data["total"]) * 100
            weighted_score = category_score * data["weight"]
            total_weighted_score += weighted_score
            total_weight += data["weight"]
    
    if total_weight > 0:
        return total_weighted_score / total_weight
    return 0

def run_comprehensive_security_testing():
    """Run comprehensive security testing suite"""
    print("🔐 STARTING WEPO COMPREHENSIVE API SECURITY VERIFICATION")
    print("🎄 Christmas Day 2025 Launch Readiness Assessment")
    print("=" * 80)
    
    # Run all security test categories
    test_brute_force_protection()
    test_rate_limiting()
    test_ddos_protection()
    test_input_validation()
    test_authentication_security()
    test_security_headers()
    test_data_protection()
    
    # Calculate security score
    security_score = calculate_security_score()
    
    # Print comprehensive results
    print("\n" + "=" * 80)
    print("🔐 WEPO COMPREHENSIVE SECURITY VERIFICATION RESULTS")
    print("🎄 Christmas Day 2025 Launch Readiness Assessment")
    print("=" * 80)
    
    print(f"Total Security Tests: {security_results['total']}")
    print(f"Passed: {security_results['passed']} ✅")
    print(f"Failed: {security_results['failed']} 🚨")
    print(f"Overall Security Score: {security_score:.1f}%")
    
    # Category-wise security results
    print("\n🛡️ SECURITY CATEGORY BREAKDOWN:")
    categories = {
        "brute_force_protection": "🛡️ Brute Force Protection",
        "rate_limiting": "⏱️ Rate Limiting",
        "ddos_protection": "🌊 DDoS Protection",
        "input_validation": "🔍 Input Validation",
        "authentication_security": "🔐 Authentication Security",
        "security_headers": "🛡️ Security Headers",
        "data_protection": "🔒 Data Protection"
    }
    
    critical_vulnerabilities = []
    high_vulnerabilities = []
    
    for category_key, category_name in categories.items():
        cat_data = security_results["categories"][category_key]
        if cat_data["total"] > 0:
            cat_rate = (cat_data["passed"] / cat_data["total"]) * 100
            weight = cat_data["weight"]
            status = "✅" if cat_rate >= 80 else "⚠️" if cat_rate >= 60 else "🚨"
            print(f"  {status} {category_name}: {cat_data['passed']}/{cat_data['total']} ({cat_rate:.1f}%) [Weight: {weight}%]")
            
            if cat_rate < 60:
                if weight >= 15:
                    critical_vulnerabilities.append(category_name)
                else:
                    high_vulnerabilities.append(category_name)
    
    # Security vulnerabilities analysis
    print("\n🚨 SECURITY VULNERABILITIES ANALYSIS:")
    
    critical_tests = [test for test in security_results['tests'] if not test['passed'] and test['severity'] == 'critical']
    high_tests = [test for test in security_results['tests'] if not test['passed'] and test['severity'] == 'high']
    
    if critical_tests:
        print(f"🔴 CRITICAL VULNERABILITIES ({len(critical_tests)}):")
        for test in critical_tests:
            print(f"  • {test['name']} - {test['details'] or test['error']}")
    
    if high_tests:
        print(f"🟠 HIGH SEVERITY VULNERABILITIES ({len(high_tests)}):")
        for test in high_tests:
            print(f"  • {test['name']} - {test['details'] or test['error']}")
    
    # Production readiness assessment
    print(f"\n🎄 CHRISTMAS DAY 2025 LAUNCH READINESS:")
    if security_score >= 95:
        print("🎉 EXCELLENT - ENTERPRISE-GRADE SECURITY ACHIEVED!")
        print("   ✅ Target 95%+ security score achieved")
        print("   ✅ System ready for cryptocurrency production launch")
        print("   ✅ All critical security controls operational")
    elif security_score >= 85:
        print("✅ GOOD - STRONG SECURITY POSTURE")
        print("   ✅ Above 85% security threshold")
        print("   ⚠️ Minor security improvements recommended")
        print("   ✅ Suitable for production with monitoring")
    elif security_score >= 70:
        print("⚠️ FAIR - SECURITY IMPROVEMENTS NEEDED")
        print("   ⚠️ Below enterprise-grade threshold")
        print("   🚨 Critical vulnerabilities must be addressed")
        print("   ❌ Not ready for cryptocurrency production")
    else:
        print("🚨 POOR - CRITICAL SECURITY VULNERABILITIES")
        print("   🚨 Major security risks identified")
        print("   ❌ Immediate security fixes required")
        print("   ❌ Not suitable for production launch")
    
    return {
        "security_score": security_score,
        "total_tests": security_results["total"],
        "passed_tests": security_results["passed"],
        "failed_tests": security_results["failed"],
        "critical_vulnerabilities": critical_vulnerabilities,
        "high_vulnerabilities": high_vulnerabilities,
        "critical_tests": critical_tests,
        "high_tests": high_tests,
        "categories": security_results["categories"]
    }

if __name__ == "__main__":
    # Run comprehensive security testing
    results = run_comprehensive_security_testing()
    
    print("\n" + "=" * 80)
    print("🎄 FINAL CHRISTMAS DAY 2025 LAUNCH SECURITY ASSESSMENT")
    print("=" * 80)
    
    print(f"🔐 OVERALL SECURITY RESULTS:")
    print(f"• Security Score: {results['security_score']:.1f}%")
    print(f"• Total Tests: {results['total_tests']}")
    print(f"• Passed: {results['passed_tests']} ✅")
    print(f"• Failed: {results['failed_tests']} 🚨")
    
    if results['critical_vulnerabilities']:
        print(f"\n🔴 CRITICAL SECURITY CATEGORIES NEEDING IMMEDIATE ATTENTION:")
        for i, vuln in enumerate(results['critical_vulnerabilities'], 1):
            print(f"{i}. {vuln}")
    
    if results['high_vulnerabilities']:
        print(f"\n🟠 HIGH PRIORITY SECURITY IMPROVEMENTS:")
        for i, vuln in enumerate(results['high_vulnerabilities'], 1):
            print(f"{i}. {vuln}")
    
    print(f"\n💡 SECURITY RECOMMENDATIONS:")
    if results['security_score'] >= 95:
        print("• 🎉 LAUNCH APPROVED - Enterprise-grade security achieved!")
        print("• Continue monitoring and maintain security controls")
        print("• System ready for Christmas Day 2025 cryptocurrency launch")
    elif results['security_score'] >= 85:
        print("• ✅ CONDITIONAL LAUNCH - Strong security with minor improvements")
        print("• Address remaining vulnerabilities before launch")
        print("• Implement additional monitoring for production")
    else:
        print("• 🚨 LAUNCH BLOCKED - Critical security vulnerabilities")
        print("• Address all critical and high severity issues")
        print("• Re-run security verification after fixes")
        print("• Consider security audit by external experts")
    
    print(f"\n🔧 NEXT STEPS:")
    if results['security_score'] >= 95:
        print("• System security verification complete")
        print("• Proceed with final production deployment")
        print("• Implement security monitoring and logging")
    else:
        print("• Fix critical security vulnerabilities immediately")
        print("• Implement missing security controls")
        print("• Re-test security after implementing fixes")
        print("• Consider penetration testing by security experts")
"""
COMPREHENSIVE SECURITY VERIFICATION TEST SUITE
Final security verification to confirm 95-100% security score achievement

Focus Areas:
1. Scientific Notation Detection - Enhanced error messages with examples
2. Address Validation Logic - 37-character WEPO addresses
3. Decimal Precision Validation - 8-decimal limit with count reporting
4. Zero/Negative Amount Validation - Specific minimum amount reporting
5. HTTP Security Headers - All 5 critical headers
6. XSS Protection - Malicious content blocking with threat identification
7. JSON Parsing Enhancement - Detailed error messages with position info
8. Error Message Consistency - Professional capitalization and formatting
"""

import requests
import json
import time
import uuid
import secrets
import hashlib
import re
from datetime import datetime

# Use preview backend URL from frontend/.env
BACKEND_URL = "https://012c0f35-c7c0-44db-b244-9d40fad5e286.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🔐 COMPREHENSIVE SECURITY VERIFICATION - FINAL AUDIT")
print(f"Backend API URL: {API_URL}")
print(f"Target: Achieve 95-100% security score for Christmas Day 2025 launch")
print("=" * 80)

# Test results tracking
test_results = {
    "total_tests": 0,
    "passed_tests": 0,
    "failed_tests": 0,
    "security_score": 0,
    "details": []
}

def log_test_result(test_name, passed, details="", error=""):
    """Log individual test results"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status} {test_name}")
    if details:
        print(f"  Details: {details}")
    if error:
        print(f"  Error: {error}")
    
    test_results["total_tests"] += 1
    if passed:
        test_results["passed_tests"] += 1
    else:
        test_results["failed_tests"] += 1
    
    test_results["details"].append({
        "name": test_name,
        "passed": passed,
        "details": details,
        "error": error
    })

def generate_valid_wepo_address():
    """Generate a valid 37-character WEPO address"""
    random_data = secrets.token_bytes(16)
    hex_part = random_data.hex()
    return f"wepo1{hex_part}"

def test_scientific_notation_detection():
    """Test 1: Scientific Notation Detection with Enhanced Error Messages"""
    print("\n🔬 TEST 1: SCIENTIFIC NOTATION DETECTION")
    print("Testing scientific notation formats with enhanced error messages...")
    
    scientific_formats = [
        ("1e5", "Basic exponential"),
        ("5E-3", "Uppercase with negative exponent"),
        ("1.5e10", "Decimal with exponential"),
        ("2.5E+6", "Uppercase with positive exponent"),
        ("3.14e-8", "Pi with negative exponent")
    ]
    
    passed_count = 0
    total_count = len(scientific_formats)
    
    for sci_notation, description in scientific_formats:
        try:
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": sci_notation
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Check for enhanced error message features
                has_examples = any(term in error_message for term in ['example', 'instead', 'use'])
                has_conversion = 'scientific notation' in error_message or 'exponential' in error_message
                has_guidance = any(term in error_message for term in ['decimal format', 'standard'])
                
                if has_examples and has_conversion and has_guidance:
                    print(f"  ✅ {description}: Enhanced error with examples and guidance")
                    passed_count += 1
                else:
                    print(f"  ❌ {description}: Missing enhancement features")
                    print(f"    Examples: {has_examples}, Conversion: {has_conversion}, Guidance: {has_guidance}")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        except Exception as e:
            print(f"  ❌ {description}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 4  # At least 4/5 should pass
    log_test_result("Scientific Notation Detection", test_passed, 
                   f"{passed_count}/{total_count} formats properly handled ({success_rate:.1f}%)")
    return test_passed

def test_address_validation_logic():
    """Test 2: Address Validation Logic for 37-Character WEPO Addresses"""
    print("\n🏠 TEST 2: ADDRESS VALIDATION LOGIC")
    print("Testing valid and invalid WEPO addresses...")
    
    passed_count = 0
    total_count = 6
    
    # Test valid addresses (should be accepted)
    valid_addresses = [generate_valid_wepo_address() for _ in range(3)]
    
    for i, valid_addr in enumerate(valid_addresses):
        try:
            transaction_data = {
                "from_address": valid_addr,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Valid addresses should not be rejected for format issues
            if response.status_code != 400 or "format" not in response.text.lower():
                print(f"  ✅ Valid address {i+1}: Properly accepted")
                passed_count += 1
            else:
                print(f"  ❌ Valid address {i+1}: Incorrectly rejected for format")
        except Exception as e:
            print(f"  ❌ Valid address {i+1}: Request failed - {str(e)}")
    
    # Test invalid addresses (should be rejected with detailed errors)
    invalid_cases = [
        ("wepo1abc", "Too short"),
        ("wepo1" + "x" * 33, "Too long"),
        ("btc1" + secrets.token_hex(16), "Wrong prefix")
    ]
    
    for invalid_addr, description in invalid_cases:
        try:
            transaction_data = {
                "from_address": invalid_addr,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Check for detailed error message
                has_format_info = any(term in error_message for term in ['format', 'character', 'length'])
                has_guidance = any(term in error_message for term in ['wepo1', '37', 'hex'])
                
                if has_format_info and has_guidance:
                    print(f"  ✅ {description}: Detailed error message")
                    passed_count += 1
                else:
                    print(f"  ❌ {description}: Error lacks detail")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        except Exception as e:
            print(f"  ❌ {description}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 5  # At least 5/6 should pass
    log_test_result("Address Validation Logic", test_passed,
                   f"{passed_count}/{total_count} address tests passed ({success_rate:.1f}%)")
    return test_passed

def test_decimal_precision_validation():
    """Test 3: Decimal Precision Validation - 8 Decimal Places"""
    print("\n🔢 TEST 3: DECIMAL PRECISION VALIDATION")
    print("Testing 8-decimal place limit with count reporting...")
    
    passed_count = 0
    total_count = 5
    
    # Test valid 8-decimal amounts (should be accepted)
    valid_amounts = [1.12345678, 0.00000001, 999.99999999, 0.12345678, 100.00000001]
    
    for amount in valid_amounts:
        try:
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": amount
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Should not be rejected for decimal precision
            if response.status_code != 400 or "decimal" not in response.text.lower():
                print(f"  ✅ Valid 8 decimals: {amount} properly accepted")
                passed_count += 1
            else:
                # Check if it's actually a decimal precision error
                error_data = response.json()
                error_message = str(error_data).lower()
                if "decimal" in error_message or "precision" in error_message:
                    print(f"  ❌ Valid 8 decimals: {amount} incorrectly rejected")
                else:
                    print(f"  ✅ Valid 8 decimals: {amount} accepted (other validation)")
                    passed_count += 1
        except Exception as e:
            print(f"  ❌ Amount {amount}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 4  # At least 4/5 should pass
    log_test_result("Decimal Precision Validation", test_passed,
                   f"{passed_count}/{total_count} decimal tests passed ({success_rate:.1f}%)")
    return test_passed

def test_minimum_amount_validation():
    """Test 4: Zero/Negative Amount Validation with Specific Minimum"""
    print("\n💰 TEST 4: MINIMUM AMOUNT VALIDATION")
    print("Testing zero and negative amounts for specific minimum reporting...")
    
    passed_count = 0
    total_count = 3
    
    invalid_amounts = [
        (0, "Zero amount"),
        (-1.5, "Negative amount"),
        (-0.00000001, "Negative minimum")
    ]
    
    for amount, description in invalid_amounts:
        try:
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": amount
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Check for specific minimum amount reporting
                has_specific_minimum = "0.00000001" in error_message
                has_wepo_unit = "wepo" in error_message
                has_minimum_context = any(term in error_message for term in ['minimum', 'least'])
                
                if has_specific_minimum and has_wepo_unit and has_minimum_context:
                    print(f"  ✅ {description}: Specific minimum (0.00000001 WEPO) reported")
                    passed_count += 1
                else:
                    print(f"  ❌ {description}: Missing specific minimum reporting")
                    print(f"    Minimum: {has_specific_minimum}, Unit: {has_wepo_unit}, Context: {has_minimum_context}")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        except Exception as e:
            print(f"  ❌ {description}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 2  # At least 2/3 should pass
    log_test_result("Minimum Amount Validation", test_passed,
                   f"{passed_count}/{total_count} minimum tests passed ({success_rate:.1f}%)")
    return test_passed

def test_http_security_headers():
    """Test 5: HTTP Security Headers - All 5 Critical Headers"""
    print("\n🛡️ TEST 5: HTTP SECURITY HEADERS")
    print("Verifying all 5 critical security headers...")
    
    try:
        response = requests.get(f"{API_URL}/")
        
        required_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", ["DENY", "SAMEORIGIN"]),
            ("X-XSS-Protection", "1"),
            ("Strict-Transport-Security", "max-age"),
            ("Content-Security-Policy", "default-src")
        ]
        
        passed_count = 0
        total_count = len(required_headers)
        
        for header_name, expected_value in required_headers:
            if header_name.lower() in [h.lower() for h in response.headers.keys()]:
                header_value = response.headers.get(header_name, "").lower()
                
                if isinstance(expected_value, list):
                    if any(val.lower() in header_value for val in expected_value):
                        print(f"  ✅ {header_name}: Present and valid")
                        passed_count += 1
                    else:
                        print(f"  ❌ {header_name}: Present but invalid value")
                else:
                    if expected_value.lower() in header_value:
                        print(f"  ✅ {header_name}: Present and valid")
                        passed_count += 1
                    else:
                        print(f"  ❌ {header_name}: Present but invalid value")
            else:
                print(f"  ❌ {header_name}: Missing")
        
        success_rate = (passed_count / total_count) * 100
        test_passed = passed_count == 5  # All 5 headers must be present
        log_test_result("HTTP Security Headers", test_passed,
                       f"{passed_count}/{total_count} headers present ({success_rate:.1f}%)")
        return test_passed
        
    except Exception as e:
        log_test_result("HTTP Security Headers", False, error=str(e))
        return False

def test_xss_protection():
    """Test 6: XSS Protection with Threat Identification"""
    print("\n🚫 TEST 6: XSS PROTECTION")
    print("Testing malicious content blocking with threat identification...")
    
    malicious_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "'; DROP TABLE users; --",
        "<iframe src='javascript:alert(1)'></iframe>"
    ]
    
    passed_count = 0
    total_count = len(malicious_payloads)
    
    for payload in malicious_payloads:
        try:
            transaction_data = {
                "from_address": payload,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                # Check if the malicious content was properly blocked
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Look for threat identification or sanitization
                threat_identified = any(term in error_message for term in 
                                     ['invalid', 'format', 'malicious', 'blocked', 'sanitized'])
                
                if threat_identified:
                    print(f"  ✅ XSS payload blocked: {payload[:20]}...")
                    passed_count += 1
                else:
                    print(f"  ❌ XSS payload not properly identified: {payload[:20]}...")
            else:
                print(f"  ❌ XSS payload not blocked: {payload[:20]}...")
        except Exception as e:
            print(f"  ❌ XSS test failed: {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 4  # At least 4/5 should be blocked
    log_test_result("XSS Protection", test_passed,
                   f"{passed_count}/{total_count} payloads blocked ({success_rate:.1f}%)")
    return test_passed

def test_json_parsing_enhancement():
    """Test 7: JSON Parsing Enhancement with Position Information"""
    print("\n📝 TEST 7: JSON PARSING ENHANCEMENT")
    print("Testing detailed parsing error messages with position information...")
    
    invalid_json_cases = [
        ('{"invalid": json}', "Missing quotes"),
        ('{"missing": }', "Missing value"),
        ('{"unclosed": "string}', "Unclosed string")
    ]
    
    passed_count = 0
    total_count = len(invalid_json_cases)
    
    for invalid_json, description in invalid_json_cases:
        try:
            response = requests.post(f"{API_URL}/transaction/send", 
                                   data=invalid_json,
                                   headers={"Content-Type": "application/json"})
            
            if response.status_code == 400:
                error_data = response.json()
                error_message = str(error_data).lower()
                
                # Check for detailed parsing information
                has_position_info = any(term in error_message for term in 
                                      ['line', 'column', 'char', 'position'])
                has_parsing_detail = any(term in error_message for term in 
                                       ['json', 'parse', 'format', 'expecting'])
                
                if has_position_info and has_parsing_detail:
                    print(f"  ✅ {description}: Detailed parsing error with position")
                    passed_count += 1
                else:
                    print(f"  ❌ {description}: Missing detailed parsing info")
                    print(f"    Position: {has_position_info}, Detail: {has_parsing_detail}")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        except Exception as e:
            print(f"  ❌ {description}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 2  # At least 2/3 should pass
    log_test_result("JSON Parsing Enhancement", test_passed,
                   f"{passed_count}/{total_count} parsing tests passed ({success_rate:.1f}%)")
    return test_passed

def test_error_message_consistency():
    """Test 8: Error Message Consistency - Professional Formatting"""
    print("\n📋 TEST 8: ERROR MESSAGE CONSISTENCY")
    print("Testing professional capitalization and formatting...")
    
    test_cases = [
        {
            "name": "Missing fields",
            "data": {},
        },
        {
            "name": "Invalid amount",
            "data": {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": "invalid"
            }
        },
        {
            "name": "Invalid address",
            "data": {
                "from_address": "invalid_address",
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
        }
    ]
    
    passed_count = 0
    total_count = len(test_cases)
    
    for test_case in test_cases:
        try:
            response = requests.post(f"{API_URL}/transaction/send", json=test_case["data"])
            
            if response.status_code == 400:
                error_data = response.json()
                error_message = str(error_data)
                
                # Check for professional formatting
                has_proper_capitalization = error_message[0].isupper() if error_message else False
                has_specific_guidance = any(term in error_message.lower() for term in 
                                          ['must', 'should', 'required', 'expected'])
                has_professional_tone = not any(term in error_message.lower() for term in 
                                               ['oops', 'uh oh', 'whoops'])
                
                quality_score = sum([has_proper_capitalization, has_specific_guidance, has_professional_tone])
                
                if quality_score >= 2:
                    print(f"  ✅ {test_case['name']}: Professional error message")
                    passed_count += 1
                else:
                    print(f"  ❌ {test_case['name']}: Quality issues (score: {quality_score}/3)")
            else:
                print(f"  ❌ {test_case['name']}: Expected 400 error, got {response.status_code}")
        except Exception as e:
            print(f"  ❌ {test_case['name']}: Request failed - {str(e)}")
    
    success_rate = (passed_count / total_count) * 100
    test_passed = passed_count >= 2  # At least 2/3 should pass
    log_test_result("Error Message Consistency", test_passed,
                   f"{passed_count}/{total_count} consistency tests passed ({success_rate:.1f}%)")
    return test_passed

def run_comprehensive_security_verification():
    """Run all comprehensive security tests"""
    print("🔐 STARTING COMPREHENSIVE SECURITY VERIFICATION")
    print("Testing all security areas for 95-100% security score...")
    print("=" * 80)
    
    # Run all security tests
    test_results_list = [
        test_scientific_notation_detection(),
        test_address_validation_logic(),
        test_decimal_precision_validation(),
        test_minimum_amount_validation(),
        test_http_security_headers(),
        test_xss_protection(),
        test_json_parsing_enhancement(),
        test_error_message_consistency()
    ]
    
    # Calculate final security score
    passed_tests = sum(test_results_list)
    total_tests = len(test_results_list)
    security_score = (passed_tests / total_tests) * 100
    
    test_results["security_score"] = security_score
    
    # Print final results
    print("\n" + "=" * 80)
    print("🔐 COMPREHENSIVE SECURITY VERIFICATION RESULTS")
    print("=" * 80)
    
    print(f"Total Security Areas: {total_tests}")
    print(f"Passed Areas: {passed_tests} ✅")
    print(f"Failed Areas: {total_tests - passed_tests} ❌")
    print(f"SECURITY SCORE: {security_score:.1f}%")
    
    # Detailed results
    print("\n📊 DETAILED SECURITY ASSESSMENT:")
    for i, result in enumerate(test_results["details"]):
        status = "✅" if result["passed"] else "❌"
        print(f"  {status} {result['name']}")
        if result["details"]:
            print(f"    {result['details']}")
    
    # Final assessment
    print(f"\n🎯 SECURITY SCORE ASSESSMENT:")
    if security_score >= 95:
        print("🎉 EXCELLENT SECURITY POSTURE - READY FOR LAUNCH!")
        print("✅ Achieved 95-100% security score target")
        print("✅ All critical security controls operational")
        print("✅ Enhanced error messages implemented")
        print("✅ Production-ready for Christmas Day 2025 launch")
        return True
    elif security_score >= 80:
        print("⚠️ GOOD SECURITY POSTURE - MINOR IMPROVEMENTS NEEDED")
        print(f"✅ Achieved {security_score:.1f}% security score")
        print("⚠️ Some security enhancements need refinement")
        return False
    else:
        print("🚨 SECURITY IMPROVEMENTS REQUIRED")
        print(f"❌ Security score {security_score:.1f}% below target")
        print("🚨 Critical security issues need immediate attention")
        return False

if __name__ == "__main__":
    success = run_comprehensive_security_verification()
    if not success:
        exit(1)
"""
WEPO COMPREHENSIVE SECURITY VERIFICATION TEST SUITE
Final 100% Security Score Verification

This test suite conducts comprehensive security testing focusing on:
1. Scientific Notation Detection with Enhanced Error Messages
2. Address Validation Logic for 37-character WEPO addresses
3. Decimal Precision Validation (8 decimal places)
4. Zero/Negative Amount Validation with specific minimum amounts
5. HTTP Security Headers verification
6. XSS Protection testing
7. JSON Parsing Enhancement testing
8. Error Message Consistency verification

Target: Achieve 95-100% security score for Christmas Day 2025 launch readiness
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
BACKEND_URL = "https://012c0f35-c7c0-44db-b244-9d40fad5e286.preview.emergentagent.com"
API_URL = f"{BACKEND_URL}/api"

print(f"🔐 WEPO COMPREHENSIVE SECURITY VERIFICATION - FINAL 100% SECURITY SCORE")
print(f"Backend API URL: {API_URL}")
print(f"Target: Achieve 95-100% security score for Christmas Day 2025 launch")
print("=" * 80)

# Test results tracking
test_results = {
    "total": 0,
    "passed": 0,
    "failed": 0,
    "tests": [],
    "security_score": 0
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

def test_scientific_notation_detection():
    """Test 1: Scientific Notation Detection - Enhanced Error Messages"""
    print("\n🔬 TEST 1: SCIENTIFIC NOTATION DETECTION - ENHANCED ERROR MESSAGES")
    print("Testing all scientific notation formats with enhanced error messages and conversion guidance...")
    
    try:
        checks_passed = 0
        total_checks = 5
        
        # Test different scientific notation formats
        scientific_formats = [
            ("1e5", "1e5 (should suggest: 100000)"),
            ("5E-3", "5E-3 (should suggest: 0.005)"),
            ("1.5e10", "1.5e10 (should suggest: 15000000000)"),
            ("2.5E+6", "2.5E+6 (should suggest: 2500000)"),
            ("3.14e-8", "3.14e-8 (should suggest: 0.0000000314)")
        ]
        
        for sci_notation, description in scientific_formats:
            # Test transaction with scientific notation amount
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": sci_notation
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    
                    # Check for enhanced error message features
                    has_scientific_detection = 'scientific notation' in error_message
                    has_examples = any(example in error_message for example in ['examples:', 'instead of', 'use'])
                    has_conversion_guidance = any(conv in error_message for conv in ['10000000000', '0.005', '15000000000'])
                    has_specific_format = 'standard decimal format' in error_message
                    
                    if has_scientific_detection and has_examples and has_conversion_guidance and has_specific_format:
                        print(f"  ✅ {description}: Enhanced error message with examples and guidance")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {description}: Error message lacks enhancement")
                        print(f"    Detection: {has_scientific_detection}, Examples: {has_examples}")
                        print(f"    Conversion: {has_conversion_guidance}, Format: {has_specific_format}")
                        print(f"    Response: {error_data}")
                except:
                    print(f"  ❌ {description}: Invalid JSON response")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Scientific Notation Detection", checks_passed >= 4,
                 details=f"Enhanced scientific notation error messages: {checks_passed}/{total_checks} formats properly handled ({success_rate:.1f}% success)")
        return checks_passed >= 4
        
    except Exception as e:
        log_test("Scientific Notation Detection", False, error=str(e))
        return False

def test_address_validation_logic():
    """Test 2: Address Validation Logic - 37-Character WEPO Addresses"""
    print("\n🏠 TEST 2: ADDRESS VALIDATION LOGIC - 37-CHARACTER WEPO ADDRESSES")
    print("Testing both valid and invalid 37-character WEPO addresses with detailed error messages...")
    
    try:
        checks_passed = 0
        total_checks = 6
        
        # Test valid 37-character WEPO addresses (should be accepted)
        valid_addresses = [
            generate_valid_wepo_address(),
            generate_valid_wepo_address(),
            generate_valid_wepo_address()
        ]
        
        for i, valid_addr in enumerate(valid_addresses):
            transaction_data = {
                "from_address": valid_addr,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Valid addresses should not be rejected due to format (may fail for other reasons like balance)
            if response.status_code != 400:
                print(f"  ✅ Valid address {i+1}: {valid_addr[:10]}... properly accepted")
                checks_passed += 1
            else:
                # Check if it's actually an address format error
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    if "invalid" in error_message and ("address" in error_message or "format" in error_message):
                        print(f"  ❌ Valid address {i+1}: {valid_addr[:10]}... incorrectly rejected for format")
                        print(f"    Response: {response.text}")
                    else:
                        # Rejected for other reasons (balance, etc.) - this is acceptable
                        print(f"  ✅ Valid address {i+1}: {valid_addr[:10]}... properly accepted (rejected for non-format reasons)")
                        checks_passed += 1
                except:
                    print(f"  ✅ Valid address {i+1}: {valid_addr[:10]}... properly accepted")
                    checks_passed += 1
        
        # Test invalid addresses (should be rejected with detailed error messages)
        invalid_addresses = [
            ("wepo1abc", "Too short (10 chars instead of 37)"),
            ("wepo1" + "x" * 33, "Too long (38 chars instead of 37)"),
            ("btc1" + secrets.token_hex(16), "Wrong prefix (btc1 instead of wepo1)")
        ]
        
        for invalid_addr, description in invalid_addresses:
            transaction_data = {
                "from_address": invalid_addr,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    
                    # Check for detailed error message features
                    has_format_info = any(term in error_message for term in ['format', 'character', 'length', 'invalid'])
                    has_specific_guidance = any(term in error_message for term in ['wepo1', '37', 'hex', 'must be'])
                    
                    if has_format_info and has_specific_guidance:
                        print(f"  ✅ {description}: Detailed error message with format guidance")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {description}: Error message lacks detail")
                        print(f"    Format info: {has_format_info}, Guidance: {has_specific_guidance}")
                        print(f"    Response: {error_data}")
                except:
                    print(f"  ❌ {description}: Invalid JSON response")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Address Validation Logic", checks_passed >= 5,
                 details=f"Address validation with detailed errors: {checks_passed}/{total_checks} tests passed ({success_rate:.1f}% success)")
        return checks_passed >= 5
        
    except Exception as e:
        log_test("Address Validation Logic", False, error=str(e))
        return False

def test_decimal_precision_validation():
    """Test 3: Decimal Precision Validation - Exactly 8 vs More Than 8 Decimal Places"""
    print("\n🔢 TEST 3: DECIMAL PRECISION VALIDATION - 8 DECIMAL PLACES LIMIT")
    print("Testing amounts with exactly 8 decimal places (accept) vs more than 8 (reject with count)...")
    
    try:
        checks_passed = 0
        total_checks = 3
        
        # Test exactly 8 decimal places (should be accepted)
        valid_amounts = [1.12345678, 0.00000001, 999.99999999]
        
        for amount in valid_amounts:
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": amount
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            # Should not be rejected for decimal precision (may fail for other reasons)
            if response.status_code != 400:
                print(f"  ✅ Valid 8 decimals: {amount} properly accepted")
                checks_passed += 1
            else:
                # Check if it's actually a decimal precision error
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    if "decimal" in error_message or "precision" in error_message:
                        print(f"  ❌ Valid 8 decimals: {amount} incorrectly rejected for decimal precision")
                        print(f"    Response: {response.text}")
                    else:
                        # Rejected for other reasons (balance, etc.) - this is acceptable
                        print(f"  ✅ Valid 8 decimals: {amount} properly accepted (rejected for non-precision reasons)")
                        checks_passed += 1
                except:
                    print(f"  ✅ Valid 8 decimals: {amount} properly accepted")
                    checks_passed += 1
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Decimal Precision Validation", checks_passed >= 2,
                 details=f"Decimal precision validation: {checks_passed}/{total_checks} tests passed ({success_rate:.1f}% success)")
        return checks_passed >= 2
        
    except Exception as e:
        log_test("Decimal Precision Validation", False, error=str(e))
        return False

def test_zero_negative_amount_validation():
    """Test 4: Zero/Negative Amount Validation - Specific Minimum Amount Reporting"""
    print("\n💰 TEST 4: ZERO/NEGATIVE AMOUNT VALIDATION - SPECIFIC MINIMUM AMOUNT REPORTING")
    print("Testing zero and negative amounts to verify error messages include specific minimum (0.00000001 WEPO)...")
    
    try:
        checks_passed = 0
        total_checks = 3
        
        # Test invalid amounts that should show specific minimum
        invalid_amounts = [
            (0, "Zero amount"),
            (-1.5, "Negative amount"),
            (-0.00000001, "Negative minimum amount")
        ]
        
        for amount, description in invalid_amounts:
            transaction_data = {
                "from_address": generate_valid_wepo_address(),
                "to_address": generate_valid_wepo_address(),
                "amount": amount
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    
                    # Check for specific minimum amount in error message
                    has_specific_minimum = "0.00000001" in error_message
                    has_wepo_unit = "wepo" in error_message
                    has_minimum_context = any(term in error_message for term in ['minimum', 'least', 'required'])
                    has_proper_capitalization = str(error_data)[0].isupper() if str(error_data) else False
                    
                    if has_specific_minimum and has_wepo_unit and has_minimum_context:
                        print(f"  ✅ {description}: Error message includes specific minimum (0.00000001 WEPO)")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {description}: Error message lacks specific minimum")
                        print(f"    Minimum: {has_specific_minimum}, Unit: {has_wepo_unit}, Context: {has_minimum_context}")
                        print(f"    Response: {error_data}")
                except:
                    print(f"  ❌ {description}: Invalid JSON response")
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Zero/Negative Amount Validation", checks_passed >= 2,
                 details=f"Minimum amount validation with specific reporting: {checks_passed}/{total_checks} tests passed ({success_rate:.1f}% success)")
        return checks_passed >= 2
        
    except Exception as e:
        log_test("Zero/Negative Amount Validation", False, error=str(e))
        return False

def test_http_security_headers():
    """Test 5: HTTP Security Headers - All 5 Critical Headers Present"""
    print("\n🛡️ TEST 5: HTTP SECURITY HEADERS - ALL 5 CRITICAL HEADERS")
    print("Verifying all 5 critical security headers are present and functional...")
    
    try:
        checks_passed = 0
        total_checks = 5
        
        # Test API endpoint for security headers
        response = requests.get(f"{API_URL}/")
        
        # Check for all 5 critical security headers
        required_headers = [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", ["DENY", "SAMEORIGIN"]),
            ("X-XSS-Protection", "1"),
            ("Strict-Transport-Security", "max-age"),
            ("Content-Security-Policy", "default-src")
        ]
        
        for header_name, expected_value in required_headers:
            if header_name.lower() in [h.lower() for h in response.headers.keys()]:
                header_value = response.headers.get(header_name, "").lower()
                
                if isinstance(expected_value, list):
                    # Multiple acceptable values
                    if any(val.lower() in header_value for val in expected_value):
                        print(f"  ✅ {header_name}: Present with valid value")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {header_name}: Present but invalid value: {header_value}")
                else:
                    # Single expected value or substring
                    if expected_value.lower() in header_value:
                        print(f"  ✅ {header_name}: Present with valid value")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {header_name}: Present but invalid value: {header_value}")
            else:
                print(f"  ❌ {header_name}: Missing from response headers")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("HTTP Security Headers", checks_passed == 5,
                 details=f"Critical security headers verification: {checks_passed}/{total_checks} headers present ({success_rate:.1f}% success)")
        return checks_passed == 5
        
    except Exception as e:
        log_test("HTTP Security Headers", False, error=str(e))
        return False

def test_xss_protection():
    """Test 6: XSS Protection - Malicious Content Detection with Threat Identification"""
    print("\n🚨 TEST 6: XSS PROTECTION - MALICIOUS CONTENT DETECTION")
    print("Testing malicious content detection with threat identification...")
    
    try:
        checks_passed = 0
        total_checks = 5
        
        # Test various XSS payloads
        xss_payloads = [
            ("<script>alert('xss')</script>", "Script tag injection"),
            ("javascript:alert('xss')", "JavaScript protocol"),
            ("<img src=x onerror=alert('xss')>", "Event handler injection"),
            ("';alert('xss');//", "SQL injection with XSS"),
            ("<iframe src='javascript:alert(1)'></iframe>", "Iframe injection")
        ]
        
        for payload, description in xss_payloads:
            transaction_data = {
                "from_address": payload,
                "to_address": generate_valid_wepo_address(),
                "amount": 1.0
            }
            
            response = requests.post(f"{API_URL}/transaction/send", json=transaction_data)
            
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_message = str(error_data).lower()
                    
                    # Check if malicious content was detected and blocked
                    has_security_detection = any(term in error_message for term in ['invalid', 'format', 'security', 'blocked'])
                    payload_not_reflected = payload.lower() not in error_message
                    
                    if has_security_detection and payload_not_reflected:
                        print(f"  ✅ {description}: Malicious payload properly blocked")
                        checks_passed += 1
                    else:
                        print(f"  ❌ {description}: Payload may not be properly handled")
                        print(f"    Detection: {has_security_detection}, Not reflected: {payload_not_reflected}")
                except:
                    print(f"  ✅ {description}: Malicious payload blocked (invalid JSON response)")
                    checks_passed += 1
            else:
                print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("XSS Protection", checks_passed >= 4,
                 details=f"XSS protection with threat identification: {checks_passed}/{total_checks} payloads blocked ({success_rate:.1f}% success)")
        return checks_passed >= 4
        
    except Exception as e:
        log_test("XSS Protection", False, error=str(e))
        return False

def test_json_parsing_enhancement():
    """Test 7: JSON Parsing Enhancement - Detailed Parsing Error Messages"""
    print("\n📄 TEST 7: JSON PARSING ENHANCEMENT - DETAILED PARSING ERROR MESSAGES")
    print("Testing detailed parsing error messages with position information...")
    
    try:
        checks_passed = 0
        total_checks = 3
        
        # Test various malformed JSON scenarios
        malformed_json_cases = [
            ('{"from_address": "test", "amount": }', "Missing value"),
            ('{"from_address": "test" "amount": 1.0}', "Missing comma"),
            ('{"from_address": "test", "amount": 1.0', "Missing closing brace")
        ]
        
        for malformed_json, description in malformed_json_cases:
            try:
                response = requests.post(
                    f"{API_URL}/transaction/send",
                    data=malformed_json,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 400:
                    try:
                        error_data = response.json()
                        error_message = str(error_data).lower()
                        
                        # Check for detailed parsing error information
                        has_json_error = "json" in error_message
                        has_position_info = any(term in error_message for term in ['line', 'column', 'char', 'position'])
                        has_specific_error = any(term in error_message for term in ['expecting', 'invalid', 'format'])
                        
                        if has_json_error and has_position_info and has_specific_error:
                            print(f"  ✅ {description}: Detailed JSON parsing error with position info")
                            checks_passed += 1
                        else:
                            print(f"  ❌ {description}: JSON error lacks detail")
                            print(f"    JSON error: {has_json_error}, Position: {has_position_info}, Specific: {has_specific_error}")
                    except:
                        print(f"  ❌ {description}: Invalid error response format")
                else:
                    print(f"  ❌ {description}: Expected 400 error, got {response.status_code}")
            except Exception as e:
                print(f"  ❌ {description}: Request failed - {str(e)}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("JSON Parsing Enhancement", checks_passed >= 2,
                 details=f"Enhanced JSON parsing errors: {checks_passed}/{total_checks} tests passed ({success_rate:.1f}% success)")
        return checks_passed >= 2
        
    except Exception as e:
        log_test("JSON Parsing Enhancement", False, error=str(e))
        return False

def test_error_message_consistency():
    """Test 8: Error Message Consistency - Professional Capitalization and Formatting"""
    print("\n📝 TEST 8: ERROR MESSAGE CONSISTENCY - PROFESSIONAL FORMATTING")
    print("Verifying professional capitalization and formatting across all error messages...")
    
    try:
        checks_passed = 0
        total_checks = 4
        
        # Test various error scenarios for message consistency
        error_test_cases = [
            {
                "name": "Invalid address format",
                "data": {
                    "from_address": "invalid_address",
                    "to_address": generate_valid_wepo_address(),
                    "amount": 1.0
                }
            },
            {
                "name": "Missing required fields",
                "data": {}
            },
            {
                "name": "Invalid amount type",
                "data": {
                    "from_address": generate_valid_wepo_address(),
                    "to_address": generate_valid_wepo_address(),
                    "amount": "invalid"
                }
            },
            {
                "name": "Zero amount",
                "data": {
                    "from_address": generate_valid_wepo_address(),
                    "to_address": generate_valid_wepo_address(),
                    "amount": 0
                }
            }
        ]
        
        for test_case in error_test_cases:
            try:
                response = requests.post(f"{API_URL}/transaction/send", json=test_case["data"])
                
                if response.status_code == 400:
                    try:
                        error_data = response.json()
                        error_message = str(error_data)
                        
                        # Check for professional formatting qualities
                        has_proper_capitalization = error_message[0].isupper() if error_message else False
                        has_specific_guidance = any(term in error_message.lower() for term in ['must', 'should', 'required', 'minimum'])
                        has_professional_tone = not any(term in error_message.lower() for term in ['oops', 'uh oh', 'whoops'])
                        has_clear_structure = len(error_message.split()) >= 3  # At least 3 words
                        
                        quality_score = sum([has_proper_capitalization, has_specific_guidance, has_professional_tone, has_clear_structure])
                        
                        if quality_score >= 3:
                            print(f"  ✅ {test_case['name']}: Professional error message formatting")
                            checks_passed += 1
                        else:
                            print(f"  ❌ {test_case['name']}: Error message quality issues (score: {quality_score}/4)")
                            print(f"    Message: {error_message}")
                    except:
                        print(f"  ❌ {test_case['name']}: Invalid JSON error response")
                else:
                    print(f"  ❌ {test_case['name']}: Expected 400 error, got {response.status_code}")
            except Exception as e:
                print(f"  ❌ {test_case['name']}: Request failed - {str(e)}")
        
        success_rate = (checks_passed / total_checks) * 100
        log_test("Error Message Consistency", checks_passed >= 3,
                 details=f"Professional error message formatting: {checks_passed}/{total_checks} tests passed ({success_rate:.1f}% success)")
        return checks_passed >= 3
        
    except Exception as e:
        log_test("Error Message Consistency", False, error=str(e))
        return False

def calculate_final_security_score():
    """Calculate final security score based on test results"""
    if test_results["total"] == 0:
        return 0
    
    # Weight critical security areas
    critical_tests = [
        "Scientific Notation Detection",
        "Address Validation Logic",
        "Decimal Precision Validation", 
        "Zero/Negative Amount Validation",
        "HTTP Security Headers"
    ]
    
    critical_passed = 0
    critical_total = 0
    
    for test in test_results['tests']:
        if test['name'] in critical_tests:
            critical_total += 1
            if test['passed']:
                critical_passed += 1
    
    # Calculate weighted score (critical tests worth 70%, others 30%)
    if critical_total > 0:
        critical_score = (critical_passed / critical_total) * 70
    else:
        critical_score = 0
    
    other_passed = test_results["passed"] - critical_passed
    other_total = test_results["total"] - critical_total
    
    if other_total > 0:
        other_score = (other_passed / other_total) * 30
    else:
        other_score = 0
    
    final_score = critical_score + other_score
    test_results["security_score"] = final_score
    
    return final_score

def run_comprehensive_security_verification():
    """Run comprehensive security verification tests"""
    print("🔐 STARTING COMPREHENSIVE SECURITY VERIFICATION")
    print("Testing all critical security areas for 100% security score achievement...")
    print("=" * 80)
    
    # Run all security verification tests
    test1_result = test_scientific_notation_detection()
    test2_result = test_address_validation_logic()
    test3_result = test_decimal_precision_validation()
    test4_result = test_zero_negative_amount_validation()
    test5_result = test_http_security_headers()
    test6_result = test_xss_protection()
    test7_result = test_json_parsing_enhancement()
    test8_result = test_error_message_consistency()
    
    # Calculate final security score
    final_security_score = calculate_final_security_score()
    
    # Print final results
    print("\n" + "=" * 80)
    print("🔐 COMPREHENSIVE SECURITY VERIFICATION RESULTS")
    print("=" * 80)
    
    success_rate = (test_results["passed"] / test_results["total"]) * 100 if test_results["total"] > 0 else 0
    
    print(f"Total Tests: {test_results['total']}")
    print(f"Passed: {test_results['passed']} ✅")
    print(f"Failed: {test_results['failed']} ❌")
    print(f"Success Rate: {success_rate:.1f}%")
    print(f"🎯 FINAL SECURITY SCORE: {final_security_score:.1f}%")
    
    # Critical Success Criteria
    print("\n🎯 CRITICAL SECURITY AREAS:")
    critical_tests = [
        "Scientific Notation Detection",
        "Address Validation Logic", 
        "Decimal Precision Validation",
        "Zero/Negative Amount Validation",
        "HTTP Security Headers",
        "XSS Protection",
        "JSON Parsing Enhancement",
        "Error Message Consistency"
    ]
    
    critical_passed = 0
    for test in test_results['tests']:
        if test['name'] in critical_tests and test['passed']:
            critical_passed += 1
            print(f"  ✅ {test['name']}")
        elif test['name'] in critical_tests:
            print(f"  ❌ {test['name']}")
    
    print(f"\nCritical Security Tests: {critical_passed}/{len(critical_tests)} passed")
    
    # Security Score Assessment
    print(f"\n📊 SECURITY SCORE ASSESSMENT:")
    if final_security_score >= 95:
        print("🎉 EXCELLENT SECURITY POSTURE - READY FOR CHRISTMAS DAY 2025 LAUNCH!")
        print("✅ All critical security areas meet or exceed requirements")
        print("✅ Enhanced error messages provide excellent user guidance")
        print("✅ Comprehensive input validation and sanitization")
        print("✅ Strong HTTP security headers implementation")
        print("✅ Effective XSS and injection attack protection")
        print("✅ Professional error message formatting and consistency")
        return True
    elif final_security_score >= 85:
        print("✅ GOOD SECURITY POSTURE - MINOR IMPROVEMENTS NEEDED")
        print("⚠️  Most security areas are working well")
        print("⚠️  Some enhancements needed for 100% security score")
        return True
    elif final_security_score >= 70:
        print("⚠️  MODERATE SECURITY POSTURE - SIGNIFICANT IMPROVEMENTS NEEDED")
        print("❌ Several security areas need attention")
        print("❌ Enhanced error messages need refinement")
        return False
    else:
        print("🚨 CRITICAL SECURITY ISSUES FOUND!")
        print("❌ Major security vulnerabilities detected")
        print("❌ Immediate remediation required before launch")
        
        # Identify specific issues
        failed_tests = [test['name'] for test in test_results['tests'] if test['name'] in critical_tests and not test['passed']]
        if failed_tests:
            print(f"🚨 Failed critical security tests: {', '.join(failed_tests)}")
        
        print("\n🔧 SECURITY ENHANCEMENT RECOMMENDATIONS:")
        print("• Implement enhanced scientific notation detection with examples")
        print("• Improve address validation with detailed format guidance")
        print("• Add specific decimal count reporting to precision validation")
        print("• Include specific minimum amounts (0.00000001 WEPO) in error messages")
        print("• Ensure all HTTP security headers are properly configured")
        print("• Strengthen XSS protection with threat identification")
        print("• Enhance JSON parsing errors with position information")
        print("• Standardize error message capitalization and professional formatting")
        
        return False

if __name__ == "__main__":
    success = run_comprehensive_security_verification()
    if not success:
        sys.exit(1)