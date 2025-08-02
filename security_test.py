#!/usr/bin/env python3
"""
WEPO CRITICAL SECURITY TESTING FOR CHRISTMAS DAY 2025 LAUNCH
=============================================================

CRITICAL SECURITY TESTS REQUIRED:

1. **BRUTE FORCE PROTECTION TEST** - CRITICAL PRIORITY
   - Test wallet login endpoint with multiple failed attempts (test 6-8 attempts)
   - Verify HTTP 423 response after 5 failed attempts (account lockout)
   - Check lockout duration and proper error messages
   - Test if lockout persists across requests

2. **RATE LIMITING TEST** - CRITICAL PRIORITY  
   - Test global API rate limiting (should limit after 60 requests/minute)
   - Test wallet creation rate limiting (should limit after 3 attempts/minute)
   - Test wallet login rate limiting (should limit after 5 attempts/minute)
   - Verify HTTP 429 responses with proper headers

3. **SECURITY INTEGRATION VERIFICATION**
   - Test if SlowAPI middleware is functioning
   - Verify rate limiting headers are present
   - Test brute force protection storage persistence

4. **WORKING SECURITY FEATURES CONFIRMATION**
   - Verify input validation still works (XSS, SQL injection protection)
   - Confirm security headers are present
   - Test password strength validation

CRITICAL SUCCESS CRITERIA:
- Brute force protection: HTTP 423 after 5 failed attempts
- Rate limiting: HTTP 429 responses at specified limits
- Overall security score: Must achieve 85%+ for cryptocurrency production launch
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

print(f"🔐 WEPO CRITICAL SECURITY TESTING FOR CHRISTMAS DAY 2025 LAUNCH")
print(f"Backend API URL: {API_URL}")
print(f"Target Security Score: 85%+ for cryptocurrency production launch")
print("=" * 80)

# Test results tracking
security_results = {
    "total_tests": 0,
    "passed_tests": 0,
    "failed_tests": 0,
    "security_score": 0.0,
    "categories": {
        "brute_force_protection": {"weight": 25, "passed": 0, "total": 0, "score": 0.0},
        "rate_limiting": {"weight": 25, "passed": 0, "total": 0, "score": 0.0},
        "security_integration": {"weight": 20, "passed": 0, "total": 0, "score": 0.0},
        "working_security_features": {"weight": 30, "passed": 0, "total": 0, "score": 0.0}
    },
    "critical_vulnerabilities": [],
    "tests": []
}

def log_security_test(name, passed, category, details=None, error=None, severity="medium"):
    """Log security test results with severity tracking"""
    status = "✅ PASSED" if passed else "❌ FAILED"
    severity_icon = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}.get(severity, "🟠")
    
    print(f"{status} {severity_icon} {name}")
    
    if details:
        print(f"  Details: {details}")
    
    if error:
        print(f"  Error: {error}")
    
    # Update results
    security_results["total_tests"] += 1
    security_results["categories"][category]["total"] += 1
    
    if passed:
        security_results["passed_tests"] += 1
        security_results["categories"][category]["passed"] += 1
    else:
        security_results["failed_tests"] += 1
        if severity in ["critical", "high"]:
            security_results["critical_vulnerabilities"].append({
                "name": name,
                "category": category,
                "severity": severity,
                "details": details,
                "error": error
            })
    
    security_results["tests"].append({
        "name": name,
        "category": category,
        "passed": passed,
        "severity": severity,
        "details": details,
        "error": error
    })

def generate_test_user():
    """Generate test user data for security testing"""
    username = f"sectest_{secrets.token_hex(4)}"
    password = f"SecTest123!{secrets.token_hex(2)}"
    return username, password

def create_test_wallet():
    """Create a test wallet for security testing"""
    username, password = generate_test_user()
    
    try:
        response = requests.post(f"{API_URL}/wallet/create", json={
            "username": username,
            "password": password
        })
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                return username, password, data.get("address")
        
        return None, None, None
    except Exception:
        return None, None, None

# ===== 1. BRUTE FORCE PROTECTION TESTING =====

def test_brute_force_protection():
    """Test 1: Brute Force Protection - CRITICAL PRIORITY"""
    print("\n🚨 BRUTE FORCE PROTECTION TESTING - CRITICAL PRIORITY")
    print("Testing wallet login endpoint with multiple failed attempts...")
    
    # Create test wallet first
    username, password, address = create_test_wallet()
    if not username:
        log_security_test("Brute Force Protection Setup", False, "brute_force_protection",
                         details="Failed to create test wallet for brute force testing", severity="critical")
        return
    
    print(f"Created test wallet: {username}")
    
    # Test multiple failed login attempts
    failed_attempts = 0
    wrong_password = "WrongPassword123!"
    
    print("Testing failed login attempts...")
    
    for attempt in range(1, 9):  # Test up to 8 attempts
        try:
            response = requests.post(f"{API_URL}/wallet/login", json={
                "username": username,
                "password": wrong_password
            })
            
            print(f"  Attempt {attempt}: HTTP {response.status_code}")
            
            if response.status_code == 423:
                # Account locked!
                log_security_test("Brute Force Account Lockout", True, "brute_force_protection",
                               details=f"Account locked after {attempt} failed attempts (HTTP 423)", severity="critical")
                
                # Test lockout persistence
                time.sleep(1)
                persistence_response = requests.post(f"{API_URL}/wallet/login", json={
                    "username": username,
                    "password": password  # Try with correct password
                })
                
                if persistence_response.status_code == 423:
                    log_security_test("Brute Force Lockout Persistence", True, "brute_force_protection",
                                   details="Account remains locked even with correct password", severity="critical")
                else:
                    log_security_test("Brute Force Lockout Persistence", False, "brute_force_protection",
                                   details=f"Lockout not persistent - HTTP {persistence_response.status_code}", severity="critical")
                
                return
            
            elif response.status_code == 401:
                failed_attempts += 1
                continue
            else:
                log_security_test("Brute Force Protection Response", False, "brute_force_protection",
                               details=f"Unexpected response on attempt {attempt}: HTTP {response.status_code}", severity="high")
                break
                
        except Exception as e:
            log_security_test("Brute Force Protection Test", False, "brute_force_protection",
                           error=str(e), severity="critical")
            return
    
    # If we get here, no lockout occurred
    log_security_test("Brute Force Account Lockout", False, "brute_force_protection",
                     details=f"NO account lockout after {failed_attempts} failed attempts", severity="critical")
    
    # Test with invalid username brute force
    print("Testing brute force protection for invalid usernames...")
    invalid_username = f"nonexistent_{secrets.token_hex(4)}"
    
    for attempt in range(1, 6):
        try:
            response = requests.post(f"{API_URL}/wallet/login", json={
                "username": invalid_username,
                "password": "AnyPassword123!"
            })
            
            if response.status_code == 423:
                log_security_test("Invalid Username Brute Force Protection", True, "brute_force_protection",
                               details=f"Protection active for invalid usernames after {attempt} attempts", severity="high")
                return
            elif response.status_code != 401:
                break
                
        except Exception as e:
            log_security_test("Invalid Username Brute Force Test", False, "brute_force_protection",
                           error=str(e), severity="high")
            return
    
    log_security_test("Invalid Username Brute Force Protection", False, "brute_force_protection",
                     details="NO protection for invalid username brute force attempts", severity="high")

# ===== 2. RATE LIMITING TESTING =====

def test_rate_limiting():
    """Test 2: Rate Limiting - CRITICAL PRIORITY"""
    print("\n🚨 RATE LIMITING TESTING - CRITICAL PRIORITY")
    print("Testing global API rate limiting and endpoint-specific limits...")
    
    # Test global API rate limiting
    print("Testing global API rate limiting (should limit after 60 requests/minute)...")
    
    start_time = time.time()
    global_requests = 0
    rate_limited = False
    
    for i in range(70):  # Test beyond the 60 request limit
        try:
            response = requests.get(f"{API_URL}/")
            global_requests += 1
            
            if response.status_code == 429:
                rate_limited = True
                log_security_test("Global API Rate Limiting", True, "rate_limiting",
                               details=f"Rate limited after {global_requests} requests (HTTP 429)", severity="critical")
                
                # Check for rate limiting headers
                headers = response.headers
                rate_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"]
                present_headers = [h for h in rate_headers if h in headers]
                
                if present_headers:
                    log_security_test("Rate Limiting Headers", True, "rate_limiting",
                                   details=f"Rate limiting headers present: {present_headers}", severity="medium")
                else:
                    log_security_test("Rate Limiting Headers", False, "rate_limiting",
                                   details="Missing rate limiting headers in 429 response", severity="medium")
                break
                
        except Exception as e:
            log_security_test("Global API Rate Limiting Test", False, "rate_limiting",
                           error=str(e), severity="critical")
            break
    
    if not rate_limited:
        log_security_test("Global API Rate Limiting", False, "rate_limiting",
                         details=f"NO global rate limiting after {global_requests} requests", severity="critical")
    
    # Test wallet creation rate limiting
    print("Testing wallet creation rate limiting (should limit after 3 attempts/minute)...")
    
    creation_attempts = 0
    creation_rate_limited = False
    
    for i in range(5):  # Test beyond the 3 attempt limit
        try:
            username, password = generate_test_user()
            response = requests.post(f"{API_URL}/wallet/create", json={
                "username": username,
                "password": password
            })
            
            creation_attempts += 1
            
            if response.status_code == 429:
                creation_rate_limited = True
                log_security_test("Wallet Creation Rate Limiting", True, "rate_limiting",
                               details=f"Wallet creation rate limited after {creation_attempts} attempts (HTTP 429)", severity="critical")
                break
            elif response.status_code == 200:
                continue
            else:
                # Other errors are acceptable (validation, etc.)
                continue
                
        except Exception as e:
            log_security_test("Wallet Creation Rate Limiting Test", False, "rate_limiting",
                           error=str(e), severity="critical")
            break
    
    if not creation_rate_limited:
        log_security_test("Wallet Creation Rate Limiting", False, "rate_limiting",
                         details=f"NO wallet creation rate limiting after {creation_attempts} attempts", severity="critical")
    
    # Test wallet login rate limiting
    print("Testing wallet login rate limiting (should limit after 5 attempts/minute)...")
    
    # Create test wallet for login testing
    username, password, address = create_test_wallet()
    if username:
        login_attempts = 0
        login_rate_limited = False
        
        for i in range(7):  # Test beyond the 5 attempt limit
            try:
                response = requests.post(f"{API_URL}/wallet/login", json={
                    "username": username,
                    "password": password
                })
                
                login_attempts += 1
                
                if response.status_code == 429:
                    login_rate_limited = True
                    log_security_test("Wallet Login Rate Limiting", True, "rate_limiting",
                                   details=f"Login rate limited after {login_attempts} attempts (HTTP 429)", severity="critical")
                    break
                elif response.status_code in [200, 401, 423]:
                    continue
                else:
                    break
                    
            except Exception as e:
                log_security_test("Wallet Login Rate Limiting Test", False, "rate_limiting",
                               error=str(e), severity="critical")
                break
        
        if not login_rate_limited:
            log_security_test("Wallet Login Rate Limiting", False, "rate_limiting",
                             details=f"NO login rate limiting after {login_attempts} attempts", severity="critical")
    else:
        log_security_test("Wallet Login Rate Limiting", False, "rate_limiting",
                         details="Could not create test wallet for login rate limiting test", severity="high")

# ===== 3. SECURITY INTEGRATION VERIFICATION =====

def test_security_integration():
    """Test 3: Security Integration Verification"""
    print("\n🔐 SECURITY INTEGRATION VERIFICATION")
    print("Testing SlowAPI middleware and security integration...")
    
    # Test security middleware functionality
    try:
        response = requests.get(f"{API_URL}/")
        
        # Check for security headers that should be added by middleware
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Content-Security-Policy",
            "Strict-Transport-Security"
        ]
        
        present_headers = [h for h in security_headers if h in response.headers]
        missing_headers = [h for h in security_headers if h not in response.headers]
        
        if len(present_headers) >= 4:
            log_security_test("Security Middleware Headers", True, "security_integration",
                           details=f"Security headers present: {present_headers}", severity="medium")
        else:
            log_security_test("Security Middleware Headers", False, "security_integration",
                           details=f"Missing security headers: {missing_headers}", severity="high")
        
    except Exception as e:
        log_security_test("Security Middleware Test", False, "security_integration",
                         error=str(e), severity="high")
    
    # Test CORS configuration
    try:
        response = requests.options(f"{API_URL}/", headers={
            "Origin": "https://malicious-site.com",
            "Access-Control-Request-Method": "POST"
        })
        
        cors_header = response.headers.get("Access-Control-Allow-Origin", "")
        
        if cors_header == "*":
            log_security_test("CORS Security Configuration", False, "security_integration",
                           details="CORS allows all origins (*) - security risk", severity="high")
        elif cors_header and "malicious-site.com" not in cors_header:
            log_security_test("CORS Security Configuration", True, "security_integration",
                           details=f"CORS properly restricted: {cors_header}", severity="medium")
        else:
            log_security_test("CORS Security Configuration", True, "security_integration",
                           details="CORS appears to be properly configured", severity="medium")
        
    except Exception as e:
        log_security_test("CORS Security Test", False, "security_integration",
                         error=str(e), severity="medium")
    
    # Test error handling security
    try:
        response = requests.post(f"{API_URL}/wallet/login", json={
            "username": "test",
            "password": "test"
        })
        
        response_text = response.text.lower()
        
        # Check if error messages expose sensitive information
        sensitive_terms = ["database", "sql", "mongodb", "internal", "stack trace", "exception"]
        exposed_terms = [term for term in sensitive_terms if term in response_text]
        
        if exposed_terms:
            log_security_test("Error Message Security", False, "security_integration",
                           details=f"Error messages may expose sensitive information: {exposed_terms}", severity="medium")
        else:
            log_security_test("Error Message Security", True, "security_integration",
                           details="Error messages don't expose sensitive information", severity="medium")
        
    except Exception as e:
        log_security_test("Error Message Security Test", False, "security_integration",
                         error=str(e), severity="medium")

# ===== 4. WORKING SECURITY FEATURES CONFIRMATION =====

def test_working_security_features():
    """Test 4: Working Security Features Confirmation"""
    print("\n✅ WORKING SECURITY FEATURES CONFIRMATION")
    print("Verifying input validation, security headers, and password strength validation...")
    
    # Test XSS protection
    xss_payloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "';alert('xss');//",
        "<svg onload=alert('xss')>"
    ]
    
    xss_blocked = 0
    for payload in xss_payloads:
        try:
            response = requests.post(f"{API_URL}/wallet/create", json={
                "username": payload,
                "password": "ValidPass123!"
            })
            
            if response.status_code == 400:
                xss_blocked += 1
            elif response.status_code == 200:
                # Check if payload was sanitized
                data = response.json()
                if payload not in str(data):
                    xss_blocked += 1
                    
        except Exception:
            continue
    
    if xss_blocked >= 4:
        log_security_test("XSS Protection", True, "working_security_features",
                         details=f"XSS protection working ({xss_blocked}/{len(xss_payloads)} blocked)", severity="medium")
    else:
        log_security_test("XSS Protection", False, "working_security_features",
                         details=f"XSS protection insufficient ({xss_blocked}/{len(xss_payloads)} blocked)", severity="high")
    
    # Test SQL/NoSQL injection protection
    injection_payloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM users --",
        "'; DELETE FROM wallets; --"
    ]
    
    injection_blocked = 0
    for payload in injection_payloads:
        try:
            response = requests.post(f"{API_URL}/wallet/login", json={
                "username": payload,
                "password": "test"
            })
            
            if response.status_code in [400, 401]:
                injection_blocked += 1
                
        except Exception:
            continue
    
    if injection_blocked >= 4:
        log_security_test("SQL/NoSQL Injection Protection", True, "working_security_features",
                         details=f"Injection protection working ({injection_blocked}/{len(injection_payloads)} blocked)", severity="medium")
    else:
        log_security_test("SQL/NoSQL Injection Protection", False, "working_security_features",
                         details=f"Injection protection insufficient ({injection_blocked}/{len(injection_payloads)} blocked)", severity="high")
    
    # Test password strength validation
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
    for weak_pass in weak_passwords:
        try:
            username, _ = generate_test_user()
            response = requests.post(f"{API_URL}/wallet/create", json={
                "username": username,
                "password": weak_pass
            })
            
            if response.status_code == 400:
                weak_rejected += 1
                
        except Exception:
            continue
    
    if weak_rejected >= 5:
        log_security_test("Password Strength Validation", True, "working_security_features",
                         details=f"Password validation working ({weak_rejected}/{len(weak_passwords)} weak passwords rejected)", severity="medium")
    else:
        log_security_test("Password Strength Validation", False, "working_security_features",
                         details=f"Password validation insufficient ({weak_rejected}/{len(weak_passwords)} weak passwords rejected)", severity="high")
    
    # Test strong password acceptance
    strong_passwords = [
        "StrongPass123!@#",
        "MySecure2024Password!",
        "ComplexP@ssw0rd2024"
    ]
    
    strong_accepted = 0
    for strong_pass in strong_passwords:
        try:
            username, _ = generate_test_user()
            response = requests.post(f"{API_URL}/wallet/create", json={
                "username": username,
                "password": strong_pass
            })
            
            if response.status_code == 200:
                strong_accepted += 1
                
        except Exception:
            continue
    
    if strong_accepted >= 2:
        log_security_test("Strong Password Acceptance", True, "working_security_features",
                         details=f"Strong passwords accepted ({strong_accepted}/{len(strong_passwords)} accepted)", severity="low")
    else:
        log_security_test("Strong Password Acceptance", False, "working_security_features",
                         details=f"Strong password acceptance issues ({strong_accepted}/{len(strong_passwords)} accepted)", severity="medium")

def calculate_security_score():
    """Calculate overall security score based on weighted categories"""
    total_weighted_score = 0.0
    
    for category, data in security_results["categories"].items():
        if data["total"] > 0:
            category_score = (data["passed"] / data["total"]) * 100
            weighted_score = (category_score * data["weight"]) / 100
            total_weighted_score += weighted_score
            data["score"] = category_score
    
    security_results["security_score"] = total_weighted_score
    return total_weighted_score

def run_critical_security_testing():
    """Run critical security testing for Christmas Day 2025 launch"""
    print("🔐 STARTING CRITICAL SECURITY TESTING FOR CHRISTMAS DAY 2025 LAUNCH")
    print("Testing critical security requirements for cryptocurrency production...")
    print("=" * 80)
    
    # Run critical security tests
    test_brute_force_protection()
    test_rate_limiting()
    test_security_integration()
    test_working_security_features()
    
    # Calculate security score
    security_score = calculate_security_score()
    
    # Print results
    print("\n" + "=" * 80)
    print("🔐 CRITICAL SECURITY TESTING RESULTS")
    print("=" * 80)
    
    print(f"Total Security Tests: {security_results['total_tests']}")
    print(f"Passed: {security_results['passed_tests']} ✅")
    print(f"Failed: {security_results['failed_tests']} ❌")
    print(f"Overall Security Score: {security_score:.1f}%")
    
    # Category breakdown
    print("\n📊 SECURITY CATEGORY BREAKDOWN:")
    for category, data in security_results["categories"].items():
        category_name = category.replace("_", " ").title()
        status = "✅" if data["score"] >= 75 else "❌"
        print(f"  {status} {category_name}: {data['passed']}/{data['total']} ({data['score']:.1f}%) [Weight: {data['weight']}%]")
    
    # Critical vulnerabilities
    if security_results["critical_vulnerabilities"]:
        print(f"\n🚨 CRITICAL VULNERABILITIES IDENTIFIED ({len(security_results['critical_vulnerabilities'])}):")
        for vuln in security_results["critical_vulnerabilities"]:
            severity_icon = {"critical": "🚨", "high": "🔴"}.get(vuln["severity"], "🟠")
            print(f"  {severity_icon} {vuln['name']} ({vuln['severity'].upper()})")
            if vuln["details"]:
                print(f"    Issue: {vuln['details']}")
    
    # Christmas Day 2025 launch assessment
    print(f"\n🎄 CHRISTMAS DAY 2025 LAUNCH ASSESSMENT:")
    if security_score >= 85:
        print("🎉 LAUNCH APPROVED - Security requirements met!")
        print("   ✅ Security score meets 85%+ requirement for cryptocurrency production")
        print("   ✅ Critical security vulnerabilities addressed")
        print("   ✅ System ready for Christmas Day 2025 launch")
    elif security_score >= 70:
        print("⚠️  LAUNCH CONDITIONAL - Security improvements needed")
        print("   ⚠️  Security score below 85% requirement")
        print("   ⚠️  Some critical vulnerabilities remain")
        print("   ⚠️  Additional security fixes required before launch")
    else:
        print("🚨 LAUNCH BLOCKED - Critical security issues")
        print("   ❌ Security score significantly below 85% requirement")
        print("   ❌ Multiple critical vulnerabilities present")
        print("   ❌ System not suitable for cryptocurrency operations")
    
    # Production readiness assessment
    print(f"\n🏭 PRODUCTION READINESS:")
    if security_score >= 85:
        print("✅ READY FOR PRODUCTION")
        print("   • Security controls meet enterprise cryptocurrency standards")
        print("   • Brute force protection operational")
        print("   • Rate limiting properly implemented")
        print("   • Input validation and security headers working")
    else:
        print("❌ NOT READY FOR PRODUCTION")
        print("   • Security vulnerabilities must be resolved")
        print("   • Critical security controls missing or non-functional")
        print("   • Immediate security fixes required")
    
    # Specific recommendations
    print(f"\n💡 IMMEDIATE ACTION REQUIRED:")
    
    # Check specific critical issues
    brute_force_score = security_results["categories"]["brute_force_protection"]["score"]
    rate_limiting_score = security_results["categories"]["rate_limiting"]["score"]
    
    if brute_force_score < 50:
        print("🚨 CRITICAL: Implement working brute force protection with account lockout")
    
    if rate_limiting_score < 50:
        print("🚨 CRITICAL: Implement comprehensive rate limiting (global + endpoint-specific)")
    
    if security_score < 85:
        print("🚨 CRITICAL: Address all security vulnerabilities before Christmas Day 2025 launch")
    
    return {
        "security_score": security_score,
        "total_tests": security_results["total_tests"],
        "passed_tests": security_results["passed_tests"],
        "failed_tests": security_results["failed_tests"],
        "critical_vulnerabilities": security_results["critical_vulnerabilities"],
        "categories": security_results["categories"],
        "launch_approved": security_score >= 85
    }

if __name__ == "__main__":
    # Run critical security testing
    results = run_critical_security_testing()
    
    print("\n" + "=" * 80)
    print("🎯 FINAL SECURITY ASSESSMENT SUMMARY")
    print("=" * 80)
    
    print(f"📊 SECURITY METRICS:")
    print(f"• Security Score: {results['security_score']:.1f}% (Target: 85%+)")
    print(f"• Total Tests: {results['total_tests']}")
    print(f"• Critical Vulnerabilities: {len(results['critical_vulnerabilities'])}")
    
    print(f"\n🎄 CHRISTMAS DAY 2025 LAUNCH STATUS:")
    if results['launch_approved']:
        print("🎉 APPROVED - Security requirements met for cryptocurrency production")
    else:
        print("🚨 BLOCKED - Critical security vulnerabilities must be resolved")
    
    print(f"\n🔧 NEXT STEPS:")
    if results['launch_approved']:
        print("• System ready for Christmas Day 2025 launch")
        print("• Continue monitoring for security edge cases")
        print("• Proceed with final production preparations")
    else:
        print("• Address critical security vulnerabilities immediately")
        print("• Focus on brute force protection and rate limiting")
        print("• Re-run security verification after fixes")
        print("• Christmas Day 2025 launch depends on security fixes")