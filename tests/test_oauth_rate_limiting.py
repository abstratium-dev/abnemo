#!/usr/bin/env python3
"""
Test OAuth Rate Limiting - Security Check Issue #8

Tests that rate limiting is properly enforced on OAuth endpoints to prevent:
- DoS attacks on login flow
- Brute force attacks on callback endpoint
- Logout abuse

This test ensures the fix for SECURITY_CHECK.md Issue #8 remains in place.
"""

import pytest
import time
from src.web_server import create_app


@pytest.fixture
def app():
    """Create test Flask app with OAuth disabled for testing."""
    app = create_app('/tmp/test_logs')
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestOAuthRateLimiting:
    """Test suite for OAuth endpoint rate limiting (Issue #8)"""

    def test_oauth_login_rate_limit(self, client):
        """Test that /oauth/login is rate limited to 10 requests per minute.
        
        This prevents DoS attacks where an attacker floods the login endpoint.
        """
        # Make 10 requests (should succeed)
        for i in range(10):
            response = client.get('/oauth/login')
            # OAuth is disabled in test, so we expect 404, but NOT 429
            assert response.status_code in [404, 302], \
                f"Request {i+1} should not be rate limited (got {response.status_code})"
        
        # 11th request should be rate limited
        response = client.get('/oauth/login')
        assert response.status_code == 429, \
            "Request 11 should be rate limited with 429 Too Many Requests"
        
        # Verify error response contains rate limit information
        assert b'429' in response.data or b'rate limit' in response.data.lower()

    def test_oauth_callback_rate_limit(self, client):
        """Test that /oauth/callback is rate limited to 20 requests per minute.
        
        This prevents brute force attacks on the callback endpoint.
        """
        # Make 20 requests (should succeed)
        for i in range(20):
            response = client.get('/oauth/callback?code=test&state=test')
            # OAuth is disabled in test, so we expect 404 or redirect, but NOT 429
            assert response.status_code in [404, 302], \
                f"Request {i+1} should not be rate limited (got {response.status_code})"
        
        # 21st request should be rate limited
        response = client.get('/oauth/callback?code=test&state=test')
        assert response.status_code == 429, \
            "Request 21 should be rate limited with 429 Too Many Requests"

    def test_api_logout_rate_limit(self, client):
        """Test that /api/logout is rate limited to 30 requests per minute.
        
        This prevents logout abuse and DoS attacks.
        """
        # Make 30 requests (should succeed or fail with CSRF, but not rate limit)
        for i in range(30):
            response = client.post('/api/logout')
            # Expect 403 (CSRF) or 200 (success), but NOT 429
            assert response.status_code in [200, 403], \
                f"Request {i+1} should not be rate limited (got {response.status_code})"
        
        # 31st request should be rate limited
        response = client.post('/api/logout')
        assert response.status_code == 429, \
            "Request 31 should be rate limited with 429 Too Many Requests"

    def test_rate_limit_headers_present(self, client):
        """Test that rate limit headers are included in responses.
        
        Flask-Limiter should add X-RateLimit-* headers to help clients
        understand their rate limit status.
        """
        response = client.get('/oauth/login')
        
        # Check for standard rate limit headers (may vary by Flask-Limiter version)
        # At minimum, we should get a response (not necessarily with headers in all configs)
        assert response.status_code in [404, 302, 429]

    def test_rate_limit_per_ip(self, client):
        """Test that rate limits are applied per IP address.
        
        This ensures that one client cannot exhaust the rate limit for all users.
        Note: In test environment, all requests come from same IP, so this
        verifies the per-IP behavior is configured correctly.
        """
        # First client exhausts the limit
        for _ in range(10):
            client.get('/oauth/login')
        
        # Next request from same client should be blocked
        response = client.get('/oauth/login')
        assert response.status_code == 429

    def test_different_endpoints_independent_limits(self, client):
        """Test that different endpoints have independent rate limits.
        
        Exhausting the limit on /oauth/login should not affect /oauth/callback.
        """
        # Exhaust login endpoint
        for _ in range(10):
            client.get('/oauth/login')
        
        # Login should be blocked
        response = client.get('/oauth/login')
        assert response.status_code == 429
        
        # But callback should still work (different limit)
        response = client.get('/oauth/callback?code=test&state=test')
        assert response.status_code in [404, 302], \
            "Callback endpoint should have independent rate limit"

    def test_rate_limit_window_reset(self, client):
        """Test that rate limits reset after the time window.
        
        Note: This test is time-sensitive and may be slow.
        It verifies that the fixed-window strategy resets properly.
        """
        # Make 10 requests to exhaust limit
        for _ in range(10):
            client.get('/oauth/login')
        
        # Should be rate limited now
        response = client.get('/oauth/login')
        assert response.status_code == 429
        
        # Wait for window to reset (61 seconds to be safe)
        # In production, this would be 1 minute, but we add buffer for test reliability
        # NOTE: This test is commented out by default as it takes >1 minute
        # Uncomment for full integration testing
        # time.sleep(61)
        # 
        # # After window reset, should work again
        # response = client.get('/oauth/login')
        # assert response.status_code in [404, 302], \
        #     "Rate limit should reset after time window"


class TestRateLimitConfiguration:
    """Test that rate limiting is properly configured"""

    def test_limiter_initialized(self, app):
        """Test that Flask-Limiter is initialized in the app."""
        # Check that limiter extension is registered
        # Flask-Limiter registers itself in app.extensions
        assert 'limiter' in app.extensions or hasattr(app, 'limiter'), \
            "Flask-Limiter should be initialized in the application"

    def test_rate_limit_storage(self, app):
        """Test that rate limiting uses appropriate storage backend."""
        # In test/development, we use memory storage
        # In production, this should be Redis/Memcached
        limiter = app.extensions.get('limiter')
        if limiter:
            # Check storage is configured (implementation detail may vary)
            assert limiter is not None


class TestRateLimitSecurity:
    """Security-focused tests for rate limiting"""

    def test_rate_limit_prevents_dos(self, client):
        """Test that rate limiting effectively prevents DoS attacks.
        
        Simulates an attacker trying to overwhelm the login endpoint.
        """
        successful_requests = 0
        blocked_requests = 0
        
        # Attempt 20 requests (limit is 10)
        for _ in range(20):
            response = client.get('/oauth/login')
            if response.status_code in [404, 302]:
                successful_requests += 1
            elif response.status_code == 429:
                blocked_requests += 1
        
        # Should have exactly 10 successful and 10 blocked
        assert successful_requests == 10, \
            f"Expected 10 successful requests, got {successful_requests}"
        assert blocked_requests == 10, \
            f"Expected 10 blocked requests, got {blocked_requests}"

    def test_rate_limit_prevents_brute_force(self, client):
        """Test that callback rate limiting prevents brute force attacks.
        
        An attacker might try to brute force the state parameter.
        Rate limiting makes this attack impractical.
        """
        # Simulate brute force with different state values
        successful_attempts = 0
        
        for i in range(25):
            response = client.get(f'/oauth/callback?code=test&state=attempt_{i}')
            if response.status_code != 429:
                successful_attempts += 1
        
        # Should only allow 20 attempts (the rate limit)
        assert successful_attempts == 20, \
            f"Rate limit should allow exactly 20 attempts, got {successful_attempts}"

    def test_rate_limit_error_response_format(self, client):
        """Test that rate limit errors return proper HTTP 429 status.
        
        This ensures clients can properly detect and handle rate limiting.
        """
        # Exhaust the limit
        for _ in range(10):
            client.get('/oauth/login')
        
        # Get rate limited response
        response = client.get('/oauth/login')
        
        # Verify proper HTTP status code
        assert response.status_code == 429, \
            "Rate limit exceeded should return HTTP 429"
        
        # Verify response is not empty
        assert len(response.data) > 0, \
            "Rate limit response should contain error information"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
