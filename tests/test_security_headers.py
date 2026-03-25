#!/usr/bin/env python3
"""
Security Headers Test Suite - SECURITY_CHECK Issue #7

Tests comprehensive security headers implementation following OWASP best practices.
This test ensures all required security headers are present and properly configured
to protect against XSS, clickjacking, MIME sniffing, Spectre attacks, and other
web vulnerabilities.

References:
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- https://owasp.org/www-project-secure-headers/
- SECURITY_CHECK.md Issue #7
"""

import pytest
import os
import sys
import tempfile

# Import the module under test
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.web_server import create_app


class TestSecurityHeaders:
    """Test suite for security headers implementation (OWASP 2026 standards)"""
    
    @pytest.fixture
    def client(self):
        """Create a test client with OAuth disabled for header testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set to development mode to disable HSTS by default
            os.environ['FLASK_ENV'] = 'development'
            try:
                app = create_app(tmpdir)
                app.config['TESTING'] = True
                with app.test_client() as client:
                    yield client
            finally:
                os.environ.pop('FLASK_ENV', None)
    
    @pytest.fixture
    def client_with_secure_cookies(self):
        """Create a test client with secure cookies enabled (HTTPS mode)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Set environment variables to enable secure cookies
            os.environ['FLASK_ENV'] = 'production'
            os.environ['ABSTRAUTH_COOKIE_SECURE'] = 'true'
            try:
                app = create_app(tmpdir)
                app.config['TESTING'] = True
                with app.test_client() as client:
                    yield client
            finally:
                os.environ.pop('ABSTRAUTH_COOKIE_SECURE', None)
                os.environ.pop('FLASK_ENV', None)
    
    def test_content_security_policy_present(self, client):
        """Test that Content-Security-Policy header is present"""
        response = client.get('/')
        assert 'Content-Security-Policy' in response.headers
        csp = response.headers['Content-Security-Policy']
        
        # Verify key CSP directives
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp
    
    def test_csp_nonce_for_scripts(self, client):
        """Test that CSP includes nonce for inline scripts (no unsafe-inline)"""
        response = client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        
        # Should have nonce-based script execution
        assert 'nonce-' in csp
        # Should NOT allow unsafe-inline for scripts (XSS protection)
        assert "'unsafe-inline'" not in csp.split('script-src')[1].split(';')[0]
    
    def test_x_frame_options_deny(self, client):
        """Test that X-Frame-Options is set to DENY (clickjacking protection)"""
        response = client.get('/')
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_x_content_type_options_nosniff(self, client):
        """Test that X-Content-Type-Options is set to nosniff (MIME sniffing protection)"""
        response = client.get('/')
        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    
    def test_x_xss_protection_disabled(self, client):
        """Test that X-XSS-Protection is disabled per OWASP recommendation"""
        response = client.get('/')
        # OWASP recommends setting this to 0 as it can create vulnerabilities
        # Modern browsers should rely on CSP instead
        assert response.headers.get('X-XSS-Protection') == '0'
    
    def test_referrer_policy_present(self, client):
        """Test that Referrer-Policy is set correctly"""
        response = client.get('/')
        assert response.headers.get('Referrer-Policy') == 'strict-origin-when-cross-origin'
    
    def test_permissions_policy_restrictive(self, client):
        """Test that Permissions-Policy restricts dangerous browser features"""
        response = client.get('/')
        permissions = response.headers.get('Permissions-Policy', '')
        
        # Should disable dangerous features
        assert 'geolocation=()' in permissions
        assert 'microphone=()' in permissions
        assert 'camera=()' in permissions
        assert 'payment=()' in permissions
        
        # Should opt-out of Google FLoC tracking
        assert 'interest-cohort=()' in permissions
    
    def test_cross_origin_opener_policy(self, client):
        """Test that Cross-Origin-Opener-Policy isolates browsing context"""
        response = client.get('/')
        assert response.headers.get('Cross-Origin-Opener-Policy') == 'same-origin'
    
    def test_cross_origin_resource_policy(self, client):
        """Test that Cross-Origin-Resource-Policy limits resource loading"""
        response = client.get('/')
        assert response.headers.get('Cross-Origin-Resource-Policy') == 'same-site'
    
    def test_cross_origin_embedder_policy(self, client):
        """Test that Cross-Origin-Embedder-Policy requires CORP"""
        response = client.get('/')
        assert response.headers.get('Cross-Origin-Embedder-Policy') == 'require-corp'
    
    def test_hsts_when_secure_enabled(self, client_with_secure_cookies):
        """Test that HSTS header is present when cookie_secure is enabled"""
        response = client_with_secure_cookies.get('/')
        hsts = response.headers.get('Strict-Transport-Security')
        
        assert hsts is not None
        assert 'max-age=31536000' in hsts
        assert 'includeSubDomains' in hsts
        assert 'preload' in hsts
    
    def test_hsts_absent_when_not_secure(self, client):
        """Test that HSTS header is absent when cookie_secure is disabled"""
        response = client.get('/')
        # HSTS should not be set in non-HTTPS environments
        assert 'Strict-Transport-Security' not in response.headers
    
    def test_server_header_removed(self, client):
        """Test that Server header is removed (prevents fingerprinting)"""
        response = client.get('/')
        assert 'Server' not in response.headers
    
    def test_x_powered_by_removed(self, client):
        """Test that X-Powered-By header is removed (prevents fingerprinting)"""
        response = client.get('/')
        assert 'X-Powered-By' not in response.headers
    
    def test_all_headers_on_api_endpoints(self, client):
        """Test that security headers are applied to API endpoints"""
        response = client.get('/api/network')
        
        # All security headers should be present on API responses too
        assert 'Content-Security-Policy' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-Content-Type-Options' in response.headers
        assert 'Cross-Origin-Opener-Policy' in response.headers
        assert 'Cross-Origin-Resource-Policy' in response.headers
    
    def test_all_headers_on_error_responses(self, client):
        """Test that security headers are applied even on error responses"""
        response = client.get('/nonexistent-page')
        
        # Security headers should be present even on 404 responses
        assert 'Content-Security-Policy' in response.headers
        assert 'X-Frame-Options' in response.headers
        assert 'X-Content-Type-Options' in response.headers
    
    def test_headers_comprehensive_coverage(self, client):
        """Test that all OWASP-recommended headers are present"""
        response = client.get('/')
        headers = response.headers
        
        # Complete list of expected security headers
        expected_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy',
            'Cross-Origin-Embedder-Policy',
        ]
        
        missing_headers = [h for h in expected_headers if h not in headers]
        assert not missing_headers, f"Missing security headers: {missing_headers}"
    
    def test_csp_prevents_inline_script_injection(self, client):
        """Test that CSP configuration prevents common XSS vectors"""
        response = client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        
        # Verify no unsafe directives that would allow XSS
        script_src = csp.split('script-src')[1].split(';')[0] if 'script-src' in csp else ''
        
        # Should NOT contain unsafe-inline or unsafe-eval for scripts
        assert "'unsafe-eval'" not in script_src
        # Note: unsafe-inline is allowed only with nonce, which is secure
    
    def test_defense_in_depth_clickjacking(self, client):
        """Test defense-in-depth for clickjacking (both CSP and X-Frame-Options)"""
        response = client.get('/')
        
        # Should have both modern (CSP) and legacy (X-Frame-Options) protection
        assert 'frame-ancestors' in response.headers.get('Content-Security-Policy', '')
        assert response.headers.get('X-Frame-Options') == 'DENY'
    
    def test_spectre_attack_mitigation(self, client):
        """Test that Cross-Origin policies mitigate Spectre-like attacks"""
        response = client.get('/')
        
        # All three Cross-Origin headers should be present for Spectre protection
        assert response.headers.get('Cross-Origin-Opener-Policy') == 'same-origin'
        assert response.headers.get('Cross-Origin-Resource-Policy') == 'same-site'
        assert response.headers.get('Cross-Origin-Embedder-Policy') == 'require-corp'


class TestSecurityHeadersRegression:
    """Regression tests to ensure security headers remain in place"""
    
    @pytest.fixture
    def client(self):
        """Create a test client"""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ['FLASK_ENV'] = 'development'
            try:
                app = create_app(tmpdir)
                app.config['TESTING'] = True
                with app.test_client() as client:
                    yield client
            finally:
                os.environ.pop('FLASK_ENV', None)
    
    @pytest.fixture
    def client_with_secure_cookies(self):
        """Create a test client with secure cookies enabled"""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ['FLASK_ENV'] = 'production'
            os.environ['ABSTRAUTH_COOKIE_SECURE'] = 'true'
            try:
                app = create_app(tmpdir)
                app.config['TESTING'] = True
                with app.test_client() as client:
                    yield client
            finally:
                os.environ.pop('ABSTRAUTH_COOKIE_SECURE', None)
                os.environ.pop('FLASK_ENV', None)
    
    def test_headers_not_removed_by_future_changes(self, client):
        """Regression test: ensure headers are not accidentally removed"""
        response = client.get('/')
        
        # Critical headers that must never be removed
        critical_headers = {
            'Content-Security-Policy': 'Prevents XSS attacks',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Cross-Origin-Opener-Policy': 'Prevents Spectre attacks',
        }
        
        for header, purpose in critical_headers.items():
            assert header in response.headers, \
                f"CRITICAL: {header} header missing! Purpose: {purpose}"
    
    def test_no_unsafe_csp_directives_added(self, client):
        """Regression test: ensure no unsafe CSP directives are added"""
        response = client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')
        
        # These should NEVER appear in CSP (except with nonce)
        unsafe_patterns = [
            "'unsafe-eval'",
            "script-src 'unsafe-inline'",  # Only allowed with nonce
            "data: script-src",  # Data URIs in script-src
        ]
        
        for pattern in unsafe_patterns:
            assert pattern not in csp, \
                f"UNSAFE CSP directive found: {pattern}"
    
    def test_hsts_not_weakened(self, client_with_secure_cookies):
        """Regression test: ensure HSTS is not weakened"""
        response = client_with_secure_cookies.get('/')
        hsts = response.headers.get('Strict-Transport-Security', '')
        
        # HSTS must have minimum 1 year max-age
        assert 'max-age=' in hsts
        max_age = int(hsts.split('max-age=')[1].split(';')[0])
        assert max_age >= 31536000, "HSTS max-age must be at least 1 year"
        
        # Must include subdomains
        assert 'includeSubDomains' in hsts


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
