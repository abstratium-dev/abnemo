#!/usr/bin/env python3
"""
Tests for Cookie Security Hardening (Security Issue #4)

This test suite verifies that the application implements OWASP cookie security
best practices to prevent XSS-based cookie theft and other cookie-related attacks.

OWASP Recommendations:
- HttpOnly flag: Prevents JavaScript access to cookies
- Secure flag: Ensures cookies are only sent over HTTPS
- SameSite=Strict: Prevents CSRF attacks
- __Host- prefix: Enforces Secure, Path=/, and no Domain attribute
- Security headers: CSP, X-Frame-Options, HSTS, etc.

Reference: 
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
"""

import os
import sys
import pytest
import tempfile
from unittest.mock import patch, MagicMock

# Import the module under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from oauth import build_oauth_config, MemorySessionStore
from web_server import create_app


class TestCookieSecurityAttributes:
    """Test suite for cookie security attributes (Issue #4)"""
    
    def test_httponly_flag_is_set(self):
        """Test that HttpOnly flag is set on session cookies"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    # Make a request to trigger session creation
                    response = client.get('/')
                
                    # Check Set-Cookie headers
                    set_cookie_headers = response.headers.getlist('Set-Cookie')
                    session_cookie = None
                    for header in set_cookie_headers:
                        if 'abnemo_session' in header or '__Host-abnemo_session' in header:
                            session_cookie = header
                            break
                    
                    assert session_cookie is not None, "Session cookie not found"
                    assert 'HttpOnly' in session_cookie, "HttpOnly flag not set"
    
    def test_secure_flag_enforced_in_production(self):
        """Test that Secure flag is enforced in production environment"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            config = build_oauth_config()
            
            # In production, Secure should be True
            assert config['cookie_secure'] is True, "Secure flag not enforced in production"
    
    def test_secure_flag_optional_in_development(self):
        """Test that Secure flag can be disabled in development"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'development',
            'ABSTRAUTH_COOKIE_SECURE': 'false'
        }):
            config = build_oauth_config()
            
            # In development with explicit false, Secure should be False
            assert config['cookie_secure'] is False
    
    def test_samesite_lax_is_set(self):
        """Test that SameSite=Lax is set (required for OAuth callback redirects)"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            config = build_oauth_config()
            
            # SameSite should be Lax (required for OAuth, still provides CSRF protection)
            assert config['cookie_samesite'] == 'Lax', "SameSite should be Lax for OAuth"
    
    def test_samesite_lax_in_response(self):
        """Test that SameSite=Lax appears in Set-Cookie header"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'development'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    # Check Set-Cookie headers
                    set_cookie_headers = response.headers.getlist('Set-Cookie')
                    session_cookie = None
                    for header in set_cookie_headers:
                        if 'abnemo_session' in header or '__Host-abnemo_session' in header:
                            session_cookie = header
                            break
                    
                    assert session_cookie is not None
                    assert 'SameSite=Lax' in session_cookie, "SameSite=Lax not set"
    
    def test_host_prefix_used_in_production(self):
        """Test that __Host- prefix is used when Secure flag is enabled"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            config = build_oauth_config()
            
            # Cookie name should have __Host- prefix in production
            assert config['session_cookie_name'].startswith('__Host-'), \
                "Cookie should use __Host- prefix in production"
    
    def test_host_prefix_not_used_without_secure(self):
        """Test that __Host- prefix is not used when Secure flag is disabled"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'development',
            'ABSTRAUTH_COOKIE_SECURE': 'false'
        }):
            config = build_oauth_config()
            
            # Cookie name should NOT have __Host- prefix without Secure
            assert not config['session_cookie_name'].startswith('__Host-'), \
                "Cookie should not use __Host- prefix without Secure flag"
    
    def test_path_attribute_is_root(self):
        """Test that Path attribute is set to / for __Host- compliance"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    # Check Set-Cookie headers
                    set_cookie_headers = response.headers.getlist('Set-Cookie')
                    session_cookie = None
                    for header in set_cookie_headers:
                        if '__Host-abnemo_session' in header:
                            session_cookie = header
                            break
                    
                    if session_cookie:
                        assert 'Path=/' in session_cookie, "Path should be /"
    
    def test_no_domain_attribute_set(self):
        """Test that Domain attribute is not set (required for __Host- prefix)"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    # Check Set-Cookie headers
                    set_cookie_headers = response.headers.getlist('Set-Cookie')
                    session_cookie = None
                    for header in set_cookie_headers:
                        if 'abnemo_session' in header or '__Host-abnemo_session' in header:
                            session_cookie = header
                            break
                    
                    if session_cookie:
                        # Domain attribute should NOT be present
                        assert 'Domain=' not in session_cookie, "Domain attribute should not be set"


class TestSecurityHeaders:
    """Test suite for security headers (defense-in-depth)"""
    
    def test_content_security_policy_header(self):
        """Test that Content-Security-Policy header is set with nonce (not unsafe-inline)"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'Content-Security-Policy' in response.headers
                    csp = response.headers['Content-Security-Policy']
                    assert "default-src 'self'" in csp
                    assert "frame-ancestors 'none'" in csp
                    # Should use nonce, not unsafe-inline for scripts
                    assert "'nonce-" in csp
                    assert "script-src 'self' 'nonce-" in csp
                    # Verify unsafe-inline is NOT in script-src
                    script_src_part = csp.split('script-src')[1].split(';')[0]
                    assert "'unsafe-inline'" not in script_src_part, "script-src must not contain unsafe-inline"
                    # unsafe-inline is OK in style-src
                    assert "style-src 'self' 'unsafe-inline'" in csp
    
    def test_x_frame_options_header(self):
        """Test that X-Frame-Options header prevents clickjacking"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'X-Frame-Options' in response.headers
                    assert response.headers['X-Frame-Options'] == 'DENY'
    
    def test_x_content_type_options_header(self):
        """Test that X-Content-Type-Options prevents MIME sniffing"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'X-Content-Type-Options' in response.headers
                    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    
    def test_strict_transport_security_in_production(self):
        """Test that HSTS header is set in production"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'Strict-Transport-Security' in response.headers
                    hsts = response.headers['Strict-Transport-Security']
                    assert 'max-age=31536000' in hsts
                    assert 'includeSubDomains' in hsts
    
    def test_referrer_policy_header(self):
        """Test that Referrer-Policy header controls information leakage"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'Referrer-Policy' in response.headers
                    assert response.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
    
    def test_permissions_policy_header(self):
        """Test that Permissions-Policy header restricts browser features"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    assert 'Permissions-Policy' in response.headers
                    policy = response.headers['Permissions-Policy']
                    assert 'geolocation=()' in policy
                    assert 'camera=()' in policy


class TestCookieSecurityAttackPrevention:
    """Test suite for attack prevention scenarios"""
    
    def test_javascript_cannot_access_httponly_cookie(self):
        """
        Test that HttpOnly cookies cannot be accessed via JavaScript.
        
        This is a conceptual test - in reality, the browser enforces this.
        We verify that the HttpOnly flag is set correctly.
        """
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    # Verify HttpOnly is set
                    set_cookie_headers = response.headers.getlist('Set-Cookie')
                    for header in set_cookie_headers:
                        if 'abnemo_session' in header:
                            assert 'HttpOnly' in header, \
                                "HttpOnly flag prevents JavaScript access"
    
    def test_csrf_protection_with_samesite_lax(self):
        """
        Test that SameSite=Lax provides CSRF protection.
        
        With SameSite=Lax, cookies are sent with top-level navigations (like OAuth callbacks)
        but not with cross-site POST requests, providing CSRF protection while allowing OAuth.
        """
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback'
        }):
            config = build_oauth_config()
            
            # SameSite=Lax provides CSRF protection for POST requests
            assert config['cookie_samesite'] == 'Lax', \
                "SameSite=Lax prevents CSRF while allowing OAuth callbacks"
    
    def test_subdomain_attack_prevented_by_host_prefix(self):
        """
        Test that __Host- prefix prevents subdomain cookie attacks.
        
        The __Host- prefix requires:
        - Secure flag
        - Path=/
        - No Domain attribute
        
        This prevents cookies from being set by subdomains.
        """
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            config = build_oauth_config()
            
            # Verify __Host- prefix is used
            assert config['session_cookie_name'].startswith('__Host-')
            assert config['cookie_secure'] is True
            # Domain is not set (verified in other test)
    
    def test_https_downgrade_prevented_by_hsts(self):
        """
        Test that HSTS header prevents HTTPS downgrade attacks.
        
        The Strict-Transport-Security header forces browsers to use HTTPS,
        preventing man-in-the-middle attacks that downgrade to HTTP.
        """
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production'
        }):
            with tempfile.TemporaryDirectory() as tmpdir:
                app = create_app(tmpdir)
                
                with app.test_client() as client:
                    response = client.get('/')
                    
                    # HSTS should be set in production
                    assert 'Strict-Transport-Security' in response.headers
                    hsts = response.headers['Strict-Transport-Security']
                    
                    # Should have long max-age
                    assert 'max-age=31536000' in hsts  # 1 year
                    
                    # Should include subdomains
                    assert 'includeSubDomains' in hsts


class TestCookieConfigurationValidation:
    """Test suite for cookie configuration validation"""
    
    def test_auto_secure_detection_production(self):
        """Test that auto mode enables Secure in production"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production',
            'ABSTRAUTH_COOKIE_SECURE': 'auto'
        }):
            config = build_oauth_config()
            assert config['cookie_secure'] is True
    
    def test_auto_secure_detection_development(self):
        """Test that auto mode disables Secure in development"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'development',
            'ABSTRAUTH_COOKIE_SECURE': 'auto'
        }):
            config = build_oauth_config()
            assert config['cookie_secure'] is False
    
    def test_explicit_secure_override(self):
        """Test that explicit Secure setting overrides auto-detection"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'development',
            'ABSTRAUTH_COOKIE_SECURE': 'true'
        }):
            config = build_oauth_config()
            assert config['cookie_secure'] is True
    
    def test_custom_cookie_name_with_host_prefix(self):
        """Test that custom cookie names get __Host- prefix in production"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production',
            'ABSTRAUTH_SESSION_COOKIE': 'my_custom_session'
        }):
            config = build_oauth_config()
            assert config['session_cookie_name'] == '__Host-my_custom_session'
    
    def test_existing_host_prefix_not_duplicated(self):
        """Test that __Host- prefix is not duplicated if already present"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'FLASK_ENV': 'production',
            'ABSTRAUTH_SESSION_COOKIE': '__Host-my_session'
        }):
            config = build_oauth_config()
            # Should not become __Host-__Host-my_session
            assert config['session_cookie_name'] == '__Host-my_session'
            assert config['session_cookie_name'].count('__Host-') == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
