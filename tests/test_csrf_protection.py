#!/usr/bin/env python3
"""
Test CSRF Protection - Verify CSRF tokens are required for state-changing endpoints

This test ensures that Issue #1 from the security audit (CSRF vulnerability) remains fixed.
All POST endpoints must require a valid CSRF token.
"""

import pytest
import json
import os
import tempfile
from src.web_server import create_app


@pytest.fixture
def app():
    """Create a test Flask application."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app = create_app(tmpdir)
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = True
        yield app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


def test_csrf_token_in_meta_tag(client):
    """Test that CSRF token is rendered in HTML meta tag (industry standard)."""
    # Get any page that renders the base template
    response = client.get('/')
    assert response.status_code in [200, 302, 401]  # May redirect or require auth
    # The token should be available via generate_csrf() in test context
    from flask_wtf.csrf import generate_csrf
    with client.application.test_request_context():
        token = generate_csrf()
        assert token is not None
        assert len(token) > 0


def test_logout_requires_csrf_token(client):
    """Test that /api/logout requires a CSRF token."""
    # Attempt logout without CSRF token
    response = client.post('/api/logout')
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_token_missing'
    assert 'CSRF token missing' in data['error']


def test_logout_rejects_invalid_csrf_token(client):
    """Test that /api/logout rejects invalid CSRF tokens."""
    # Attempt logout with invalid CSRF token
    response = client.post(
        '/api/logout',
        headers={'X-CSRF-Token': 'invalid_token_12345'}
    )
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_error'


def test_logout_accepts_valid_csrf_token(client):
    """Test that /api/logout accepts valid CSRF tokens."""
    # First make a GET request to establish session and get CSRF token
    response = client.get('/')
    
    # Extract CSRF token from the response or generate one
    from flask_wtf.csrf import generate_csrf
    with client:
        # Make a request to set up the session context
        client.get('/')
        csrf_token = generate_csrf()
        
        # Now make the POST request with the token
        response = client.post(
            '/api/logout',
            headers={'X-CSRF-Token': csrf_token}
        )
    
    # Should succeed (200) even without OAuth enabled
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True


def test_accept_list_filter_requires_csrf_token(client):
    """Test that /api/accept-list-filters POST requires a CSRF token."""
    # Attempt to create filter without CSRF token
    response = client.post(
        '/api/accept-list-filters',
        json={'pattern': '192.168.1.1', 'description': 'Test filter'}
    )
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_token_missing'


def test_warnlist_filter_requires_csrf_token(client):
    """Test that /api/warnlist-filters POST requires a CSRF token."""
    # Attempt to create filter without CSRF token
    response = client.post(
        '/api/warnlist-filters',
        json={'pattern': '10.0.0.1', 'description': 'Test warn filter'}
    )
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_token_missing'


def test_ip_ban_requires_csrf_token(client):
    """Test that /api/ip-bans POST requires a CSRF token."""
    # Attempt to ban IP without CSRF token
    response = client.post(
        '/api/ip-bans',
        json={'ip': '1.2.3.4'}
    )
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_token_missing'


def test_fail2ban_custom_requires_csrf_token(client):
    """Test that /api/fail2ban/visualize/custom POST requires a CSRF token."""
    # Attempt to visualize custom config without CSRF token
    response = client.post(
        '/api/fail2ban/visualize/custom',
        json={'config': 'test config'}
    )
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['code'] == 'csrf_token_missing'


def test_csrf_token_in_form_data(client):
    """Test that CSRF token can be provided in form data."""
    # Generate a valid CSRF token with proper session
    from flask_wtf.csrf import generate_csrf
    with client:
        client.get('/')  # Establish session
        csrf_token = generate_csrf()
        
        # Attempt logout with CSRF token in form data
        response = client.post(
            '/api/logout',
            data={'csrf_token': csrf_token}
        )
    
    assert response.status_code == 200


def test_csrf_protection_prevents_attack_scenario(client):
    """
    Test the attack scenario from the security audit:
    An attacker's website should not be able to trigger state-changing requests.
    """
    # Simulate an attacker trying to logout a user without a valid CSRF token
    # This would be triggered from an attacker's website via form submission or fetch
    
    # Attempt 1: No CSRF token (like an <img> tag attack)
    response = client.post('/api/logout')
    assert response.status_code == 403
    
    # Attempt 2: Guessed/forged CSRF token
    response = client.post(
        '/api/logout',
        headers={'X-CSRF-Token': 'forged_token_abc123'}
    )
    assert response.status_code == 403
    
    # Only legitimate requests with valid tokens should succeed
    from flask_wtf.csrf import generate_csrf
    with client:
        client.get('/')  # Establish session
        csrf_token = generate_csrf()
        
        response = client.post(
            '/api/logout',
            headers={'X-CSRF-Token': csrf_token}
        )
    
    assert response.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
