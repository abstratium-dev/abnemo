#!/usr/bin/env python3
"""
OAuth Module - OAuth 2.0 / OIDC authentication with PKCE
Handles authorization code flow with PKCE for secure authentication
"""

import os
import json
import base64
import hashlib
import secrets
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _base64url_encode(data):
    """Base64 URL-safe encoding without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _generate_code_verifier():
    """Generate a random code verifier for PKCE"""
    return _base64url_encode(os.urandom(32))


def _generate_state():
    """Generate a random state parameter"""
    return _base64url_encode(os.urandom(16))


def _build_code_challenge(code_verifier):
    """Build code challenge from verifier using SHA256"""
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return _base64url_encode(digest)


def _parse_jwt_claims(token):
    """Parse JWT token claims without verification (for display only)"""
    if not token or '.' not in token:
        return {}
    try:
        payload = token.split('.')[1]
        padded = payload + '=' * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded.decode('utf-8'))
    except Exception:
        return {}


def build_oauth_config():
    """Build OAuth configuration from environment variables
    
    Returns:
        Dictionary with OAuth configuration
    """
    config = {
        'client_id': os.getenv('ABSTRAUTH_CLIENT_ID'),
        'client_secret': os.getenv('ABSTRAUTH_CLIENT_SECRET'),
        'authorization_endpoint': os.getenv('ABSTRAUTH_AUTHORIZATION_ENDPOINT'),
        'token_endpoint': os.getenv('ABSTRAUTH_TOKEN_ENDPOINT'),
        'redirect_uri': os.getenv('ABSTRAUTH_REDIRECT_URI'),
        'scope': os.getenv('ABSTRAUTH_SCOPE', 'openid profile email'),
        'session_cookie_name': os.getenv('ABSTRAUTH_SESSION_COOKIE', 'abnemo_session'),
        'cookie_secure': os.getenv('ABSTRAUTH_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes'),
        'cookie_samesite': 'Lax',
        'session_ttl': int(os.getenv('ABSTRAUTH_SESSION_TTL', '3600')),
    }
    
    # Parse required groups
    required_groups_raw = os.getenv('ABSTRAUTH_REQUIRED_GROUPS')
    if required_groups_raw:
        required_groups = [group.strip() for group in required_groups_raw.split(',') if group.strip()]
    else:
        single_group = os.getenv('ABSTRAUTH_REQUIRED_GROUP')
        required_groups = [single_group] if single_group else []
    
    config['required_groups'] = required_groups
    config['required_group'] = required_groups[0] if len(required_groups) == 1 else None
    
    # Check if all required fields are present
    required = ['client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint', 'redirect_uri']
    config['enabled'] = all(config[key] for key in required)
    
    return config


def summarize_oauth_config(config):
    """Create a summary of OAuth config for logging (without secrets)
    
    Args:
        config: OAuth configuration dictionary
    
    Returns:
        Summary dictionary safe for logging
    """
    summary = {
        'enabled': config.get('enabled', False),
        'client_id_present': bool(config.get('client_id')),
        'client_secret_present': bool(config.get('client_secret')),
        'authorization_endpoint': bool(config.get('authorization_endpoint')),
        'token_endpoint': bool(config.get('token_endpoint')),
        'redirect_uri': bool(config.get('redirect_uri')),
        'scope': config.get('scope'),
        'session_cookie_name': config.get('session_cookie_name'),
        'cookie_secure': config.get('cookie_secure'),
        'cookie_samesite': config.get('cookie_samesite'),
        'session_ttl': config.get('session_ttl'),
        'required_group': config.get('required_group'),
        'required_groups': config.get('required_groups'),
    }
    return summary


class MemorySessionStore:
    """Simple in-memory session storage for BFF state."""

    def __init__(self, ttl_seconds=3600):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.Lock()

    def _now(self):
        return datetime.now(timezone.utc)

    def _is_expired(self, session):
        expires_at = session.get('_session_expires_at')
        return bool(expires_at and expires_at < self._now())

    def create_session(self):
        """Create a new session and return (session_id, session_data)"""
        with self._lock:
            session_id = secrets.token_urlsafe(32)
            data = {
                '_session_expires_at': self._now() + timedelta(seconds=self.ttl_seconds),
                'authenticated': False
            }
            self._sessions[session_id] = data
            return session_id, data

    def get(self, session_id):
        """Get session data by ID, refreshing expiry if valid"""
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if self._is_expired(session):
                del self._sessions[session_id]
                return None
            session['_session_expires_at'] = self._now() + timedelta(seconds=self.ttl_seconds)
            return session

    def delete(self, session_id):
        """Delete a session by ID"""
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)


def build_authorization_url(base_url, params):
    """Build OAuth authorization URL with parameters
    
    Args:
        base_url: Base authorization endpoint URL
        params: Dictionary of query parameters
    
    Returns:
        Complete authorization URL
    """
    parsed = urllib.parse.urlparse(base_url)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    query.update(params)
    encoded = urllib.parse.urlencode(query)
    rebuilt = parsed._replace(query=encoded)
    return urllib.parse.urlunparse(rebuilt)


def exchange_code_for_token(config, code, code_verifier):
    """Exchange authorization code for access token
    
    Args:
        config: OAuth configuration dictionary
        code: Authorization code from callback
        code_verifier: PKCE code verifier
    
    Returns:
        Token response dictionary
    
    Raises:
        urllib.error.HTTPError on failure
    """
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': config['redirect_uri'],
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'code_verifier': code_verifier
    }
    data = urllib.parse.urlencode(payload).encode('utf-8')
    request_obj = urllib.request.Request(
        config['token_endpoint'],
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    try:
        with urllib.request.urlopen(request_obj, timeout=15) as response:
            body = response.read().decode('utf-8')
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode('utf-8', errors='ignore')
        logger.error('Token exchange failed: %s', error_body)
        raise


def extract_user(tokens):
    """Extract user information from tokens
    
    Args:
        tokens: Token response dictionary
    
    Returns:
        User dictionary with sub, email, name, groups
    """
    token = tokens.get('id_token') or tokens.get('access_token')
    claims = _parse_jwt_claims(token)
    if not claims:
        return None

    def _normalize_groups(raw_groups):
        if not raw_groups:
            return []
        if isinstance(raw_groups, str):
            return [raw_groups]
        if isinstance(raw_groups, (list, tuple, set)):
            return [str(group) for group in raw_groups if group]
        return [str(raw_groups)]

    user = {
        'sub': claims.get('sub'),
        'email': claims.get('email'),
        'name': claims.get('name'),
        'groups': _normalize_groups(claims.get('groups')),
    }
    # Remove empty values
    return {k: v for k, v in user.items() if v}


def user_has_required_group(session, required_groups):
    """Check if user has at least one of the required groups
    
    Args:
        session: Session dictionary with user data
        required_groups: List of required group names
    
    Returns:
        True if user has required group or no groups required
    """
    if not required_groups:
        return True
    user = session.get('user') or {}
    groups = user.get('groups') or []
    return any(group in groups for group in required_groups)


def register_oauth_routes(app, oauth_config, session_store):
    """Register OAuth routes with the Flask app
    
    Args:
        app: Flask application instance
        oauth_config: OAuth configuration dictionary
        session_store: MemorySessionStore instance
    """
    from flask import request, jsonify, redirect, g
    
    @app.route('/oauth/login')
    def oauth_login():
        """Initiate OAuth login flow"""
        if not oauth_config['enabled']:
            return jsonify({'error': 'OAuth not configured'}), 404

        session = getattr(g, 'session_data', {})
        code_verifier = _generate_code_verifier()
        code_challenge = _build_code_challenge(code_verifier)
        state = _generate_state()

        session['pkce'] = {
            'code_verifier': code_verifier,
            'state': state,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

        auth_url = build_authorization_url(
            oauth_config['authorization_endpoint'],
            {
                'response_type': 'code',
                'client_id': oauth_config['client_id'],
                'redirect_uri': oauth_config['redirect_uri'],
                'scope': oauth_config['scope'],
                'state': state,
                'code_challenge': code_challenge,
                'code_challenge_method': 'S256'
            }
        )
        return redirect(auth_url)

    @app.route('/oauth/callback')
    def oauth_callback():
        """Handle OAuth callback"""
        if not oauth_config['enabled']:
            return jsonify({'error': 'OAuth not configured'}), 404

        session = getattr(g, 'session_data', {})
        pkce = session.get('pkce', {})
        expected_state = pkce.get('state')
        received_state = request.args.get('state')
        if not expected_state or expected_state != received_state:
            return redirect('/?error=invalid_state')

        code = request.args.get('code')
        if not code:
            return redirect('/?error=missing_code')

        try:
            tokens = exchange_code_for_token(oauth_config, code, pkce.get('code_verifier', ''))
        except Exception:
            return redirect('/?error=token_exchange_failed')

        session.pop('pkce', None)
        session['authenticated'] = True
        session['tokens'] = {
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
        }
        session['user'] = extract_user(tokens)

        return redirect('/')

    @app.route('/api/user')
    def api_user():
        """Return authentication status and user info."""
        if not oauth_config['enabled']:
            return jsonify({'authenticated': True, 'oauth_enabled': False, 'user': None})

        session = getattr(g, 'session_data', {})
        if not session.get('authenticated'):
            return jsonify({
                'authenticated': False,
                'oauth_enabled': True,
                'user': None,
                'code': 'not_authenticated',
                'required_groups': oauth_config['required_groups'],
                'required_group': oauth_config.get('required_group'),
                'has_access': False
            }), 401

        if oauth_config['required_groups'] and not user_has_required_group(session, oauth_config['required_groups']):
            return jsonify({
                'authenticated': True,
                'oauth_enabled': True,
                'user': session.get('user'),
                'code': 'missing_required_group',
                'required_groups': oauth_config['required_groups'],
                'required_group': oauth_config.get('required_group'),
                'has_access': False
            }), 403

        return jsonify({
            'authenticated': True,
            'oauth_enabled': True,
            'user': session.get('user'),
            'required_groups': oauth_config['required_groups'],
            'required_group': oauth_config.get('required_group'),
            'has_access': True
        })

    @app.route('/api/logout', methods=['POST'])
    def api_logout():
        """Clear authentication session."""
        if not oauth_config['enabled']:
            return jsonify({'success': True, 'oauth_enabled': False})

        session_id = getattr(g, 'session_id', None)
        session_store.delete(session_id)
        g.clear_session_cookie = True
        return jsonify({'success': True})

    @app.route('/api/oauth/status')
    def api_oauth_status():
        """Expose non-secret OAuth configuration details for diagnostics."""
        summary = summarize_oauth_config(oauth_config)
        summary['active_session'] = bool(getattr(g, 'session_data', {}).get('authenticated'))
        if oauth_config['enabled']:
            summary['session_cookie_received'] = bool(request.cookies.get(oauth_config['session_cookie_name']))
        return jsonify(summary)
