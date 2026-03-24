#!/usr/bin/env python3
"""
Tests for OAuth module - OAuth 2.0 / OIDC authentication with PKCE
"""

import os
import json
import base64
import hashlib
import time
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from cryptography.fernet import Fernet

# Import the module under test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from oauth import (
    _base64url_encode,
    _generate_code_verifier,
    _generate_state,
    _build_code_challenge,
    _parse_jwt_claims,
    _extract_jwt_expiry,
    _is_token_expired,
    build_oauth_config,
    summarize_oauth_config,
    MemorySessionStore,
    build_authorization_url,
    extract_user,
    user_has_required_group,
)


class TestBase64UrlEncoding:
    """Test base64 URL-safe encoding functions"""
    
    def test_base64url_encode(self):
        """Test base64 URL-safe encoding without padding"""
        data = b'hello world'
        encoded = _base64url_encode(data)
        assert isinstance(encoded, str)
        assert '=' not in encoded  # No padding
        assert '+' not in encoded  # URL-safe
        assert '/' not in encoded  # URL-safe
    
    def test_base64url_encode_empty(self):
        """Test encoding empty data"""
        encoded = _base64url_encode(b'')
        assert encoded == ''


class TestPKCEGeneration:
    """Test PKCE code verifier and challenge generation"""
    
    def test_generate_code_verifier(self):
        """Test code verifier generation"""
        verifier = _generate_code_verifier()
        assert isinstance(verifier, str)
        assert len(verifier) >= 43  # Minimum length per RFC 7636
        assert len(verifier) <= 128  # Maximum length per RFC 7636
        assert '=' not in verifier  # No padding
    
    def test_generate_code_verifier_uniqueness(self):
        """Test that code verifiers are unique"""
        verifier1 = _generate_code_verifier()
        verifier2 = _generate_code_verifier()
        assert verifier1 != verifier2
    
    def test_generate_state(self):
        """Test state parameter generation"""
        state = _generate_state()
        assert isinstance(state, str)
        assert len(state) > 0
        assert '=' not in state  # No padding
    
    def test_generate_state_uniqueness(self):
        """Test that state parameters are unique"""
        state1 = _generate_state()
        state2 = _generate_state()
        assert state1 != state2
    
    def test_build_code_challenge(self):
        """Test code challenge generation from verifier"""
        verifier = 'test_verifier_1234567890'
        challenge = _build_code_challenge(verifier)
        
        # Verify it's a valid base64url string
        assert isinstance(challenge, str)
        assert '=' not in challenge
        
        # Verify it's the SHA256 hash
        expected_digest = hashlib.sha256(verifier.encode('ascii')).digest()
        expected_challenge = _base64url_encode(expected_digest)
        assert challenge == expected_challenge
    
    def test_code_challenge_deterministic(self):
        """Test that same verifier produces same challenge"""
        verifier = 'test_verifier'
        challenge1 = _build_code_challenge(verifier)
        challenge2 = _build_code_challenge(verifier)
        assert challenge1 == challenge2


class TestJWTParsing:
    """Test JWT token parsing and expiry extraction"""
    
    def create_jwt(self, payload, header=None):
        """Helper to create a JWT token for testing"""
        if header is None:
            header = {'alg': 'RS256', 'typ': 'JWT'}
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        
        # Fake signature
        signature = 'fake_signature'
        
        return f'{header_b64}.{payload_b64}.{signature}'
    
    def test_parse_jwt_claims_valid(self):
        """Test parsing valid JWT claims"""
        payload = {
            'sub': 'user123',
            'email': 'test@example.com',
            'name': 'Test User',
            'exp': 1234567890
        }
        token = self.create_jwt(payload)
        claims = _parse_jwt_claims(token)
        
        assert claims['sub'] == 'user123'
        assert claims['email'] == 'test@example.com'
        assert claims['name'] == 'Test User'
        assert claims['exp'] == 1234567890
    
    def test_parse_jwt_claims_empty_token(self):
        """Test parsing empty token"""
        claims = _parse_jwt_claims('')
        assert claims == {}
    
    def test_parse_jwt_claims_none(self):
        """Test parsing None token"""
        claims = _parse_jwt_claims(None)
        assert claims == {}
    
    def test_parse_jwt_claims_invalid_format(self):
        """Test parsing invalid token format"""
        claims = _parse_jwt_claims('invalid.token')
        assert claims == {}
    
    def test_extract_jwt_expiry_valid(self):
        """Test extracting expiry from valid JWT"""
        exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        payload = {'sub': 'user123', 'exp': exp_timestamp}
        token = self.create_jwt(payload)
        
        expiry = _extract_jwt_expiry(token)
        assert expiry is not None
        assert isinstance(expiry, datetime)
        assert expiry.tzinfo == timezone.utc
    
    def test_extract_jwt_expiry_no_exp_claim(self):
        """Test extracting expiry from JWT without exp claim"""
        payload = {'sub': 'user123'}
        token = self.create_jwt(payload)
        
        expiry = _extract_jwt_expiry(token)
        assert expiry is None
    
    def test_extract_jwt_expiry_invalid_token(self):
        """Test extracting expiry from invalid token"""
        expiry = _extract_jwt_expiry('invalid_token')
        assert expiry is None
    
    def test_extract_jwt_expiry_invalid_timestamp(self):
        """Test extracting expiry with invalid timestamp"""
        payload = {'sub': 'user123', 'exp': 'invalid'}
        token = self.create_jwt(payload)
        
        expiry = _extract_jwt_expiry(token)
        assert expiry is None


class TestTokenExpiry:
    """Test token expiry validation"""
    
    def create_jwt(self, payload):
        """Helper to create a JWT token"""
        header = {'alg': 'RS256', 'typ': 'JWT'}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        return f'{header_b64}.{payload_b64}.fake_signature'
    
    def test_is_token_expired_none(self):
        """Test that None tokens are considered expired"""
        assert _is_token_expired(None) is True
    
    def test_is_token_expired_empty(self):
        """Test that empty token dict is considered expired"""
        assert _is_token_expired({}) is True
    
    def test_is_token_expired_by_expires_at(self):
        """Test token expiry using expires_at field"""
        # Expired token
        expired_tokens = {
            'access_token': 'token',
            'expires_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        }
        assert _is_token_expired(expired_tokens) is True
        
        # Valid token
        valid_tokens = {
            'access_token': 'token',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        assert _is_token_expired(valid_tokens) is False
    
    def test_is_token_expired_by_jwt_exp(self):
        """Test token expiry using JWT exp claim"""
        # Expired JWT
        exp_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        expired_jwt = self.create_jwt({'sub': 'user', 'exp': exp_timestamp})
        tokens = {'access_token': expired_jwt}
        assert _is_token_expired(tokens) is True
        
        # Valid JWT
        exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        valid_jwt = self.create_jwt({'sub': 'user', 'exp': exp_timestamp})
        tokens = {'access_token': valid_jwt}
        assert _is_token_expired(tokens) is False
    
    def test_is_token_expired_both_checks(self):
        """Test that both expires_at and JWT exp are checked"""
        # expires_at says expired, JWT says valid - should be expired
        exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
        jwt = self.create_jwt({'sub': 'user', 'exp': exp_timestamp})
        tokens = {
            'access_token': jwt,
            'expires_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        }
        assert _is_token_expired(tokens) is True
    
    def test_is_token_expired_invalid_expires_at(self):
        """Test handling of invalid expires_at format"""
        tokens = {
            'access_token': 'token',
            'expires_at': 'invalid_date'
        }
        # Should not crash, should check JWT or return False
        result = _is_token_expired(tokens)
        assert isinstance(result, bool)


class TestOAuthConfig:
    """Test OAuth configuration building and validation"""
    
    def test_build_oauth_config_all_present(self):
        """Test building config when all required vars are present"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'ABSTRAUTH_WELLKNOWN_URI': 'https://auth.example.com/.well-known/oauth-authorization-server',
            'ABSTRAUTH_SCOPE': 'openid profile email',
            'ABSTRAUTH_SESSION_COOKIE': 'my_session',
            'ABSTRAUTH_COOKIE_SECURE': 'true',
            'ABSTRAUTH_SESSION_TTL': '7200',
            'ABSTRAUTH_REQUIRED_GROUPS': 'admin,moderator'
        }):
            config = build_oauth_config()
            
            assert config['enabled'] is True
            assert config['client_id'] == 'test_client'
            assert config['client_secret'] == 'test_secret'
            assert config['authorization_endpoint'] == 'https://auth.example.com/authorize'
            assert config['token_endpoint'] == 'https://auth.example.com/token'
            assert config['redirect_uri'] == 'https://app.example.com/callback'
            assert config['scope'] == 'openid profile email'
            assert config['session_cookie_name'] == '__Host-my_session'  # __Host- prefix added when secure=true
            assert config['cookie_secure'] is True
            assert config['cookie_samesite'] == 'Lax'
            assert config['session_ttl'] == 7200
            assert config['required_groups'] == ['admin', 'moderator']
    
    def test_build_oauth_config_missing_required(self):
        """Test building config when required vars are missing"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            # Missing other required fields
        }, clear=True):
            config = build_oauth_config()
            assert config['enabled'] is False
    
    def test_build_oauth_config_defaults(self):
        """Test default values when optional vars are not set"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'ABSTRAUTH_WELLKNOWN_URI': 'https://auth.example.com/.well-known/openid-configuration',
            'FLASK_ENV': 'development',  # Set to development to avoid __Host- prefix
        }, clear=True):
            config = build_oauth_config()
            
            assert config['scope'] == 'openid profile email'
            assert config['session_cookie_name'] == 'abnemo_session'
            assert config['cookie_secure'] is False
            assert config['session_ttl'] == 3600
            assert config['required_groups'] == []
    
    def test_build_oauth_config_single_group(self):
        """Test single group configuration"""
        with patch.dict(os.environ, {
            'ABSTRAUTH_CLIENT_ID': 'test_client',
            'ABSTRAUTH_CLIENT_SECRET': 'test_secret',
            'ABSTRAUTH_AUTHORIZATION_ENDPOINT': 'https://auth.example.com/authorize',
            'ABSTRAUTH_TOKEN_ENDPOINT': 'https://auth.example.com/token',
            'ABSTRAUTH_REDIRECT_URI': 'https://app.example.com/callback',
            'ABSTRAUTH_WELLKNOWN_URI': 'https://auth.example.com/.well-known/openid-configuration',
            'ABSTRAUTH_REQUIRED_GROUP': 'admin'
        }, clear=True):
            config = build_oauth_config()
            
            assert config['required_groups'] == ['admin']
            assert config['required_group'] == 'admin'
    
    def test_summarize_oauth_config(self):
        """Test OAuth config summary (without secrets)"""
        config = {
            'enabled': True,
            'client_id': 'test_client',
            'client_secret': 'super_secret',
            'authorization_endpoint': 'https://auth.example.com/authorize',
            'token_endpoint': 'https://auth.example.com/token',
            'redirect_uri': 'https://app.example.com/callback',
            'wellknown_uri': 'https://auth.example.com/.well-known/openid-configuration',
            'scope': 'openid profile',
            'session_cookie_name': 'my_session',
            'cookie_secure': True,
            'cookie_samesite': 'Lax',
            'session_ttl': 3600,
            'required_group': 'admin',
            'required_groups': ['admin']
        }
        
        summary = summarize_oauth_config(config)
        
        assert summary['enabled'] is True
        assert summary['client_id_present'] is True
        assert summary['client_secret_present'] is True
        assert 'super_secret' not in str(summary)  # Secret not exposed
        assert 'test_client' not in str(summary)  # Client ID not exposed
        assert summary['scope'] == 'openid profile'


class TestMemorySessionStore:
    """Test in-memory session storage"""
    
    def test_create_session(self):
        """Test creating a new session"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, session_data = store.create_session()
        
        assert isinstance(session_id, str)
        assert len(session_id) > 0
        assert session_data['authenticated'] is False
        assert '_session_expires_at' in session_data
    
    def test_create_session_uniqueness(self):
        """Test that session IDs are unique"""
        store = MemorySessionStore()
        session_id1, _ = store.create_session()
        session_id2, _ = store.create_session()
        assert session_id1 != session_id2
    
    def test_get_session_valid(self):
        """Test retrieving a valid session"""
        store = MemorySessionStore()
        session_id, _ = store.create_session()
        
        retrieved = store.get(session_id)
        assert retrieved is not None
        assert retrieved['authenticated'] is False
    
    def test_get_session_nonexistent(self):
        """Test retrieving a non-existent session"""
        store = MemorySessionStore()
        retrieved = store.get('nonexistent_id')
        assert retrieved is None
    
    def test_get_session_expired(self):
        """Test that expired sessions are deleted"""
        store = MemorySessionStore(ttl_seconds=1)
        session_id, _ = store.create_session()
        
        # Wait for expiry
        time.sleep(2)
        
        retrieved = store.get(session_id)
        assert retrieved is None
    
    def test_get_session_refreshes_expiry(self):
        """Test that accessing a session refreshes its expiry"""
        store = MemorySessionStore(ttl_seconds=2)
        session_id, session_data = store.create_session()
        
        original_expiry = session_data['_session_expires_at']
        time.sleep(1)
        
        retrieved = store.get(session_id)
        new_expiry = retrieved['_session_expires_at']
        
        assert new_expiry > original_expiry
    
    def test_delete_session(self):
        """Test deleting a session"""
        store = MemorySessionStore()
        session_id, _ = store.create_session()
        
        store.delete(session_id)
        retrieved = store.get(session_id)
        assert retrieved is None
    
    def test_delete_nonexistent_session(self):
        """Test deleting a non-existent session (should not crash)"""
        store = MemorySessionStore()
        store.delete('nonexistent_id')  # Should not raise
    
    def test_store_and_retrieve_tokens(self):
        """Test storing and retrieving encrypted tokens"""
        store = MemorySessionStore()
        session_id, _ = store.create_session()
        
        tokens = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        store.store_tokens(session_id, tokens)
        retrieved_tokens = store.retrieve_tokens(session_id)
        
        assert retrieved_tokens is not None
        assert retrieved_tokens['access_token'] == 'test_access_token'
        assert retrieved_tokens['refresh_token'] == 'test_refresh_token'
        assert retrieved_tokens['expires_at'] == tokens['expires_at']
    
    def test_tokens_are_encrypted(self):
        """Test that tokens are encrypted in storage"""
        store = MemorySessionStore()
        session_id, _ = store.create_session()
        
        tokens = {'access_token': 'secret_token'}
        store.store_tokens(session_id, tokens)
        
        # Access internal storage
        session = store._sessions[session_id]
        encrypted = session.get('_encrypted_tokens')
        
        # Encrypted data should not contain plaintext token
        assert 'secret_token' not in encrypted
        assert isinstance(encrypted, str)
    
    def test_session_invalidated_on_token_expiry(self):
        """Test that sessions are invalidated when tokens expire"""
        store = MemorySessionStore()
        session_id, session_data = store.create_session()
        session_data['authenticated'] = True
        
        # Create expired JWT
        exp_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        header = {'alg': 'RS256', 'typ': 'JWT'}
        payload = {'sub': 'user', 'exp': exp_timestamp}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        expired_jwt = f'{header_b64}.{payload_b64}.sig'
        
        tokens = {
            'access_token': expired_jwt,
            'expires_at': (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        }
        
        store.store_tokens(session_id, tokens)
        
        # Try to retrieve session - should be invalidated due to expired token
        retrieved = store.get(session_id)
        assert retrieved is None
    
    def test_encryption_key_from_env(self):
        """Test using encryption key from environment variable"""
        key = Fernet.generate_key().decode()
        with patch.dict(os.environ, {'ABNEMO_TOKEN_ENCRYPTION_KEY': key}):
            store = MemorySessionStore()
            assert store._fernet is not None
    
    def test_encryption_key_generated(self):
        """Test that encryption key is generated if not provided"""
        with patch.dict(os.environ, {}, clear=True):
            store = MemorySessionStore()
            assert store._fernet is not None


class TestAuthorizationURL:
    """Test authorization URL building"""
    
    def test_build_authorization_url(self):
        """Test building authorization URL with parameters"""
        base_url = 'https://auth.example.com/authorize'
        params = {
            'client_id': 'test_client',
            'redirect_uri': 'https://app.example.com/callback',
            'scope': 'openid profile',
            'state': 'random_state',
            'code_challenge': 'challenge',
            'code_challenge_method': 'S256'
        }
        
        url = build_authorization_url(base_url, params)
        
        assert url.startswith('https://auth.example.com/authorize?')
        assert 'client_id=test_client' in url
        assert 'redirect_uri=https' in url
        assert 'scope=openid' in url
        assert 'state=random_state' in url
        assert 'code_challenge=challenge' in url
        assert 'code_challenge_method=S256' in url
    
    def test_build_authorization_url_with_existing_params(self):
        """Test building URL when base already has query params"""
        base_url = 'https://auth.example.com/authorize?existing=param'
        params = {'new': 'value'}
        
        url = build_authorization_url(base_url, params)
        
        assert 'existing=param' in url
        assert 'new=value' in url


class TestUserExtraction:
    """Test user information extraction from tokens"""
    
    def create_jwt(self, payload):
        """Helper to create a JWT token"""
        header = {'alg': 'RS256', 'typ': 'JWT'}
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode('utf-8')
        ).rstrip(b'=').decode('ascii')
        return f'{header_b64}.{payload_b64}.fake_signature'
    
    def test_extract_user_from_id_token(self):
        """Test extracting user info from id_token"""
        payload = {
            'sub': 'user123',
            'email': 'test@example.com',
            'name': 'Test User',
            'groups': ['admin', 'users']
        }
        id_token = self.create_jwt(payload)
        tokens = {'id_token': id_token}
        
        user = extract_user(tokens)
        
        assert user['sub'] == 'user123'
        assert user['email'] == 'test@example.com'
        assert user['name'] == 'Test User'
        assert user['groups'] == ['admin', 'users']
    
    def test_extract_user_from_access_token(self):
        """Test extracting user info from access_token when no id_token"""
        payload = {
            'sub': 'user456',
            'email': 'user@example.com'
        }
        access_token = self.create_jwt(payload)
        tokens = {'access_token': access_token}
        
        user = extract_user(tokens)
        
        assert user['sub'] == 'user456'
        assert user['email'] == 'user@example.com'
    
    def test_extract_user_groups_normalization(self):
        """Test that groups are normalized to list"""
        # Single string group
        payload = {'sub': 'user', 'groups': 'admin'}
        token = self.create_jwt(payload)
        user = extract_user({'id_token': token})
        assert user['groups'] == ['admin']
        
        # List of groups
        payload = {'sub': 'user', 'groups': ['admin', 'users']}
        token = self.create_jwt(payload)
        user = extract_user({'id_token': token})
        assert user['groups'] == ['admin', 'users']
        
        # No groups
        payload = {'sub': 'user'}
        token = self.create_jwt(payload)
        user = extract_user({'id_token': token})
        assert 'groups' not in user or user['groups'] == []
    
    def test_extract_user_removes_empty_values(self):
        """Test that empty values are removed from user dict"""
        payload = {
            'sub': 'user123',
            'email': '',
            'name': None
        }
        token = self.create_jwt(payload)
        user = extract_user({'id_token': token})
        
        assert 'sub' in user
        assert 'email' not in user  # Empty string removed
        assert 'name' not in user  # None removed
    
    def test_extract_user_invalid_token(self):
        """Test extracting user from invalid token"""
        tokens = {'id_token': 'invalid_token'}
        user = extract_user(tokens)
        assert user is None


class TestGroupAuthorization:
    """Test group-based authorization"""
    
    def test_user_has_required_group_no_requirement(self):
        """Test when no groups are required"""
        session = {'user': {'groups': []}}
        assert user_has_required_group(session, []) is True
        assert user_has_required_group(session, None) is True
    
    def test_user_has_required_group_match(self):
        """Test when user has required group"""
        session = {'user': {'groups': ['admin', 'users']}}
        assert user_has_required_group(session, ['admin']) is True
        assert user_has_required_group(session, ['moderator', 'admin']) is True
    
    def test_user_has_required_group_no_match(self):
        """Test when user doesn't have required group"""
        session = {'user': {'groups': ['users']}}
        assert user_has_required_group(session, ['admin']) is False
        assert user_has_required_group(session, ['admin', 'moderator']) is False
    
    def test_user_has_required_group_no_groups(self):
        """Test when user has no groups"""
        session = {'user': {'groups': []}}
        assert user_has_required_group(session, ['admin']) is False
    
    def test_user_has_required_group_no_user(self):
        """Test when session has no user"""
        session = {}
        assert user_has_required_group(session, ['admin']) is False
    
    def test_user_has_required_group_missing_groups_field(self):
        """Test when user object has no groups field"""
        session = {'user': {'sub': 'user123'}}
        assert user_has_required_group(session, ['admin']) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
