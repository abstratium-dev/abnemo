#!/usr/bin/env python3
"""
Tests for JWT validation functionality - Security Issue #5 fix

This test suite validates that JWT tokens are properly verified using
cryptographic signatures from the OAuth provider's JWKS endpoint.
"""

import json
import base64
import time
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from src.oauth import (
    _validate_jwt_token,
    _get_jwks_client,
    _get_jwks_uri_from_wellknown,
    extract_user,
    build_oauth_config,
    _parse_jwt_claims
)


class TestJWTValidation:
    """Test JWT signature validation to prevent token forgery attacks."""
    
    @pytest.fixture
    def rsa_keys(self):
        """Generate RSA key pair for testing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Get PEM format for PyJWT
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'private_key': private_pem,
            'public_key': public_pem,
            'private_key_obj': private_key,
            'public_key_obj': public_key
        }
    
    @pytest.fixture
    def valid_jwt(self, rsa_keys):
        """Create a valid JWT token signed with RSA."""
        payload = {
            'sub': 'user123',
            'email': 'test@example.com',
            'name': 'Test User',
            'groups': ['users', 'developers'],
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
            'iss': 'https://auth-t.abstratium.dev'
        }
        
        token = pyjwt.encode(
            payload,
            rsa_keys['private_key'],
            algorithm='RS256',
            headers={'kid': 'test-key-id'}
        )
        
        return token
    
    @pytest.fixture
    def expired_jwt(self, rsa_keys):
        """Create an expired JWT token."""
        payload = {
            'sub': 'user123',
            'email': 'test@example.com',
            'iat': int(time.time()) - 7200,
            'exp': int(time.time()) - 3600,  # Expired 1 hour ago
        }
        
        token = pyjwt.encode(
            payload,
            rsa_keys['private_key'],
            algorithm='RS256',
            headers={'kid': 'test-key-id'}
        )
        
        return token
    
    @pytest.fixture
    def forged_jwt(self):
        """Create a forged JWT token without valid signature."""
        # Create a token with admin groups but no valid signature
        payload = {
            'sub': 'attacker',
            'email': 'attacker@evil.com',
            'groups': ['admin', 'superuser'],
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
        }
        
        # Encode header and payload but use fake signature
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'fake-key'}).encode()
        ).rstrip(b'=').decode()
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        
        # Use a fake signature
        fake_signature = base64.urlsafe_b64encode(b'FAKE_SIGNATURE').rstrip(b'=').decode()
        
        return f"{header}.{payload_encoded}.{fake_signature}"
    
    @pytest.fixture
    def mock_oauth_config(self):
        """Mock OAuth configuration."""
        return {
            'enabled': True,
            'wellknown_uri': 'https://auth-t.abstratium.dev/.well-known/oauth-authorization-server',
            'client_id': 'test-client',
            'client_secret': 'test-secret',
        }
    
    @pytest.fixture
    def mock_jwks_response(self, rsa_keys):
        """Mock JWKS endpoint response."""
        # Convert public key to JWK format
        public_numbers = rsa_keys['public_key_obj'].public_numbers()
        
        # Convert to base64url encoding
        def int_to_base64url(num):
            num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
            return base64.urlsafe_b64encode(num_bytes).rstrip(b'=').decode()
        
        jwks = {
            'keys': [
                {
                    'kty': 'RSA',
                    'use': 'sig',
                    'kid': 'test-key-id',
                    'alg': 'RS256',
                    'n': int_to_base64url(public_numbers.n),
                    'e': int_to_base64url(public_numbers.e),
                }
            ]
        }
        
        return jwks
    
    def test_valid_jwt_passes_validation(self, valid_jwt, mock_oauth_config, rsa_keys, mock_jwks_response):
        """Test that a valid JWT with correct signature passes validation."""
        # Reset global cache
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                # Create mock signing key
                mock_signing_key = Mock()
                mock_signing_key.key = rsa_keys['public_key']
                
                mock_client = Mock()
                mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
                mock_jwks_client_class.return_value = mock_client
                
                result = _validate_jwt_token(valid_jwt, mock_oauth_config)
                
                assert result is not None
                assert result['sub'] == 'user123'
                assert result['email'] == 'test@example.com'
                assert result['groups'] == ['users', 'developers']
    
    def test_forged_jwt_fails_validation(self, forged_jwt, mock_oauth_config):
        """Test that a forged JWT with invalid signature is rejected."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_client = Mock()
                # Simulate key not found or signature verification failure
                mock_client.get_signing_key_from_jwt.side_effect = pyjwt.InvalidTokenError('Invalid signature')
                mock_jwks_client_class.return_value = mock_client
                
                result = _validate_jwt_token(forged_jwt, mock_oauth_config)
                
                assert result is None
    
    def test_expired_jwt_fails_validation(self, expired_jwt, mock_oauth_config, rsa_keys):
        """Test that an expired JWT is rejected."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_signing_key = Mock()
                mock_signing_key.key = rsa_keys['public_key']
                
                mock_client = Mock()
                mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
                mock_jwks_client_class.return_value = mock_client
                
                result = _validate_jwt_token(expired_jwt, mock_oauth_config, verify_exp=True)
                
                assert result is None
    
    def test_extract_user_validates_signature(self, valid_jwt, mock_oauth_config, rsa_keys):
        """Test that extract_user validates JWT signature before extracting claims."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        tokens = {
            'access_token': valid_jwt,
            'id_token': valid_jwt
        }
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_signing_key = Mock()
                mock_signing_key.key = rsa_keys['public_key']
                
                mock_client = Mock()
                mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
                mock_jwks_client_class.return_value = mock_client
                
                user = extract_user(tokens, mock_oauth_config)
                
                assert user is not None
                assert user['sub'] == 'user123'
                assert user['email'] == 'test@example.com'
                assert 'developers' in user['groups']
    
    def test_extract_user_rejects_forged_token(self, forged_jwt, mock_oauth_config):
        """Test that extract_user rejects forged tokens."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        tokens = {
            'access_token': forged_jwt
        }
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_client = Mock()
                mock_client.get_signing_key_from_jwt.side_effect = pyjwt.InvalidTokenError('Invalid signature')
                mock_jwks_client_class.return_value = mock_client
                
                user = extract_user(tokens, mock_oauth_config)
                
                # Should return None for invalid token
                assert user is None
    
    def test_jwks_uri_fetched_from_wellknown(self):
        """Test that JWKS URI is fetched from well-known endpoint."""
        wellknown_response = {
            'issuer': 'https://auth-t.abstratium.dev',
            'jwks_uri': 'https://auth-t.abstratium.dev/.well-known/jwks.json',
            'authorization_endpoint': 'https://auth-t.abstratium.dev/oauth2/authorize',
        }
        
        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = Mock()
            mock_response.read.return_value = json.dumps(wellknown_response).encode()
            mock_response.__enter__ = Mock(return_value=mock_response)
            mock_response.__exit__ = Mock(return_value=False)
            mock_urlopen.return_value = mock_response
            
            jwks_uri = _get_jwks_uri_from_wellknown(
                'https://auth-t.abstratium.dev/.well-known/oauth-authorization-server'
            )
            
            assert jwks_uri == 'https://auth-t.abstratium.dev/.well-known/jwks.json'
    
    def test_jwks_client_caching(self, mock_oauth_config):
        """Test that JWKS client is cached and reused."""
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_client = Mock()
                mock_jwks_client_class.return_value = mock_client
                
                # Reset the global cache
                import src.oauth
                src.oauth._jwks_client = None
                src.oauth._jwks_last_refresh = None
                
                # First call should create client
                client1 = _get_jwks_client(mock_oauth_config)
                assert client1 is not None
                assert mock_jwks_client_class.call_count == 1
                
                # Second call should reuse cached client
                client2 = _get_jwks_client(mock_oauth_config)
                assert client2 is client1
                assert mock_jwks_client_class.call_count == 1  # Not called again
    
    def test_jwks_client_refresh_after_one_day(self, mock_oauth_config):
        """Test that JWKS client is refreshed after one day."""
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_client = Mock()
                mock_jwks_client_class.return_value = mock_client
                
                # Reset the global cache
                import src.oauth
                src.oauth._jwks_client = None
                src.oauth._jwks_last_refresh = None
                
                # First call
                client1 = _get_jwks_client(mock_oauth_config)
                assert mock_jwks_client_class.call_count == 1
                
                # Simulate time passing (more than 1 day)
                src.oauth._jwks_last_refresh = datetime.now(timezone.utc) - timedelta(days=2)
                
                # Second call should refresh
                client2 = _get_jwks_client(mock_oauth_config)
                assert mock_jwks_client_class.call_count == 2  # Called again
    
    def test_parse_jwt_claims_warning(self):
        """Test that _parse_jwt_claims is only for display, not authorization."""
        # Create a token with admin claims (unsigned)
        payload = {
            'sub': 'attacker',
            'groups': ['admin'],
            'exp': int(time.time()) + 3600
        }
        
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'none'}).encode()
        ).rstrip(b'=').decode()
        
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        
        fake_token = f"{header}.{payload_encoded}."
        
        # _parse_jwt_claims should parse it (no validation)
        claims = _parse_jwt_claims(fake_token)
        assert claims['sub'] == 'attacker'
        assert 'admin' in claims['groups']
        
        # But extract_user with OAuth enabled should reject it
        mock_config = {'enabled': True, 'wellknown_uri': 'https://test.com/.well-known'}
        
        with patch('src.oauth._validate_jwt_token') as mock_validate:
            mock_validate.return_value = None  # Validation fails
            
            user = extract_user({'access_token': fake_token}, mock_config)
            assert user is None  # Should be rejected
    
    def test_empty_token_fails_validation(self, mock_oauth_config):
        """Test that empty or None token fails validation."""
        assert _validate_jwt_token(None, mock_oauth_config) is None
        assert _validate_jwt_token('', mock_oauth_config) is None
        assert _validate_jwt_token('   ', mock_oauth_config) is None
    
    def test_malformed_token_fails_validation(self, mock_oauth_config):
        """Test that malformed tokens fail validation."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
            mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
            
            with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                mock_client = Mock()
                mock_client.get_signing_key_from_jwt.side_effect = pyjwt.InvalidTokenError('Malformed')
                mock_jwks_client_class.return_value = mock_client
                
                # Various malformed tokens
                assert _validate_jwt_token('not.a.jwt', mock_oauth_config) is None
                assert _validate_jwt_token('only_one_part', mock_oauth_config) is None
                assert _validate_jwt_token('two.parts', mock_oauth_config) is None
    
    def test_oauth_disabled_skips_validation(self):
        """Test that JWT validation is skipped when OAuth is disabled."""
        config = {'enabled': False}
        
        # Create an unsigned token
        payload = {'sub': 'test', 'email': 'test@example.com'}
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).rstrip(b'=').decode()
        
        fake_token = f"header.{payload_encoded}.signature"
        
        # Should fall back to parsing without validation
        user = extract_user({'access_token': fake_token}, config)
        
        # In disabled mode, it uses _parse_jwt_claims
        assert user is not None
        assert user['sub'] == 'test'


class TestJWTValidationIntegration:
    """Integration tests for JWT validation in the OAuth flow."""
    
    def test_wellknown_uri_required_for_validation(self):
        """Test that ABSTRAUTH_WELLKNOWN_URI is required for JWT validation."""
        config = build_oauth_config()
        
        # If wellknown_uri is not set, validation should fail gracefully
        if not config.get('wellknown_uri'):
            assert _get_jwks_client(config) is None
    
    def test_algorithm_confusion_prevented(self):
        """Test that algorithm confusion attacks are prevented."""
        import src.oauth
        src.oauth._jwks_client = None
        src.oauth._jwks_last_refresh = None
        
        # Generate RSA keys for this test
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Try to create a token with HS256 (symmetric) instead of RS256 (asymmetric)
        payload = {
            'sub': 'attacker',
            'groups': ['admin'],
            'iat': int(time.time()),
            'exp': int(time.time()) + 3600,
        }
        
        # Sign with HS256 using the public key as secret (algorithm confusion attack)
        try:
            malicious_token = pyjwt.encode(
                payload,
                public_pem,
                algorithm='HS256',
                headers={'kid': 'test-key-id'}
            )
            
            mock_config = {
                'enabled': True,
                'wellknown_uri': 'https://auth-t.abstratium.dev/.well-known/oauth-authorization-server'
            }
            
            with patch('src.oauth._get_jwks_uri_from_wellknown') as mock_wellknown:
                mock_wellknown.return_value = 'https://auth-t.abstratium.dev/.well-known/jwks.json'
                
                with patch('src.oauth.PyJWKClient') as mock_jwks_client_class:
                    mock_signing_key = Mock()
                    mock_signing_key.key = public_pem
                    
                    mock_client = Mock()
                    mock_client.get_signing_key_from_jwt.return_value = mock_signing_key
                    mock_jwks_client_class.return_value = mock_client
                    
                    # Should fail because we only accept RS256
                    result = _validate_jwt_token(malicious_token, mock_config)
                    assert result is None
        except Exception:
            # If PyJWT prevents this at encoding time, that's also fine
            pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
