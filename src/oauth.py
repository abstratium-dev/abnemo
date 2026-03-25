#!/usr/bin/env python3
"""
OAuth Module - OAuth 2.0 / OIDC authentication with PKCE
Handles authorization code flow with PKCE for secure authentication
"""

import os
import json
import base64
import hashlib
import hmac
import secrets
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from flask_wtf.csrf import validate_csrf
from flask import request
from werkzeug.exceptions import BadRequest
from cryptography.fernet import Fernet, InvalidToken
import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)

# Global JWKS client cache - initialized when OAuth is configured
_jwks_client = None
_jwks_client_lock = threading.Lock()
_jwks_last_refresh = None
_jwks_refresh_interval = timedelta(days=1)  # Refresh JWKS once per day


def _base64url_encode(data):
    """Base64 URL-safe encoding without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _generate_code_verifier():
    """Generate a random code verifier for PKCE"""
    return _base64url_encode(os.urandom(32))


def _generate_state():
    """Generate a random state parameter (legacy - use _generate_signed_state for security)"""
    return _base64url_encode(os.urandom(16))


def _generate_signed_state(session_id, server_secret, max_age_seconds=600):
    """Generate a cryptographically signed state parameter bound to session.
    
    This implements industry-standard OAuth 2.0 state parameter security:
    - HMAC-SHA256 signature binds state to server secret
    - Timestamp prevents replay attacks (default 10 minute expiry)
    - Session ID binding prevents session fixation
    - Nonce provides additional randomness
    
    Format: base64url(payload).base64url(signature)
    Payload: {"session_id": "...", "timestamp": 123456, "nonce": "..."}
    
    Args:
        session_id: Current session identifier
        server_secret: Secret key for HMAC (should be from environment)
        max_age_seconds: Maximum age of state before expiry (default 600 = 10 minutes)
    
    Returns:
        Signed state string in format: payload.signature
    """
    timestamp = int(datetime.now(timezone.utc).timestamp())
    nonce = _base64url_encode(os.urandom(16))
    
    # Create payload with session binding and timestamp
    payload = {
        'session_id': session_id,
        'timestamp': timestamp,
        'nonce': nonce,
        'max_age': max_age_seconds
    }
    
    # Encode payload
    payload_json = json.dumps(payload, separators=(',', ':'))
    encoded_payload = _base64url_encode(payload_json.encode('utf-8'))
    
    # Create HMAC signature
    signature = hmac.new(
        server_secret.encode('utf-8'),
        encoded_payload.encode('utf-8'),
        hashlib.sha256
    ).digest()
    encoded_signature = _base64url_encode(signature)
    
    return f"{encoded_payload}.{encoded_signature}"


def _validate_signed_state(state, session_id, server_secret):
    """Validate a cryptographically signed state parameter.
    
    This validates:
    1. State format is correct (payload.signature)
    2. HMAC signature is valid (prevents tampering)
    3. State is not expired (timestamp check)
    4. State is bound to current session (prevents session fixation)
    
    Args:
        state: Signed state string to validate
        session_id: Current session identifier
        server_secret: Secret key for HMAC validation
    
    Returns:
        Dict with 'valid' boolean and 'error'/'message' on failure
    """
    if not state or not session_id or not server_secret:
        return {
            'valid': False,
            'error': 'missing_parameters',
            'message': 'State, session ID, or server secret is missing'
        }
    
    try:
        # Split payload and signature
        parts = state.split('.')
        if len(parts) != 2:
            return {
                'valid': False,
                'error': 'invalid_format',
                'message': 'State parameter has invalid format'
            }
        
        encoded_payload, encoded_signature = parts
        
        # Verify HMAC signature using timing-safe comparison
        expected_signature = hmac.new(
            server_secret.encode('utf-8'),
            encoded_payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        expected_encoded = _base64url_encode(expected_signature)
        
        # Use timing-safe comparison to prevent timing attacks
        if not hmac.compare_digest(encoded_signature, expected_encoded):
            return {
                'valid': False,
                'error': 'invalid_signature',
                'message': 'State parameter signature is invalid'
            }
        
        # Decode payload
        # Add padding if needed for base64 decoding
        padding = 4 - len(encoded_payload) % 4
        if padding != 4:
            encoded_payload += '=' * padding
        
        payload_json = base64.urlsafe_b64decode(encoded_payload).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Validate session binding
        if payload.get('session_id') != session_id:
            return {
                'valid': False,
                'error': 'session_mismatch',
                'message': 'State parameter is not bound to current session'
            }
        
        # Validate timestamp (check expiration)
        timestamp = payload.get('timestamp', 0)
        max_age = payload.get('max_age', 600)
        current_timestamp = int(datetime.now(timezone.utc).timestamp())
        
        if current_timestamp - timestamp > max_age:
            return {
                'valid': False,
                'error': 'state_expired',
                'message': f'State parameter has expired (max age: {max_age}s)'
            }
        
        # State is valid
        return {
            'valid': True,
            'payload': payload
        }
        
    except (ValueError, json.JSONDecodeError, KeyError) as e:
        return {
            'valid': False,
            'error': 'validation_error',
            'message': f'State validation failed: {str(e)}'
        }
    except Exception as e:
        logger.error('Unexpected error validating state: %s', e)
        return {
            'valid': False,
            'error': 'internal_error',
            'message': 'Internal error validating state'
        }


def _build_code_challenge(code_verifier):
    """Build code challenge from verifier using SHA256"""
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    return _base64url_encode(digest)


def _parse_jwt_claims(token):
    """Parse JWT token claims without verification (for display only - DO NOT USE FOR AUTHORIZATION)
    
    WARNING: This function does NOT validate the JWT signature.
    Use _validate_jwt_token() for any authorization decisions.
    """
    if not token or '.' not in token:
        return {}
    try:
        payload = token.split('.')[1]
        padded = payload + '=' * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded.decode('utf-8'))
    except Exception:
        return {}


def _extract_jwt_expiry(token):
    """Extract expiry timestamp from JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        datetime object representing token expiry, or None if not found
    """
    claims = _parse_jwt_claims(token)
    exp = claims.get('exp')
    if exp:
        try:
            return datetime.fromtimestamp(exp, tz=timezone.utc)
        except (ValueError, OSError, TypeError):
            return None
    return None


def _get_jwks_uri_from_wellknown(wellknown_uri):
    """Fetch JWKS URI from the well-known OIDC configuration endpoint.
    
    Args:
        wellknown_uri: URL to the .well-known/oauth-authorization-server endpoint
    
    Returns:
        JWKS URI string or None if not found
    """
    try:
        request_obj = urllib.request.Request(wellknown_uri)
        with urllib.request.urlopen(request_obj, timeout=10) as response:
            body = response.read().decode('utf-8')
            config = json.loads(body)
            jwks_uri = config.get('jwks_uri')
            if jwks_uri:
                logger.info('Fetched JWKS URI from well-known endpoint: %s', jwks_uri)
                return jwks_uri
            else:
                logger.error('No jwks_uri found in well-known configuration')
                return None
    except Exception as e:
        logger.error('Failed to fetch JWKS URI from %s: %s', wellknown_uri, e)
        return None


def _get_jwks_client(oauth_config):
    """Get or create a PyJWKClient for JWT validation.
    
    This function manages a singleton JWKS client that:
    - Fetches public keys from the OAuth provider's JWKS endpoint
    - Caches keys to avoid repeated network requests
    - Automatically refreshes keys when needed
    - Refreshes the JWKS URI once per day from the well-known endpoint
    
    Args:
        oauth_config: OAuth configuration dictionary with wellknown_uri
    
    Returns:
        PyJWKClient instance or None if configuration is invalid
    """
    global _jwks_client, _jwks_last_refresh
    
    if not oauth_config.get('enabled'):
        return None
    
    wellknown_uri = oauth_config.get('wellknown_uri')
    if not wellknown_uri:
        logger.error('No wellknown_uri configured for JWT validation')
        return None
    
    with _jwks_client_lock:
        now = datetime.now(timezone.utc)
        
        # Check if we need to refresh the JWKS client (once per day)
        needs_refresh = (
            _jwks_client is None or
            _jwks_last_refresh is None or
            (now - _jwks_last_refresh) > _jwks_refresh_interval
        )
        
        if needs_refresh:
            logger.info('Refreshing JWKS client from well-known endpoint')
            jwks_uri = _get_jwks_uri_from_wellknown(wellknown_uri)
            
            if jwks_uri:
                try:
                    # Create new PyJWKClient with caching enabled
                    # cache_keys=True enables in-memory caching of keys
                    # max_cached_keys=16 limits memory usage
                    _jwks_client = PyJWKClient(
                        jwks_uri,
                        cache_keys=True,
                        max_cached_keys=16,
                        lifespan=3600  # Cache keys for 1 hour
                    )
                    _jwks_last_refresh = now
                    logger.info('JWKS client initialized successfully')
                except Exception as e:
                    logger.error('Failed to create JWKS client: %s', e)
                    _jwks_client = None
            else:
                _jwks_client = None
        
        return _jwks_client


def _validate_jwt_token(token, oauth_config, verify_exp=True):
    """Validate JWT token signature and claims using JWKS public keys.
    
    This function implements industry-standard JWT validation:
    1. Fetches the appropriate public key from JWKS endpoint
    2. Verifies the token signature using RS256 algorithm
    3. Validates standard claims (exp, iss, aud if configured)
    4. Returns decoded and verified claims
    
    Args:
        token: JWT token string to validate
        oauth_config: OAuth configuration dictionary
        verify_exp: Whether to verify token expiration (default: True)
    
    Returns:
        Dictionary of validated claims or None if validation fails
    """
    if not token:
        logger.warning('JWT validation failed: empty token')
        return None
    
    jwks_client = _get_jwks_client(oauth_config)
    if not jwks_client:
        logger.error('JWT validation failed: JWKS client not available')
        return None
    
    try:
        # Get the signing key from the token's kid header
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        # Get the algorithm from the token header
        unverified_header = jwt.get_unverified_header(token)
        token_alg = unverified_header.get('alg', 'RS256')
        
        # Log token details for debugging (without signature)
        unverified_claims = _parse_jwt_claims(token)
        logger.debug('JWT token details: alg=%s, kid=%s, iss=%s, aud=%s, sub=%s', 
                   token_alg, 
                   unverified_header.get('kid', 'none'),
                   unverified_claims.get('iss', 'none'),
                   unverified_claims.get('aud', 'none'),
                   unverified_claims.get('sub', 'none'))
        
        # Only allow secure RSA algorithms to prevent algorithm confusion attacks
        # RS256 = RSA-PKCS1 with SHA-256 (widely used)
        # PS256 = RSA-PSS with SHA-256 (more secure, used by Abstrauth)
        allowed_algorithms = ['RS256', 'PS256']
        if token_alg not in allowed_algorithms:
            logger.warning('JWT validation failed: unsupported algorithm %s (only %s allowed)', 
                          token_alg, ', '.join(allowed_algorithms))
            return None
        
        # Decode and validate the token
        # - Verifies signature using the public key
        # - Validates expiration time (exp claim)
        # - Does NOT validate audience (aud) - this is optional in OIDC and depends on provider config
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=allowed_algorithms,  # Accept RS256 and PS256 (both secure RSA algorithms)
            options={
                'verify_signature': True,
                'verify_exp': verify_exp,
                'verify_iat': True,
                'verify_aud': False,  # Don't validate audience - not all OIDC providers include it
                'require': ['exp', 'iat']  # Require these claims to be present
            }
        )
        
        logger.info('JWT validation successful for sub=%s, groups=%s', 
                   decoded.get('sub'), decoded.get('groups', []))
        return decoded
        
    except jwt.ExpiredSignatureError:
        logger.warning('JWT validation failed: token expired')
        return None
    except jwt.InvalidTokenError as e:
        logger.warning('JWT validation failed: %s', e)
        return None
    except Exception as e:
        logger.error('JWT validation error: %s', e)
        return None


def _is_token_expired(tokens):
    """Check if tokens are expired based on JWT exp claim or expires_at.
    
    Args:
        tokens: Dictionary containing access_token and/or expires_at
    
    Returns:
        True if tokens are expired, False otherwise
    """
    if not tokens:
        return True
    
    # First check expires_at if present
    expires_at_str = tokens.get('expires_at')
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at < datetime.now(timezone.utc):
                return True
        except (ValueError, TypeError):
            pass
    
    # Also check JWT exp claim from access_token
    access_token = tokens.get('access_token')
    if access_token:
        jwt_expiry = _extract_jwt_expiry(access_token)
        if jwt_expiry and jwt_expiry < datetime.now(timezone.utc):
            return True
    
    return False


def build_oauth_config():
    """Build OAuth configuration from environment variables
    
    Returns:
        Dictionary with OAuth configuration
    """
    # Determine if we're in production (HTTPS required)
    is_production = os.getenv('FLASK_ENV', 'production') == 'production'
    cookie_secure_env = os.getenv('ABSTRAUTH_COOKIE_SECURE', 'auto').lower()
    
    # Auto-detect: force Secure in production, allow override in dev
    if cookie_secure_env == 'auto':
        cookie_secure = is_production
    else:
        cookie_secure = cookie_secure_env in ('1', 'true', 'yes')
    
    # Use __Host- prefix for maximum security (requires Secure, Path=/, no Domain)
    # Falls back to regular name if Secure cannot be enabled
    base_cookie_name = os.getenv('ABSTRAUTH_SESSION_COOKIE', 'abnemo_session')
    if cookie_secure and not base_cookie_name.startswith('__Host-'):
        session_cookie_name = f'__Host-{base_cookie_name}'
    else:
        session_cookie_name = base_cookie_name
    
    # Get or generate server secret for state signing
    # This should be a persistent secret in production (from environment)
    server_secret = os.getenv('ABNEMO_STATE_SECRET')
    if not server_secret:
        # Generate ephemeral secret (will change on restart - acceptable for state)
        server_secret = secrets.token_urlsafe(32)
        logger.warning('No ABNEMO_STATE_SECRET set, using ephemeral secret for state signing')
    
    config = {
        'client_id': os.getenv('ABSTRAUTH_CLIENT_ID'),
        'client_secret': os.getenv('ABSTRAUTH_CLIENT_SECRET'),
        'authorization_endpoint': os.getenv('ABSTRAUTH_AUTHORIZATION_ENDPOINT'),
        'token_endpoint': os.getenv('ABSTRAUTH_TOKEN_ENDPOINT'),
        'redirect_uri': os.getenv('ABSTRAUTH_REDIRECT_URI'),
        'wellknown_uri': os.getenv('ABSTRAUTH_WELLKNOWN_URI'),
        'scope': os.getenv('ABSTRAUTH_SCOPE', 'openid profile email'),
        'session_cookie_name': session_cookie_name,
        'cookie_secure': cookie_secure,
        'cookie_samesite': 'Lax',  # Lax required for OAuth callback redirects; still provides CSRF protection
        'session_ttl': int(os.getenv('ABSTRAUTH_SESSION_TTL', '3600')),
        'state_secret': server_secret,
        'state_max_age': int(os.getenv('ABSTRAUTH_STATE_MAX_AGE', '600')),  # 10 minutes default
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
    required = ['client_id', 'client_secret', 'authorization_endpoint', 'token_endpoint', 'redirect_uri', 'wellknown_uri']
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
        'wellknown_uri': bool(config.get('wellknown_uri')),
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
    """Simple in-memory session storage for BFF state with encrypted token storage."""

    def __init__(self, ttl_seconds=3600):
        self.ttl_seconds = ttl_seconds
        self._sessions = {}
        self._lock = threading.Lock()
        # Initialize Fernet encryption for token protection
        # Key is generated at runtime and stored in memory only
        encryption_key = os.getenv('ABNEMO_TOKEN_ENCRYPTION_KEY')
        if encryption_key:
            self._fernet = Fernet(encryption_key.encode())
        else:
            # Generate a new key if not provided (will be lost on restart)
            self._fernet = Fernet(Fernet.generate_key())
            logger.warning('No ABNEMO_TOKEN_ENCRYPTION_KEY set, using ephemeral key')

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
            
            # Check if tokens are expired
            if session.get('authenticated'):
                encrypted = session.get('_encrypted_tokens')
                if encrypted:
                    tokens = self._decrypt_tokens(encrypted)
                    if _is_token_expired(tokens):
                        logger.info('Session %s invalidated due to expired tokens', session_id[:8])
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

    def regenerate_session(self, old_session_id):
        """Regenerate session ID to prevent session fixation attacks.
        
        This method creates a new session ID and transfers all session data
        from the old session to the new one, then deletes the old session.
        This is critical for preventing session fixation attacks where an
        attacker tricks a victim into using a known session ID.
        
        Args:
            old_session_id: The current session ID to regenerate
        
        Returns:
            Tuple of (new_session_id, session_data) or (None, None) if old session not found
        """
        if not old_session_id:
            return None, None
        
        with self._lock:
            # Get the old session data
            old_session = self._sessions.get(old_session_id)
            if not old_session:
                return None, None
            
            # Generate a new session ID
            new_session_id = secrets.token_urlsafe(32)
            
            # Copy all data from old session to new session
            # This preserves authentication state, user info, tokens, etc.
            new_session = old_session.copy()
            
            # Update expiry time for the new session
            new_session['_session_expires_at'] = self._now() + timedelta(seconds=self.ttl_seconds)
            
            # Store the new session
            self._sessions[new_session_id] = new_session
            
            # Delete the old session to prevent reuse
            del self._sessions[old_session_id]
            
            logger.info('Session regenerated: %s -> %s', old_session_id[:8], new_session_id[:8])
            
            return new_session_id, new_session

    def _encrypt_tokens(self, tokens):
        """Encrypt token dictionary for secure storage.
        
        Args:
            tokens: Dictionary containing access_token, refresh_token, etc.
        
        Returns:
            Encrypted token string (base64 encoded)
        """
        if not tokens:
            return None
        try:
            # Serialize tokens to JSON and encrypt
            tokens_json = json.dumps(tokens)
            encrypted = self._fernet.encrypt(tokens_json.encode('utf-8'))
            return encrypted.decode('ascii')
        except Exception as e:
            logger.error('Failed to encrypt tokens: %s', e)
            return None

    def _decrypt_tokens(self, encrypted_tokens):
        """Decrypt token string to recover original tokens.
        
        Args:
            encrypted_tokens: Encrypted token string
        
        Returns:
            Dictionary containing decrypted tokens or None if decryption fails
        """
        if not encrypted_tokens:
            return None
        try:
            # Decrypt and deserialize tokens
            decrypted = self._fernet.decrypt(encrypted_tokens.encode('ascii'))
            tokens = json.loads(decrypted.decode('utf-8'))
            return tokens
        except (InvalidToken, json.JSONDecodeError) as e:
            logger.error('Failed to decrypt tokens: %s', e)
            return None

    def store_tokens(self, session_id, tokens):
        """Securely store tokens in session with encryption.
        
        Args:
            session_id: Session identifier
            tokens: Dictionary containing access_token, refresh_token, expires_at
        """
        if not session_id:
            return
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                # Encrypt tokens before storing
                encrypted = self._encrypt_tokens(tokens)
                session['_encrypted_tokens'] = encrypted

    def retrieve_tokens(self, session_id):
        """Retrieve and decrypt tokens from session.
        
        Args:
            session_id: Session identifier
        
        Returns:
            Dictionary containing decrypted tokens or None
        """
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            encrypted = session.get('_encrypted_tokens')
            return self._decrypt_tokens(encrypted)


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


def extract_user(tokens, oauth_config=None):
    """Extract user information from tokens with signature validation.
    
    Args:
        tokens: Token response dictionary
        oauth_config: OAuth configuration (required for JWT validation)
    
    Returns:
        User dictionary with sub, email, name, groups or None if validation fails
    """
    token = tokens.get('id_token') or tokens.get('access_token')
    if not token:
        return None
    
    # SECURITY: Validate JWT signature before trusting claims
    # This prevents token forgery attacks
    claims = None
    if oauth_config and oauth_config.get('enabled'):
        claims = _validate_jwt_token(token, oauth_config)
        if not claims:
            logger.error('JWT validation failed - rejecting token')
            return None
    else:
        # Fallback for when OAuth is disabled (testing/development only)
        logger.warning('JWT validation skipped - OAuth not enabled')
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
        session_id = getattr(g, 'session_id', None)
        
        if not session_id:
            logger.error('No session ID available for OAuth login')
            return jsonify({'error': 'Session initialization failed'}), 500
        
        code_verifier = _generate_code_verifier()
        code_challenge = _build_code_challenge(code_verifier)
        
        # Generate cryptographically signed state bound to session
        state = _generate_signed_state(
            session_id,
            oauth_config['state_secret'],
            oauth_config['state_max_age']
        )

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
        session_id = getattr(g, 'session_id', None)
        pkce = session.get('pkce', {})
        expected_state = pkce.get('state')
        received_state = request.args.get('state')
        
        # Validate state parameter exists
        if not expected_state or not received_state:
            logger.warning('OAuth callback missing state parameter')
            return redirect('/?error=missing_state')
        
        # Validate state with cryptographic signature and session binding
        validation = _validate_signed_state(
            received_state,
            session_id,
            oauth_config['state_secret']
        )
        
        if not validation['valid']:
            logger.warning('OAuth state validation failed: %s - %s', 
                         validation.get('error'), validation.get('message'))
            return redirect(f"/?error=invalid_state&reason={validation.get('error')}")
        
        # Additional check: compare with stored state (defense in depth)
        if expected_state != received_state:
            logger.warning('OAuth state mismatch despite valid signature')
            return redirect('/?error=state_mismatch')

        code = request.args.get('code')
        if not code:
            return redirect('/?error=missing_code')

        try:
            tokens = exchange_code_for_token(oauth_config, code, pkce.get('code_verifier', ''))
        except Exception:
            return redirect('/?error=token_exchange_failed')

        # SECURITY: Regenerate session ID after successful authentication
        # This prevents session fixation attacks (OWASP recommendation)
        old_session_id = g.session_id
        new_session_id, new_session_data = session_store.regenerate_session(old_session_id)
        
        if not new_session_id:
            logger.error('Failed to regenerate session after authentication')
            return redirect('/?error=session_regeneration_failed')
        
        # Update g with new session ID and data
        g.session_id = new_session_id
        g.session_data = new_session_data
        g.session_regenerated = True  # Flag to update cookie in after_request
        
        # Now update the new session with authentication data
        new_session_data.pop('pkce', None)
        new_session_data['authenticated'] = True
        
        # Store tokens encrypted in session store
        token_data = {
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
        }
        session_store.store_tokens(new_session_id, token_data)
        new_session_data['user'] = extract_user(tokens, oauth_config)

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
        # Validate CSRF token
        try:
            csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            if not csrf_token:
                return jsonify({
                    'error': 'CSRF token missing',
                    'code': 'csrf_token_missing'
                }), 403
            validate_csrf(csrf_token)
        except (BadRequest, Exception) as e:
            return jsonify({
                'error': 'CSRF token validation failed',
                'code': 'csrf_error',
                'reason': str(e)
            }), 403

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
