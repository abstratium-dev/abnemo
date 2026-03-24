#!/usr/bin/env python3
"""
Test suite for OAuth token encryption (Security Issue #2 fix)

This test ensures that tokens are encrypted in memory and cannot be accessed
in plaintext, protecting against memory dumps and process inspection attacks.
"""

import os
import json
import pytest
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet, InvalidToken
from src.oauth import MemorySessionStore


class TestTokenEncryption:
    """Test token encryption in MemorySessionStore"""

    def test_tokens_encrypted_in_memory(self):
        """Verify that tokens are stored encrypted, not in plaintext"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, session_data = store.create_session()
        
        # Sample tokens (similar to OAuth response)
        tokens = {
            'access_token': 'secret_access_token_12345',
            'refresh_token': 'secret_refresh_token_67890',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        # Store tokens
        store.store_tokens(session_id, tokens)
        
        # Verify tokens are NOT in plaintext in memory
        session = store._sessions[session_id]
        assert 'tokens' not in session, "Tokens should not be stored in 'tokens' key"
        assert '_encrypted_tokens' in session, "Encrypted tokens should be present"
        
        # Verify the encrypted data doesn't contain plaintext tokens
        encrypted_data = session['_encrypted_tokens']
        assert 'secret_access_token_12345' not in encrypted_data
        assert 'secret_refresh_token_67890' not in encrypted_data
        
    def test_token_encryption_decryption_roundtrip(self):
        """Verify tokens can be encrypted and decrypted correctly"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, session_data = store.create_session()
        
        original_tokens = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token',
            'expires_at': '2026-03-24T20:00:00+00:00'
        }
        
        # Store and retrieve tokens
        store.store_tokens(session_id, original_tokens)
        retrieved_tokens = store.retrieve_tokens(session_id)
        
        # Verify tokens match
        assert retrieved_tokens is not None
        assert retrieved_tokens['access_token'] == original_tokens['access_token']
        assert retrieved_tokens['refresh_token'] == original_tokens['refresh_token']
        assert retrieved_tokens['expires_at'] == original_tokens['expires_at']
        
    def test_encrypted_tokens_cannot_be_decrypted_with_wrong_key(self):
        """Verify that encrypted tokens cannot be decrypted with a different key"""
        store1 = MemorySessionStore(ttl_seconds=3600)
        store2 = MemorySessionStore(ttl_seconds=3600)
        
        session_id, _ = store1.create_session()
        
        tokens = {
            'access_token': 'secret_token',
            'refresh_token': 'secret_refresh',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        # Encrypt with store1
        store1.store_tokens(session_id, tokens)
        encrypted = store1._sessions[session_id]['_encrypted_tokens']
        
        # Try to decrypt with store2 (different key)
        decrypted = store2._decrypt_tokens(encrypted)
        
        # Should fail to decrypt
        assert decrypted is None
        
    def test_token_encryption_with_environment_key(self):
        """Verify that encryption uses environment variable key if provided"""
        # Generate a test key
        test_key = Fernet.generate_key().decode('ascii')
        os.environ['ABNEMO_TOKEN_ENCRYPTION_KEY'] = test_key
        
        try:
            store = MemorySessionStore(ttl_seconds=3600)
            session_id, _ = store.create_session()
            
            tokens = {
                'access_token': 'env_key_test_token',
                'refresh_token': 'env_key_refresh_token',
                'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            }
            
            # Store and retrieve
            store.store_tokens(session_id, tokens)
            retrieved = store.retrieve_tokens(session_id)
            
            assert retrieved is not None
            assert retrieved['access_token'] == tokens['access_token']
            
            # Verify the store is using the environment key
            assert store._fernet._signing_key == Fernet(test_key.encode())._signing_key
            
        finally:
            # Clean up environment
            del os.environ['ABNEMO_TOKEN_ENCRYPTION_KEY']
            
    def test_tokens_not_accessible_via_session_data(self):
        """Verify tokens cannot be accessed through normal session data access"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, session_data = store.create_session()
        
        tokens = {
            'access_token': 'hidden_access_token',
            'refresh_token': 'hidden_refresh_token',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        store.store_tokens(session_id, tokens)
        
        # Get session data (what application code would see)
        session = store.get(session_id)
        
        # Tokens should not be directly accessible
        assert 'access_token' not in session
        assert 'refresh_token' not in session
        assert 'tokens' not in session
        
    def test_token_deletion_on_session_delete(self):
        """Verify tokens are deleted when session is deleted"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, _ = store.create_session()
        
        tokens = {
            'access_token': 'to_be_deleted',
            'refresh_token': 'to_be_deleted_refresh',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        store.store_tokens(session_id, tokens)
        
        # Verify tokens are stored
        assert store.retrieve_tokens(session_id) is not None
        
        # Delete session
        store.delete(session_id)
        
        # Verify tokens are gone
        assert store.retrieve_tokens(session_id) is None
        
    def test_empty_tokens_handling(self):
        """Verify handling of None and empty token dictionaries"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, _ = store.create_session()
        
        # Test None tokens
        store.store_tokens(session_id, None)
        retrieved = store.retrieve_tokens(session_id)
        assert retrieved is None
        
        # Test empty dict
        store.store_tokens(session_id, {})
        retrieved = store.retrieve_tokens(session_id)
        assert retrieved is None or retrieved == {}
        
    def test_malformed_encrypted_data_handling(self):
        """Verify graceful handling of corrupted encrypted data"""
        store = MemorySessionStore(ttl_seconds=3600)
        
        # Test with invalid base64
        result = store._decrypt_tokens("not_valid_encrypted_data!!!")
        assert result is None
        
        # Test with valid base64 but invalid Fernet token
        result = store._decrypt_tokens("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=")
        assert result is None
        
    def test_token_encryption_preserves_data_types(self):
        """Verify that encryption/decryption preserves data types"""
        store = MemorySessionStore(ttl_seconds=3600)
        session_id, _ = store.create_session()
        
        tokens = {
            'access_token': 'string_token',
            'refresh_token': 'string_refresh',
            'expires_at': '2026-03-24T20:00:00+00:00',
            'expires_in': 3600,  # integer
            'scope': ['read', 'write'],  # list
            'metadata': {'key': 'value'}  # nested dict
        }
        
        store.store_tokens(session_id, tokens)
        retrieved = store.retrieve_tokens(session_id)
        
        assert isinstance(retrieved['access_token'], str)
        assert isinstance(retrieved['expires_in'], int)
        assert isinstance(retrieved['scope'], list)
        assert isinstance(retrieved['metadata'], dict)
        assert retrieved['metadata']['key'] == 'value'
        
    def test_multiple_sessions_independent_encryption(self):
        """Verify that multiple sessions have independently encrypted tokens"""
        store = MemorySessionStore(ttl_seconds=3600)
        
        # Create two sessions
        session_id1, _ = store.create_session()
        session_id2, _ = store.create_session()
        
        tokens1 = {
            'access_token': 'session1_token',
            'refresh_token': 'session1_refresh',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        tokens2 = {
            'access_token': 'session2_token',
            'refresh_token': 'session2_refresh',
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        }
        
        # Store tokens in both sessions
        store.store_tokens(session_id1, tokens1)
        store.store_tokens(session_id2, tokens2)
        
        # Retrieve and verify
        retrieved1 = store.retrieve_tokens(session_id1)
        retrieved2 = store.retrieve_tokens(session_id2)
        
        assert retrieved1['access_token'] == 'session1_token'
        assert retrieved2['access_token'] == 'session2_token'
        
        # Verify encrypted data is different
        encrypted1 = store._sessions[session_id1]['_encrypted_tokens']
        encrypted2 = store._sessions[session_id2]['_encrypted_tokens']
        assert encrypted1 != encrypted2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
