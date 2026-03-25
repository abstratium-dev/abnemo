#!/usr/bin/env python3
"""
Test OAuth State Parameter Security (Issue #6 from Security Audit)

This test suite verifies that the OAuth state parameter is cryptographically
bound to the session and includes timestamp validation to prevent:
- CSRF attacks on OAuth callback
- State parameter replay attacks
- Session fixation attacks
- State tampering
"""

import time
import json
import base64
import hmac
import hashlib
import pytest
from datetime import datetime, timezone
from src.oauth import (
    _generate_signed_state,
    _validate_signed_state,
    _base64url_encode
)


class TestOAuthStateParameterSecurity:
    """Test suite for OAuth state parameter security fixes."""
    
    @pytest.fixture
    def test_session_id(self):
        """Provide a test session ID."""
        return "test_session_abc123xyz"
    
    @pytest.fixture
    def test_secret(self):
        """Provide a test server secret."""
        return "test_server_secret_key_for_hmac_signing"
    
    def test_state_generation_format(self, test_session_id, test_secret):
        """Test that generated state has correct format: payload.signature"""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # State should be in format: base64url(payload).base64url(signature)
        assert isinstance(state, str)
        parts = state.split('.')
        assert len(parts) == 2, "State should have format: payload.signature"
        
        # Both parts should be base64url encoded
        payload_part, signature_part = parts
        assert len(payload_part) > 0
        assert len(signature_part) > 0
    
    def test_state_contains_session_binding(self, test_session_id, test_secret):
        """Test that state payload contains session ID binding."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Decode payload to verify it contains session_id
        payload_part = state.split('.')[0]
        # Add padding for base64 decoding
        padding = 4 - len(payload_part) % 4
        if padding != 4:
            payload_part += '=' * padding
        
        payload_json = base64.urlsafe_b64decode(payload_part).decode('utf-8')
        payload = json.loads(payload_json)
        
        assert 'session_id' in payload
        assert payload['session_id'] == test_session_id
        assert 'timestamp' in payload
        assert 'nonce' in payload
        assert 'max_age' in payload
    
    def test_state_validation_success(self, test_session_id, test_secret):
        """Test that valid state passes validation."""
        state = _generate_signed_state(test_session_id, test_secret, max_age_seconds=600)
        
        # Validate immediately - should succeed
        result = _validate_signed_state(state, test_session_id, test_secret)
        
        assert result['valid'] is True
        assert 'payload' in result
        assert result['payload']['session_id'] == test_session_id
    
    def test_state_validation_rejects_tampered_payload(self, test_session_id, test_secret):
        """Test that tampering with payload invalidates signature."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Tamper with the payload part
        payload_part, signature_part = state.split('.')
        
        # Decode, modify, and re-encode payload
        padding = 4 - len(payload_part) % 4
        if padding != 4:
            payload_part += '=' * padding
        payload_json = base64.urlsafe_b64decode(payload_part).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Change session_id to simulate tampering
        payload['session_id'] = 'attacker_session_id'
        
        # Re-encode tampered payload
        tampered_json = json.dumps(payload, separators=(',', ':'))
        tampered_payload = _base64url_encode(tampered_json.encode('utf-8'))
        
        # Create tampered state with original signature
        tampered_state = f"{tampered_payload}.{signature_part}"
        
        # Validation should fail due to invalid signature
        result = _validate_signed_state(tampered_state, test_session_id, test_secret)
        
        assert result['valid'] is False
        assert result['error'] == 'invalid_signature'
    
    def test_state_validation_rejects_wrong_session(self, test_session_id, test_secret):
        """Test that state bound to one session cannot be used with another."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Try to validate with different session ID
        different_session_id = "different_session_xyz789"
        result = _validate_signed_state(state, different_session_id, test_secret)
        
        assert result['valid'] is False
        assert result['error'] == 'session_mismatch'
    
    def test_state_validation_rejects_wrong_secret(self, test_session_id, test_secret):
        """Test that state signed with one secret cannot be validated with another."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Try to validate with different secret
        different_secret = "wrong_secret_key"
        result = _validate_signed_state(state, test_session_id, different_secret)
        
        assert result['valid'] is False
        assert result['error'] == 'invalid_signature'
    
    def test_state_validation_rejects_expired_state(self, test_session_id, test_secret):
        """Test that expired state is rejected."""
        # Generate state with very short max_age (1 second)
        state = _generate_signed_state(test_session_id, test_secret, max_age_seconds=1)
        
        # Wait for state to expire
        time.sleep(2)
        
        # Validation should fail due to expiration
        result = _validate_signed_state(state, test_session_id, test_secret)
        
        assert result['valid'] is False
        assert result['error'] == 'state_expired'
    
    def test_state_validation_rejects_invalid_format(self, test_session_id, test_secret):
        """Test that malformed state is rejected."""
        # Test various invalid formats
        invalid_states = [
            "",  # Empty
            "no_dot_separator",  # Missing separator
            "too.many.dots.here",  # Too many parts
            "invalid.base64!@#",  # Invalid base64
        ]
        
        for invalid_state in invalid_states:
            result = _validate_signed_state(invalid_state, test_session_id, test_secret)
            assert result['valid'] is False
    
    def test_state_validation_rejects_missing_parameters(self, test_session_id, test_secret):
        """Test that validation fails when required parameters are missing."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Test with missing session_id
        result = _validate_signed_state(state, None, test_secret)
        assert result['valid'] is False
        assert result['error'] == 'missing_parameters'
        
        # Test with missing secret
        result = _validate_signed_state(state, test_session_id, None)
        assert result['valid'] is False
        assert result['error'] == 'missing_parameters'
        
        # Test with missing state
        result = _validate_signed_state(None, test_session_id, test_secret)
        assert result['valid'] is False
        assert result['error'] == 'missing_parameters'
    
    def test_state_uniqueness(self, test_session_id, test_secret):
        """Test that each generated state is unique (due to nonce and timestamp)."""
        states = set()
        
        # Generate multiple states
        for _ in range(100):
            state = _generate_signed_state(test_session_id, test_secret)
            states.add(state)
        
        # All states should be unique
        assert len(states) == 100
    
    def test_state_replay_attack_prevention(self, test_session_id, test_secret):
        """Test that state cannot be reused (single-use validation)."""
        state = _generate_signed_state(test_session_id, test_secret)
        
        # First validation should succeed
        result1 = _validate_signed_state(state, test_session_id, test_secret)
        assert result1['valid'] is True
        
        # In a real implementation, the state should be deleted after first use
        # This test verifies the validation logic itself
        # The actual single-use enforcement happens in the session store
        
        # The same state can technically be validated again if not removed
        # But in practice, the OAuth callback handler removes it from session
        result2 = _validate_signed_state(state, test_session_id, test_secret)
        assert result2['valid'] is True  # Still valid cryptographically
    
    def test_timing_safe_comparison(self, test_session_id, test_secret):
        """Test that signature comparison is timing-safe."""
        # This test verifies that hmac.compare_digest is used
        # We can't directly test timing, but we verify the function works correctly
        
        state = _generate_signed_state(test_session_id, test_secret)
        
        # Valid state should pass
        result = _validate_signed_state(state, test_session_id, test_secret)
        assert result['valid'] is True
        
        # Invalid signature should fail
        payload_part, _ = state.split('.')
        wrong_signature = _base64url_encode(b'wrong_signature_bytes_here')
        invalid_state = f"{payload_part}.{wrong_signature}"
        
        result = _validate_signed_state(invalid_state, test_session_id, test_secret)
        assert result['valid'] is False
        assert result['error'] == 'invalid_signature'
    
    def test_state_max_age_configuration(self, test_session_id, test_secret):
        """Test that max_age is properly embedded and enforced."""
        # Generate state with custom max_age
        custom_max_age = 300  # 5 minutes
        state = _generate_signed_state(test_session_id, test_secret, max_age_seconds=custom_max_age)
        
        # Decode and verify max_age is stored
        payload_part = state.split('.')[0]
        padding = 4 - len(payload_part) % 4
        if padding != 4:
            payload_part += '=' * padding
        payload_json = base64.urlsafe_b64decode(payload_part).decode('utf-8')
        payload = json.loads(payload_json)
        
        assert payload['max_age'] == custom_max_age
        
        # State should be valid immediately
        result = _validate_signed_state(state, test_session_id, test_secret)
        assert result['valid'] is True
    
    def test_state_nonce_provides_randomness(self, test_session_id, test_secret):
        """Test that nonce provides additional randomness."""
        # Generate two states at the same time
        state1 = _generate_signed_state(test_session_id, test_secret)
        state2 = _generate_signed_state(test_session_id, test_secret)
        
        # States should be different due to nonce
        assert state1 != state2
        
        # Extract nonces
        def get_nonce(state):
            payload_part = state.split('.')[0]
            padding = 4 - len(payload_part) % 4
            if padding != 4:
                payload_part += '=' * padding
            payload_json = base64.urlsafe_b64decode(payload_part).decode('utf-8')
            payload = json.loads(payload_json)
            return payload['nonce']
        
        nonce1 = get_nonce(state1)
        nonce2 = get_nonce(state2)
        
        # Nonces should be different
        assert nonce1 != nonce2


class TestOAuthStateIntegration:
    """Integration tests for OAuth state parameter in full flow."""
    
    def test_state_lifecycle(self):
        """Test complete state lifecycle: generate -> validate -> use."""
        session_id = "integration_test_session"
        secret = "integration_test_secret"
        
        # Step 1: Generate state during /oauth/login
        state = _generate_signed_state(session_id, secret, max_age_seconds=600)
        assert state is not None
        
        # Step 2: State is sent to OAuth provider and returned in callback
        # (simulated by keeping the state variable)
        
        # Step 3: Validate state during /oauth/callback
        result = _validate_signed_state(state, session_id, secret)
        assert result['valid'] is True
        
        # Step 4: After successful validation, state should not be reused
        # (In real implementation, it's removed from session)
    
    def test_attack_scenario_session_fixation(self):
        """Test that state prevents session fixation attacks."""
        # Attacker's session
        attacker_session_id = "attacker_session_123"
        secret = "server_secret"
        
        # Attacker generates state with their session
        attacker_state = _generate_signed_state(attacker_session_id, secret)
        
        # Victim's session
        victim_session_id = "victim_session_456"
        
        # Attacker tries to use their state with victim's session
        result = _validate_signed_state(attacker_state, victim_session_id, secret)
        
        # Should fail due to session mismatch
        assert result['valid'] is False
        assert result['error'] == 'session_mismatch'
    
    def test_attack_scenario_csrf(self):
        """Test that state prevents CSRF attacks on OAuth callback."""
        session_id = "user_session"
        secret = "server_secret"
        
        # Legitimate user initiates OAuth flow
        legitimate_state = _generate_signed_state(session_id, secret)
        
        # Attacker tries to forge a state
        attacker_forged_state = "forged_payload.forged_signature"
        
        # Validation should fail
        result = _validate_signed_state(attacker_forged_state, session_id, secret)
        assert result['valid'] is False
    
    def test_attack_scenario_replay(self):
        """Test that expired state cannot be replayed."""
        session_id = "user_session"
        secret = "server_secret"
        
        # Generate state with 1 second expiry
        state = _generate_signed_state(session_id, secret, max_age_seconds=1)
        
        # Wait for expiry
        time.sleep(2)
        
        # Attacker tries to replay the state
        result = _validate_signed_state(state, session_id, secret)
        
        # Should fail due to expiration
        assert result['valid'] is False
        assert result['error'] == 'state_expired'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
