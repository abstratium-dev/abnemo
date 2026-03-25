# OAuth Security Analysis - SECURITY_CHECK.md

**Date**: March 23, 2026  
**Scope**: OAuth 2.0 implementation in `src/oauth.py` and `src/web_server.py`  
**Severity**: 🔴 **CRITICAL VULNERABILITIES FOUND**

---

## Executive Summary

The OAuth implementation has **CRITICAL security vulnerabilities** that could allow attackers to:
1. **Steal access tokens and session cookies** via XSS attacks
2. **Perform unauthorized actions** via CSRF attacks
3. **Hijack user sessions** through session fixation
4. **Access sensitive data** stored in memory without encryption

---

## Critical Vulnerabilities

### 🔴 1. **NO CSRF PROTECTION ON STATE-CHANGING ENDPOINTS**

**Location**: `src/web_server.py` and other endpoint files  
**Severity**: CRITICAL  
**Attack Vector**: Cross-Site Request Forgery (CSRF)

#### Issue
The `/api/logout` endpoint (line 386-395 in `oauth.py`) and other POST endpoints have **NO CSRF token validation**. An attacker can craft a malicious link or embed a form on their website to perform actions on behalf of authenticated users.

```python
@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Clear authentication session."""
    if not oauth_config['enabled']:
        return jsonify({'success': True, 'oauth_enabled': False})

    session_id = getattr(g, 'session_id', None)
    session_store.delete(session_id)
    g.clear_session_cookie = True
    return jsonify({'success': True})
```

#### Attack Scenario
```html
<!-- Attacker's website -->
<img src="https://victim-abnemo.com/api/logout" style="display:none">
<!-- OR -->
<form action="https://victim-abnemo.com/api/logout" method="POST" id="evil">
<script>document.getElementById('evil').submit();</script>
```

When a logged-in user visits the attacker's page, they are automatically logged out. More dangerous: if there are other POST endpoints (IP banning, configuration changes), those could be triggered too.

#### Recommendation
- Implement CSRF tokens using Flask-WTF or similar
- Require `X-CSRF-Token` header for all state-changing requests
- Use SameSite=Strict cookies (currently Lax) for session cookies

---

### 🔴 2. **TOKENS STORED IN MEMORY WITHOUT ENCRYPTION**

**Location**: `src/oauth.py` lines 339-344  
**Severity**: CRITICAL  
**Attack Vector**: Memory dump, server compromise, debugging exposure

#### Issue
Access tokens, refresh tokens, and ID tokens are stored **in plaintext** in the in-memory session store:

```python
session['tokens'] = {
    'access_token': tokens.get('access_token'),
    'refresh_token': tokens.get('refresh_token'),
    'expires_at': (datetime.now(timezone.utc) + timedelta(seconds=tokens.get('expires_in', 3600))).isoformat()
}
```

#### Risks
1. **Memory dumps**: If the server crashes or is compromised, tokens are exposed
2. **Process inspection**: Anyone with access to the process can read tokens
3. **Logging leaks**: If session data is logged for debugging, tokens are exposed
4. **No token rotation**: Refresh tokens are stored but never used for rotation

#### Recommendation
- **Don't store tokens in session** - use them immediately and discard
- If storage is required, encrypt tokens with a server-side key
- Implement token rotation using refresh tokens
- Use short-lived sessions and re-authenticate frequently

---

### 🔴 3. **SESSION FIXATION VULNERABILITY**

**Location**: `src/web_server.py` lines 390-398  
**Severity**: HIGH  
**Attack Vector**: Session fixation attack

#### Issue
The session ID is created **before authentication** and reused after login:

```python
@app.before_request
def _load_bff_session():
    session_id = request.cookies.get(oauth_config['session_cookie_name'])
    session_data = session_store.get(session_id)
    if not session_data:
        session_id, session_data = session_store.create_session()
        g.session_is_new = True
    g.session_id = session_id
    g.session_data = session_data
```

#### Attack Scenario
1. Attacker visits the site and gets session ID `ABC123`
2. Attacker tricks victim into using the same session ID (via link or XSS)
3. Victim logs in with session ID `ABC123`
4. Attacker now has access to victim's authenticated session

#### Recommendation
- **Regenerate session ID after successful login**
- Invalidate old session ID when creating authenticated session
- Add session binding to IP address or User-Agent (with caution)

---

### 🔴 4. **NO HTTPONLY FLAG VERIFICATION FOR COOKIES**

**Location**: `src/web_server.py` lines 408-416  
**Severity**: HIGH  
**Attack Vector**: XSS-based cookie theft

#### Issue
While `httponly=True` is set, there's **no verification** that JavaScript cannot access the cookie. If there's any XSS vulnerability in the application, the session cookie could be stolen.

```python
response.set_cookie(
    oauth_config['session_cookie_name'],
    session_id,
    httponly=True,  # Good!
    secure=oauth_config['cookie_secure'],  # Configurable - BAD!
    samesite=oauth_config['cookie_samesite'],  # Lax - WEAK!
    max_age=oauth_config['session_ttl'],
    path='/'
)
```

#### Issues
1. **`secure` flag is optional** - defaults to `false` in development
2. **`samesite=Lax`** - allows cookies in GET requests from other sites
3. **No `Domain` restriction** - cookie could be sent to subdomains

#### Recommendation
- **Force `secure=True` in production** (fail if HTTPS not available)
- **Use `samesite=Strict`** for session cookies
- **Set explicit `Domain`** to prevent subdomain attacks
- Add Content-Security-Policy headers to prevent XSS

---

### 🟡 5. **JWT TOKENS NOT VALIDATED**

**Location**: `src/oauth.py` lines 43-53  
**Severity**: MEDIUM  
**Attack Vector**: Token forgery, tampering

#### Issue
JWT tokens are parsed **without signature verification**:

```python
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
```

The comment says "for display only" but the function is used for **authorization decisions**:
- Line 234: `claims = _parse_jwt_claims(token)` in `extract_user()`
- Line 257-271: User groups extracted from unverified claims

#### Attack Scenario
An attacker could:
1. Create a fake JWT with `"groups": ["admin"]`
2. Base64-encode it without a valid signature
3. Use it to bypass group-based access controls

#### Recommendation
- **Validate JWT signatures** using the OAuth provider's public key
- Use a library like `PyJWT` or `python-jose` for proper validation
- Verify `iss`, `aud`, `exp` claims
- Reject tokens with invalid signatures

---

### 🟡 6. **STATE PARAMETER NOT BOUND TO SESSION**

**Location**: `src/oauth.py` lines 315-326  
**Severity**: MEDIUM  
**Attack Vector**: CSRF on OAuth callback

#### Issue
The `state` parameter is validated but **not cryptographically bound** to the session:

```python
session = getattr(g, 'session_data', {})
pkce = session.get('pkce', {})
expected_state = pkce.get('state')
received_state = request.args.get('state')
if not expected_state or expected_state != received_state:
    return redirect('/?error=invalid_state')
```

#### Risks
1. State is stored in session, but session could be hijacked
2. No HMAC or signature to bind state to server secret
3. No timestamp validation (state could be replayed)

#### Recommendation
- Generate state as `HMAC(server_secret, session_id + timestamp)`
- Validate HMAC on callback
- Add expiration time to state (e.g., 5 minutes)

---

### 🟡 7. **MISSING SECURITY HEADERS**

**Location**: `src/web_server.py` - no security headers configured  
**Severity**: MEDIUM  
**Attack Vector**: XSS, clickjacking, MIME sniffing

#### Issue
The application does **not set critical security headers**:
- No `Content-Security-Policy` (allows inline scripts - XSS risk)
- No `X-Frame-Options` (clickjacking risk)
- No `X-Content-Type-Options` (MIME sniffing risk)
- No `Strict-Transport-Security` (HTTPS downgrade risk)

#### Recommendation
Add security headers middleware:
```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

### 🟡 8. **NO RATE LIMITING ON OAUTH ENDPOINTS**

**Location**: All OAuth endpoints  
**Severity**: MEDIUM  
**Attack Vector**: Brute force, DoS

#### Issue
No rate limiting on:
- `/oauth/login` - could be used for DoS
- `/oauth/callback` - could be brute-forced
- `/api/logout` - could be abused

#### Recommendation
- Implement rate limiting using Flask-Limiter
- Limit login attempts per IP
- Add exponential backoff for failed attempts

---

### 🟢 9. **GOOD: PKCE IMPLEMENTATION**

**Location**: `src/oauth.py` lines 27-40  
**Severity**: N/A (Positive finding)

#### Observation
The implementation correctly uses **PKCE (Proof Key for Code Exchange)** with SHA256:
- Code verifier generated with 32 bytes of randomness
- Code challenge properly computed
- Verifier sent during token exchange

This **prevents authorization code interception attacks**. ✅

---

### 🟢 10. **GOOD: SECURE RANDOM GENERATION**

**Location**: `src/oauth.py` line 138  
**Severity**: N/A (Positive finding)

#### Observation
Session IDs are generated using `secrets.token_urlsafe(32)` which is cryptographically secure. ✅

---

## Attack Scenarios Summary

### Scenario 1: Token Theft via XSS
1. Attacker finds XSS vulnerability in the application
2. Injects JavaScript to read session storage or make API calls
3. Steals access token from `/api/user` response or session
4. Uses token to access victim's data

**Likelihood**: HIGH (if XSS exists)  
**Impact**: CRITICAL

### Scenario 2: CSRF Logout Attack
1. Victim is logged into Abnemo
2. Attacker sends victim a link to malicious page
3. Malicious page triggers `POST /api/logout`
4. Victim is logged out (DoS attack)

**Likelihood**: HIGH  
**Impact**: MEDIUM

### Scenario 3: Session Fixation
1. Attacker gets session ID from their own browser
2. Tricks victim into using that session ID (via URL or XSS)
3. Victim logs in
4. Attacker uses the same session ID to access victim's account

**Likelihood**: MEDIUM  
**Impact**: CRITICAL

### Scenario 4: Forged JWT Attack
1. Attacker creates fake JWT with admin groups
2. Sends it to the application
3. Application accepts it without signature verification
4. Attacker gains unauthorized access

**Likelihood**: HIGH  
**Impact**: CRITICAL

---

## Token Storage Analysis

### Where are tokens stored?

1. **Server-side (in-memory)**:
   - Location: `MemorySessionStore._sessions` dictionary
   - Format: Plaintext
   - Encryption: ❌ None
   - Persistence: ❌ Lost on restart
   - Access: Anyone with process access

2. **Client-side**:
   - Location: HTTP-only cookie (session ID only)
   - Format: Session ID (not the token itself)
   - Encryption: ❌ None (just base64)
   - HttpOnly: ✅ Yes
   - Secure: ⚠️ Optional (configurable)
   - SameSite: ⚠️ Lax (should be Strict)

### Can tokens be stolen?

**YES**, in multiple ways:

1. **Memory dump**: If server is compromised, tokens are in plaintext
2. **Session hijacking**: If session cookie is stolen (XSS, network sniffing)
3. **CSRF**: If attacker can make requests on behalf of user
4. **Subdomain attack**: If `Domain` is not set properly
5. **HTTPS downgrade**: If `Secure` flag is not enforced

---

## Recommendations Priority

### 🔴 CRITICAL (Fix Immediately)

1. **Add CSRF protection** to all POST/PUT/DELETE endpoints
2. **Validate JWT signatures** before trusting claims
3. **Regenerate session ID** after successful login
4. **Encrypt tokens** in session store or don't store them
5. **Force `secure=True`** in production environments

### 🟡 HIGH (Fix Soon)

6. **Add security headers** (CSP, X-Frame-Options, etc.)
7. **Implement rate limiting** on authentication endpoints
8. **Use `SameSite=Strict`** for session cookies
9. **Add token expiration checks** before using stored tokens
10. **Implement refresh token rotation**

### 🟢 MEDIUM (Improve)

11. **Add session binding** (IP, User-Agent)
12. **Implement audit logging** for authentication events
13. **Add security monitoring** for suspicious activity
14. **Create security tests** for OAuth flows
15. **Document security assumptions** and threat model

---

## Compliance Notes

The `SECURITY.md` file claims:
- ✅ "OAuth 2.0 with PKCE" - TRUE (implemented correctly)
- ❌ "CSRF protection" - FALSE (state parameter only, no CSRF tokens)
- ❌ "CORS" - NOT FOUND (no CORS headers configured)
- ❌ "Content Security Policy" - FALSE (no CSP headers)
- ❌ "Security headers" - FALSE (no security headers)

**Compliance Status**: ⚠️ Claims do not match implementation

---

## Testing Recommendations

### Manual Tests

1. **CSRF Test**: Create HTML page with `<form>` to `/api/logout`, verify it works
2. **Session Fixation**: Set cookie before login, verify it changes after
3. **JWT Forgery**: Create fake JWT, verify it's rejected
4. **XSS Test**: Try to inject `<script>` in user inputs
5. **Cookie Theft**: Verify cookies have HttpOnly, Secure, SameSite

### Automated Tests

```python
def test_csrf_protection():
    # Should fail without CSRF token
    response = client.post('/api/logout')
    assert response.status_code == 403

def test_session_regeneration():
    # Session ID should change after login
    session_before = get_session_id()
    login()
    session_after = get_session_id()
    assert session_before != session_after

def test_jwt_validation():
    # Forged JWT should be rejected
    fake_jwt = create_fake_jwt(groups=['admin'])
    response = client.get('/api/user', headers={'Authorization': f'Bearer {fake_jwt}'})
    assert response.status_code == 401
```

---

## Conclusion

The OAuth implementation has **critical security vulnerabilities** that make it unsuitable for production use without significant improvements. The most critical issues are:

1. ❌ No CSRF protection
2. ❌ No JWT signature validation
3. ❌ Session fixation vulnerability
4. ❌ Tokens stored in plaintext

**Recommendation**: Do not deploy to production until these issues are fixed.

---

**Auditor Note**: This analysis was performed by examining the source code. A full penetration test would be recommended before production deployment.
