import os
import pytest
from unittest.mock import patch, MagicMock, AsyncMock, PropertyMock

# ---------------------------------------------------------
# 1. ENVIRONMENT SETUP (Must happen before importing main)
# ---------------------------------------------------------
os.environ["JSON_SECRET_KEY"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
os.environ["KEYCLOAK_CLIENT_ID"] = "test-client"
os.environ["KEYCLOAK_CLIENT_SECRET"] = "test-secret"
os.environ["AUTH_SIG_SECRET"] = "test-sig-secret"
os.environ["SESSION_SECRET"] = "test-session-secret"

# Mock the K8s config loaders BEFORE importing main so the app starts locally
with patch("kubernetes.config.load_incluster_config"), patch("kubernetes.config.load_kube_config"):
    from main import (
        app, 
        k8s_api, 
        require_user, 
        verify_internal_token, 
        verify_token,
        _get_guac_auth_token
    )
    from fastapi.testclient import TestClient

client = TestClient(app)

# ---------------------------------------------------------
# 2. FIXTURES & DEPENDENCY OVERRIDES
# ---------------------------------------------------------

def mock_require_user():
    """Mock the authenticated user dependency."""
    return {
        "preferred_username": "testuser",
        "email": "testuser@example.com",
        "groups": ["researchers"]
    }

def mock_verify_internal_token():
    """Bypass the internal service account token check."""
    return True

@pytest.fixture(autouse=True)
def override_dependencies():
    """Automatically apply dependency overrides for all tests."""
    app.dependency_overrides[require_user] = mock_require_user
    app.dependency_overrides[verify_internal_token] = mock_verify_internal_token
    yield
    app.dependency_overrides.clear()

# ---------------------------------------------------------
# 3. PUBLIC & UNAUTHENTICATED ROUTES
# ---------------------------------------------------------

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "k8tre-portal"}

def test_logged_out_page():
    response = client.get("/logged-out")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

@patch("main.oauth.keycloak.authorize_redirect", new_callable=AsyncMock)
def test_login_redirect(mock_authorize_redirect):
    """Test that /login clears session and redirects to Keycloak."""
    mock_authorize_redirect.return_value = {"status": "redirected"}
    response = client.get("/login")
    # In a real TestClient, this triggers the mocked AsyncMock
    assert mock_authorize_redirect.called

# ---------------------------------------------------------
# 4. AUTHENTICATED ROUTES (MOCKING KUBERNETES)
# ---------------------------------------------------------

@patch("main.k8s_api.get_namespaced_custom_object")
def test_api_projects_success(mock_get_cr):
    """Test the /api/projects endpoint with mocked K8s CRDs."""
    
    # We need to mock 3 sequential K8s API calls: User -> Group -> Project
    mock_get_cr.side_effect = [
        {"spec": {"groups": ["test-group"]}},                            # User CR
        {"spec": {"projects": ["test-project"]}},                        # Group CR
        {"spec": {"description": "A test project", "apps": []}}          # Project CR
    ]
    
    response = client.get("/api/projects")
    assert response.status_code == 200
    data = response.json()
    assert "projects" in data
    assert len(data["projects"]) == 1
    assert data["projects"][0]["name"] == "test-project"
    assert data["projects"][0]["description"] == "A test project"

@patch("main.k8s_api.get_namespaced_custom_object")
def test_api_projects_user_not_found(mock_get_cr):
    """Test /api/projects when the K8s User CRD is missing."""
    mock_get_cr.side_effect = Exception("Not Found")
    
    response = client.get("/api/projects")
    assert response.status_code == 404
    assert "User CR not found" in response.json()["error"]

@patch("main.k8s_api.list_namespaced_custom_object")
def test_internal_projects(mock_list_cr):
    """Test internal project listing (protected by SA token)."""
    mock_list_cr.return_value = {
        "items": [
            {"metadata": {"name": "project-alpha"}},
            {"metadata": {"name": "project-beta"}}
        ]
    }
    
    # We bypass the SA token requirement using the dependency override defined earlier
    response = client.get("/internal/projects")
    assert response.status_code == 200
    assert response.json() == {"projects": [{"name": "project-alpha"}, {"name": "project-beta"}]}

# ---------------------------------------------------------
# 5. COMPLEX LOGIC & EXTERNAL CALLS (MOCKING HTTPX)
# ---------------------------------------------------------

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_guacamole_auth_token_generation(mock_post):
    """Test the encryption and external call to Guacamole for token generation."""
    
    # Mock the Guacamole API response
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"authToken": "mocked-guac-token-123"}
    mock_post.return_value = mock_response
    
    test_data = {"username": "testuser", "connections": {"conn1": {}}}
    
    token = await _get_guac_auth_token(test_data)
    
    assert token == "mocked-guac-token-123"
    assert mock_post.called
    
    # Verify the external API was called with the right headers
    call_args = mock_post.call_args
    assert "application/x-www-form-urlencoded" in call_args.kwargs["headers"]["Content-Type"]

# ---------------------------------------------------------
# 6. AUTH VALIDATOR MIDDLEWARE (CORE LOGIC)
# ---------------------------------------------------------

@patch("main.verify_token")
@patch("main._is_user_authorised_project")
def test_auth_validate_success(mock_is_auth, mock_verify_token):
    """Test the Nginx ingress /auth/validate endpoint."""
    # Mock valid token verification
    mock_verify_token.return_value = {
        "preferred_username": "testuser",
        "email": "test@example.com",
        "groups": ["group1"]
    }
    # Mock user having access to the requested project
    mock_is_auth.return_value = True
    
    # Pass the token and project exactly how Nginx ingress does: via the original URL header
    response = client.get(
        "/auth/validate",
        headers={"x-original-url": "/myapp?token=fake_jwt_token&project=test-project"}
    )
    
    assert response.status_code == 200
    
    # Check that it injected the correct Nginx headers
    headers = response.headers
    assert headers["Remote-User"] == "testuser"
    assert headers["X-Auth-Project"] == "test-project"
    assert "X-Auth-Signature" not in headers # Shouldn't have signature for non-hub paths

@patch("main.verify_token")
@patch("main._is_user_authorised_project")
def test_auth_validate_hub_route_generates_signatures(mock_is_auth, mock_verify_token):
    """Test that accessing /hub generates HMAC signatures in the headers."""
    mock_verify_token.return_value = {"preferred_username": "testuser"}
    mock_is_auth.return_value = True
    
    # Requesting a JupyterHub path via the Nginx original URL header
    response = client.get(
        "/auth/validate",
        headers={"x-original-url": "/hub/spawn?token=fake_jwt_token&project=test-project"}
    )
    
    assert response.status_code == 200
    assert "X-Auth-Stamp" in response.headers
    assert "X-Auth-Signature" in response.headers
    assert response.headers["X-Auth-Audience"] == "jupyterhub"

@patch("main.k8s_api.get_namespaced_custom_object")
def test_projects_html_success(mock_get_cr):
    """Test /projects HTML route loads successfully."""
    mock_get_cr.side_effect = [
        {"spec": {"groups": ["test-group"]}},                            # User CR
        {"spec": {"projects": ["test-project"]}},                        # Group CR
        {"spec": {"description": "A test project", "apps": []}}          # Project CR
    ]
    response = client.get("/projects")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

@patch("main.k8s_api.get_namespaced_custom_object")
def test_projects_html_user_not_found(mock_get_cr):
    """Test /projects HTML route shows error when User CR not found."""
    mock_get_cr.side_effect = Exception("Not Found")
    response = client.get("/projects")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Failed to resolve projects" in response.text

# ---------------------------------------------------------
# 7. LOGOUT AND SESSION CLEANUP
# ---------------------------------------------------------

@patch("main.revoke_user_tokens", new_callable=AsyncMock)
def test_logout(mock_revoke):
    """Test that /logout clears the session and revokes tokens."""
    response = client.get("/logout", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/logged-out"
    assert mock_revoke.called

@patch("main.revoke_user_tokens", new_callable=AsyncMock)
def test_api_cleanup_session(mock_revoke):
    """Test /api/cleanup-session triggers token revocation based on headers."""
    from main import active_user_sessions
    active_user_sessions["testuser"] = {"token": "t1", "refresh_token": "r1"}
    
    response = client.post("/api/cleanup-session", headers={"X-Auth-User": "testuser"})
    assert response.status_code == 200
    assert response.json() == {"status": "cleaned", "user": "testuser"}
    assert mock_revoke.called
    
    # cleanup after test
    active_user_sessions.pop("testuser", None)

# ---------------------------------------------------------
# 8. APPS AND VDI ROUTING
# ---------------------------------------------------------

@patch("main.k8s_api.get_namespaced_custom_object")
def test_get_apps_html_success(mock_get_cr):
    """Test /projects/{project}/apps HTML page."""
    mock_get_cr.return_value = {"spec": {"apps": [{"name": "jupyter", "type": "jupyter"}]}}
    response = client.get("/projects/test-project/apps")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "jupyter" in response.text

@patch("main.k8s_api.get_namespaced_custom_object")
def test_get_apps_json_success(mock_get_cr):
    """Test /api/projects/{project}/apps JSON endpoint."""
    mock_get_cr.return_value = {"spec": {"apps": [{"name": "jupyter", "type": "jupyter"}]}}
    response = client.get("/api/projects/test-project/apps")
    assert response.status_code == 200
    assert response.json()["apps"][0]["name"] == "jupyter"

@patch("main._is_user_authorised_project")
@patch("main.verify_token")
def test_auth_sso_success(mock_verify_token, mock_is_auth):
    """Test /auth/sso sets cookies and redirects."""
    mock_verify_token.return_value = {"preferred_username": "testuser", "email": "test@test.com"}
    mock_is_auth.return_value = True
    
    response = client.get("/auth/sso?token=fake-token&project=test-project&app=jupyter", follow_redirects=False)
    assert response.status_code == 307
    
    # Verify cookies were set
    set_cookie_headers = [h[1] for h in response.headers.raw if h[0] == b"set-cookie"]
    set_cookie_str = b"".join(set_cookie_headers).decode()
    assert "k8tre-project=test-project" in set_cookie_str
    assert "k8tre-auth-token-test-project=fake-token" in set_cookie_str

# ---------------------------------------------------------
# 9. VDI STATUS AND CONNECTION
# ---------------------------------------------------------

@patch("main.k8s_api.get_namespaced_custom_object")
def test_api_vdi_status_success(mock_get_cr):
    """Test VDI status endpoint returns phase and ready info."""
    mock_get_cr.return_value = {
        "status": {"phase": "Running", "password": "fake-password"}
    }
    
    response = client.get("/api/vdi/status/testuser/test-project")
    assert response.status_code == 200
    data = response.json()
    assert data["phase"] == "Running"
    assert data["has_password"] is True

@patch("main.k8s_api.get_namespaced_custom_object")
def test_api_vdi_status_wrong_user(mock_get_cr):
    """Test VDI status endpoint blocks mismatched users."""
    response = client.get("/api/vdi/status/wronguser/test-project")
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]

@patch("main._get_guac_auth_token", new_callable=AsyncMock)
@patch("main._build_connections_for_user")
def test_api_vdi_connect(mock_build_conns, mock_guac_token):
    """Test VDI connection endpoint generates Guacamole token."""
    mock_build_conns.return_value = {"test-project-desktop": {"protocol": "rdp"}}
    mock_guac_token.return_value = "guac-fake-token"
    
    response = client.get("/api/vdi/connect/testuser/test-project", follow_redirects=False)
    assert response.status_code == 307
    assert "token=guac-fake-token" in response.headers["location"]

@patch("main.k8s_api.delete_namespaced_custom_object")
def test_internal_vdi_delete(mock_delete):
    """Test internal VDI deletion route."""
    response = client.delete("/internal/vdi/testuser/test-project")
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"
    assert mock_delete.called

# ---------------------------------------------------------
# 10. REFRESH TOKEN API
# ---------------------------------------------------------

@patch("jwt.decode")
def test_api_refresh_token_valid(mock_decode):
    """Test /api/refresh-token when token is still valid."""
    import time
    mock_decode.return_value = {"exp": int(time.time()) + 1000}
    response = client.get("/api/refresh-token?current_token=valid&project=test&user=testuser")
    assert response.status_code == 200
    assert response.json()["status"] == "valid"

# ---------------------------------------------------------
# 11. LAUNCH APP Safeguard Tests
# ---------------------------------------------------------

@patch("main.ensure_valid_token", new_callable=AsyncMock)
@patch("main.k8s_api.get_namespaced_custom_object")
@patch("starlette.requests.Request.session", new_callable=PropertyMock)
def test_launch_non_vdi_app_outside_vdi(mock_session, mock_get_cr, mock_ensure_token):
    """Test that launching a non-VDI app outside a VDI context is blocked."""
    # Set session: vdi_context is False
    mock_session.return_value = {"vdi_context": False}
    
    # Mock project CR containing a non-VDI app (e.g. jupyter)
    mock_get_cr.return_value = {
        "spec": {
            "apps": [
                {"name": "jupyter", "type": "jupyter"}
            ]
        }
    }
    mock_ensure_token.return_value = "valid-token-123"
    
    response = client.get("/launch/test-project/jupyter")
    assert response.status_code == 200
    assert "VDI Session Required" in response.text
    assert "jupyter" in response.text


@patch("main.ensure_valid_token", new_callable=AsyncMock)
@patch("main.k8s_api.get_namespaced_custom_object")
@patch("starlette.requests.Request.session", new_callable=PropertyMock)
def test_launch_non_vdi_app_inside_vdi(mock_session, mock_get_cr, mock_ensure_token):
    """Test that launching a non-VDI app inside a VDI context succeeds (redirects)."""
    # Set session: vdi_context is True
    mock_session.return_value = {"vdi_context": True, "vdi_project": "test-project"}
    
    # Mock project CR containing a non-VDI app (e.g. jupyter)
    mock_get_cr.return_value = {
        "spec": {
            "apps": [
                {"name": "jupyter", "type": "jupyter"}
            ]
        }
    }
    mock_ensure_token.return_value = "valid-token-123"
    
    response = client.get("/launch/test-project/jupyter", follow_redirects=False)
    assert response.status_code == 307
    assert "/hub/login" in response.headers["location"]


@patch("main.client.CustomObjectsApi")
@patch("main.ensure_valid_token", new_callable=AsyncMock)
@patch("main.k8s_api.get_namespaced_custom_object")
@patch("starlette.requests.Request.session", new_callable=PropertyMock)
def test_launch_vdi_app_outside_vdi(mock_session, mock_get_cr, mock_ensure_token, mock_crd_client):
    """Test that launching a VDI app outside a VDI context succeeds (starts VDI and redirects)."""
    # Set session: vdi_context is False
    mock_session.return_value = {"vdi_context": False, "_session_id": "test-session-id"}
    
    # Mock project CR containing a VDI app
    mock_get_cr.return_value = {
        "spec": {
            "apps": [
                {"name": "vdi", "type": "vdi"}
            ]
        }
    }
    mock_ensure_token.return_value = "valid-token-123"
    
    # Mock custom object API creation
    mock_crd_inst = MagicMock()
    mock_crd_client.return_value = mock_crd_inst
    
    response = client.get("/launch/test-project/vdi", follow_redirects=False)
    assert response.status_code == 307
    assert "/vdi/status/testuser/test-project" in response.headers["location"]
    assert mock_crd_inst.create_namespaced_custom_object.called
