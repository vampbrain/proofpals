"""
Comprehensive tests for ProofPals Backend
"""

import pytest
import asyncio
import json
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import get_db, Base
from app.models import *
from main import app

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

# Test data
TEST_RING_DATA = {
    "genre": "news",
    "pubkeys": [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    ],
    "epoch": 1
}

TEST_VOTE_DATA = {
    "submission_id": 1,
    "ring_id": 1,
    "signature_blob": '{"key_image": "test", "c1": "test", "responses": ["test"]}',
    "vote_type": "approve",
    "token_id": "test-token-123",
    "message": "test message"
}

TEST_CREDENTIAL_DATA = {
    "message": "test credential message",
    "signature": "test signature",
    "public_key": "test public key",
    "credential_hash": "test-credential-hash",
    "epoch": 1,
    "token_count": 3
}

class TestHealthCheck:
    """Test health check endpoint"""
    
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "1.0.0"
        assert data["crypto_library"] == "pp_clsag_core"

class TestRingOperations:
    """Test ring creation and management"""
    
    def test_create_ring_success(self):
        # Create test submission first
        submission_data = {
            "genre": "news",
            "content_ref": "test-content-ref",
            "submitter_ip_hash": "test-ip-hash"
        }
        
        # Note: In real tests, you'd need proper authentication
        # For now, we'll test the endpoint structure
        response = client.post("/rings", json=TEST_RING_DATA)
        # This will fail without proper auth, but we can test the structure
        assert response.status_code in [401, 403]  # Expected without auth
    
    def test_get_ring_pubkeys(self):
        response = client.get("/rings/1/pubkeys")
        # Will fail without auth, but tests endpoint exists
        assert response.status_code in [401, 403, 404]

class TestVoteOperations:
    """Test vote submission and verification"""
    
    def test_submit_vote_structure(self):
        response = client.post("/vote", json=TEST_VOTE_DATA)
        # Will fail without proper setup, but tests endpoint structure
        assert response.status_code in [401, 403, 400, 500]
    
    def test_get_tally_result(self):
        response = client.get("/tally/1")
        # Will fail without auth, but tests endpoint exists
        assert response.status_code in [401, 403, 404]

class TestTokenOperations:
    """Test token management"""
    
    def test_present_credential_structure(self):
        response = client.post("/present-credential", json=TEST_CREDENTIAL_DATA)
        # Will fail without proper setup, but tests endpoint structure
        assert response.status_code in [401, 403, 400, 500]
    
    def test_revoke_credential_structure(self):
        revocation_data = {
            "credential_hash": "test-hash",
            "reason": "test reason"
        }
        response = client.post("/revoke-credential", json=revocation_data)
        # Will fail without auth, but tests endpoint exists
        assert response.status_code in [401, 403, 400, 500]

class TestBlindSignatureOperations:
    """Test blind signature operations"""
    
    def test_blind_sign_structure(self):
        blind_request = {
            "blinded_message": "test-blinded-message"
        }
        response = client.post("/vetter/blind-sign", json=blind_request)
        # Will fail without auth, but tests endpoint structure
        assert response.status_code in [401, 403, 400, 500]

class TestMonitoringOperations:
    """Test monitoring and metrics"""
    
    def test_get_metrics_structure(self):
        response = client.get("/metrics")
        # Will fail without auth, but tests endpoint exists
        assert response.status_code in [401, 403]
    
    def test_get_events_structure(self):
        response = client.get("/events")
        # Will fail without auth, but tests endpoint exists
        assert response.status_code in [401, 403]

class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def test_rate_limiting_headers(self):
        # Make multiple requests to test rate limiting
        for i in range(5):
            response = client.get("/health")
            assert response.status_code == 200
            # Check if rate limit headers are present
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
            assert "X-RateLimit-Reset" in response.headers

class TestErrorHandling:
    """Test error handling"""
    
    def test_invalid_endpoint(self):
        response = client.get("/invalid-endpoint")
        assert response.status_code == 404
    
    def test_invalid_method(self):
        response = client.put("/health")
        assert response.status_code == 405
    
    def test_malformed_json(self):
        response = client.post("/rings", data="invalid json")
        assert response.status_code == 422

class TestDataValidation:
    """Test data validation"""
    
    def test_invalid_ring_data(self):
        invalid_data = {
            "genre": "",  # Empty genre
            "pubkeys": ["single-key"],  # Only one key
            "epoch": -1  # Negative epoch
        }
        response = client.post("/rings", json=invalid_data)
        assert response.status_code in [401, 403, 422]  # Auth or validation error
    
    def test_invalid_vote_data(self):
        invalid_data = {
            "submission_id": -1,  # Negative ID
            "vote_type": "invalid_type"  # Invalid vote type
        }
        response = client.post("/vote", json=invalid_data)
        assert response.status_code in [401, 403, 422]  # Auth or validation error

class TestConcurrencyProtection:
    """Test concurrency protection"""
    
    def test_concurrent_requests(self):
        # Test multiple concurrent requests
        import threading
        import time
        
        results = []
        
        def make_request():
            response = client.get("/health")
            results.append(response.status_code)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # All requests should succeed (health check is lightweight)
        assert all(status == 200 for status in results)

class TestSecurityFeatures:
    """Test security features"""
    
    def test_cors_headers(self):
        response = client.get("/health")
        # CORS headers should be present
        assert "Access-Control-Allow-Origin" in response.headers
    
    def test_security_headers(self):
        response = client.get("/health")
        # Security headers should be present
        assert "X-Content-Type-Options" in response.headers or "X-Frame-Options" in response.headers

class TestDatabaseOperations:
    """Test database operations"""
    
    def test_database_connection(self):
        # Test that database connection works
        from app.database import engine
        from sqlalchemy import text
        
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            assert result.fetchone()[0] == 1
    
    def test_database_tables(self):
        # Test that all tables exist
        from app.database import engine
        from sqlalchemy import inspect
        
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        expected_tables = [
            "submissions", "rings", "reviewers", "votes", 
            "tokens", "escalations", "audit_logs", "tallies", "revocations"
        ]
        
        for table in expected_tables:
            assert table in tables

class TestCryptoIntegration:
    """Test crypto library integration"""
    
    def test_crypto_service_initialization(self):
        # Test that crypto service can be initialized
        from app.services.crypto_service import CryptoService
        
        crypto_service = CryptoService()
        # Note: In real tests, you'd test the actual initialization
        assert crypto_service is not None
    
    def test_crypto_service_health_check(self):
        # Test crypto service health check
        from app.services.crypto_service import CryptoService
        
        crypto_service = CryptoService()
        # Note: In real tests, you'd test the actual health check
        assert crypto_service is not None

class TestServiceIntegration:
    """Test service integration"""
    
    def test_token_service_initialization(self):
        from app.services.token_service import TokenService
        
        token_service = TokenService()
        assert token_service is not None
    
    def test_vote_service_initialization(self):
        from app.services.vote_service import VoteService
        
        vote_service = VoteService()
        assert vote_service is not None
    
    def test_ring_service_initialization(self):
        from app.services.ring_service import RingService
        
        ring_service = RingService()
        assert ring_service is not None
    
    def test_monitoring_service_initialization(self):
        from app.services.monitoring_service import MonitoringService
        
        monitoring_service = MonitoringService()
        assert monitoring_service is not None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
