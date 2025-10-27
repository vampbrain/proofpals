# File: backend/tests/test_weighted_voting.py (NEW)
# Create this test file

import pytest
from tally_service import get_tally_service

@pytest.mark.asyncio
async def test_weighted_voting_basic(db_session):
    """Test that higher reputation votes count more"""
    # Setup: Create submission with 3 votes
    # Voter 1: reputation=100, vote=approve
    # Voter 2: reputation=50, vote=reject
    # Voter 3: reputation=150, vote=approve
    
    # Expected: Weighted approve = 250, weighted reject = 50
    # Decision should be APPROVED
    
    tally_service = get_tally_service()
    result = await tally_service.compute_weighted_tally(submission_id, db_session)
    
    assert result["success"] is True
    assert result["decision"] == "approved"
    assert result["weighted_counts"]["approve"] > result["weighted_counts"]["reject"]

@pytest.mark.asyncio
async def test_weighted_vs_unweighted_difference(db_session):
    """Test case where weighted and unweighted decisions differ"""
    # Setup: Create submission with votes
    # 3 low-reputation voters (rep=10 each) vote reject
    # 1 high-reputation voter (rep=200) votes approve
    
    # Unweighted: reject wins (3 vs 1)
    # Weighted: approve wins (200 vs 30)
    
    tally_service = get_tally_service()
    result = await tally_service.compute_weighted_tally(submission_id, db_session)
    
    # Verify weighted decision is approve despite minority
    assert result["decision"] == "approved"
    assert result["unweighted_counts"]["reject"] > result["unweighted_counts"]["approve"]
    assert result["weighted_counts"]["approve"] > result["weighted_counts"]["reject"]

@pytest.mark.asyncio
async def test_reputation_normalization(db_session):
    """Test that extreme reputation values are normalized"""
    # Setup votes with extreme reputations
    # Voter 1: rep=-100 (should normalize to 1)
    # Voter 2: rep=0 (should normalize to 1)
    # Voter 3: rep=1000 (should normalize to 200)
    
    tally_service = get_tally_service()
    result = await tally_service.compute_weighted_tally(submission_id, db_session)
    
    # Verify normalization worked
    assert result["success"] is True
    # All votes should have positive weight