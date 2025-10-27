"""
ProofPals Sybil Attack Simulator
Simulates various Sybil attack scenarios and measures resistance
"""

import asyncio
import random
import hashlib
from typing import List, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# Add parent directory to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

try:
    from database import get_db
    from models import Reviewer, Ring, Submission, Vote, Token
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False

try:
    import pp_clsag_core
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class AttackScenario:
    """Configuration for a Sybil attack scenario"""
    name: str
    num_honest_reviewers: int
    num_attacker_credentials: int
    ring_size: int
    target_submissions: int
    attack_strategy: str  # 'random', 'coordinated', 'targeted'
    attacker_reputation: int = 50  # Starting reputation for attackers


@dataclass
class AttackResult:
    """Results from a Sybil attack simulation"""
    scenario_name: str
    successful_attacks: int
    total_attempts: int
    success_rate: float
    avg_attacker_influence: float
    detection_rate: float
    cost_estimate: Dict[str, float]
    timestamp: str


class SybilAttackSimulator:
    """Simulates Sybil attacks on the ProofPals system"""
    
    def __init__(self):
        self.results = []
        self.honest_reviewers = []
        self.attacker_credentials = []
        
    async def setup_environment(self, scenario: AttackScenario, db):
        """Setup test environment for attack simulation"""
        print(f"\n📋 Setting up scenario: {scenario.name}")
        print(f"   Honest reviewers: {scenario.num_honest_reviewers}")
        print(f"   Attacker credentials: {scenario.num_attacker_credentials}")
        print(f"   Ring size: {scenario.ring_size}")
        
        # Create honest reviewers
        print("   Creating honest reviewers...")
        for i in range(scenario.num_honest_reviewers):
            cred_hash = hashlib.sha256(f"honest_reviewer_{i}".encode()).hexdigest()
            reviewer = Reviewer(
                credential_hash=cred_hash,
                reputation_score=100,  # Honest reviewers start with good reputation
                revoked=False,
                created_at=datetime.utcnow()
            )
            db.add(reviewer)
            self.honest_reviewers.append(cred_hash)
        
        # Create attacker credentials
        print("   Creating attacker credentials...")
        for i in range(scenario.num_attacker_credentials):
            cred_hash = hashlib.sha256(f"attacker_{i}".encode()).hexdigest()
            reviewer = Reviewer(
                credential_hash=cred_hash,
                reputation_score=scenario.attacker_reputation,
                revoked=False,
                created_at=datetime.utcnow()
            )
            db.add(reviewer)
            self.attacker_credentials.append(cred_hash)
        
        await db.commit()
        print("   ✅ Environment setup complete")
    
    async def simulate_credential_acquisition(
        self, 
        num_credentials: int
    ) -> Dict[str, float]:
        """
        Simulate cost of acquiring N credentials through vetter
        
        Returns cost estimates in different dimensions
        """
        # Cost model assumptions:
        # - KYC verification: $50 per attempt
        # - Document forgery: $500 per fake identity
        # - Time: 1 week per credential
        # - Risk of detection: increases with volume
        
        costs = {
            "monetary_usd": num_credentials * 550,  # KYC + forgery
            "time_weeks": num_credentials * 1,
            "detection_risk": min(0.9, 0.1 * num_credentials),  # 10% per credential, max 90%
            "technical_difficulty": "medium" if num_credentials < 10 else "high"
        }
        
        return costs
    
    async def simulate_attack(
        self,
        scenario: AttackScenario,
        db
    ) -> AttackResult:
        """Simulate a complete Sybil attack scenario"""
        
        print(f"\n🎯 Running attack simulation: {scenario.name}")
        
        successful_attacks = 0
        total_attempts = 0
        attacker_influences = []
        
        # Create test submissions
        submissions = []
        for i in range(scenario.target_submissions):
            submission = Submission(
                genre="test_genre",
                content_ref=f"test_submission_{i}",
                submitter_ip_hash=hashlib.sha256(f"submitter_{i}".encode()).hexdigest(),
                status="pending",
                created_at=datetime.utcnow()
            )
            db.add(submission)
            await db.flush()
            submissions.append(submission.id)
        
        await db.commit()
        
        # For each submission, calculate attacker influence
        for submission_id in submissions:
            total_attempts += 1
            
            # Determine how many attackers get into this ring
            total_reviewers = len(self.honest_reviewers) + len(self.attacker_credentials)
            expected_attackers = int((len(self.attacker_credentials) / total_reviewers) * scenario.ring_size)
            
            # Add some randomness
            num_attackers_in_ring = max(0, min(
                scenario.ring_size,
                expected_attackers + random.randint(-1, 1)
            ))
            
            # Calculate attacker influence
            influence = num_attackers_in_ring / scenario.ring_size
            attacker_influences.append(influence)
            
            # Simulate voting
            attacker_votes_approve = num_attackers_in_ring if scenario.attack_strategy == 'coordinated' else 0
            honest_in_ring = scenario.ring_size - num_attackers_in_ring
            honest_votes_approve = random.randint(0, honest_in_ring) if scenario.attack_strategy != 'coordinated' else random.randint(0, honest_in_ring)
            
            # Check if attackers achieved their goal
            if attacker_votes_approve > (scenario.ring_size - num_attackers_in_ring - honest_votes_approve):
                successful_attacks += 1
                print(f"   ⚠️  Submission {submission_id}: Attackers succeeded (influence: {influence:.2%})")
            else:
                print(f"   ✅ Submission {submission_id}: Attack failed (influence: {influence:.2%})")
        
        # Calculate metrics
        success_rate = successful_attacks / total_attempts if total_attempts > 0 else 0
        avg_influence = np.mean(attacker_influences) if (HAS_NUMPY and attacker_influences) else (sum(attacker_influences) / len(attacker_influences) if attacker_influences else 0)
        
        # Detection rate (simplified model)
        # Higher success rate = easier to detect coordinated behavior
        detection_rate = min(0.95, success_rate * 1.5) if success_rate > 0.3 else 0.1
        
        # Cost estimate
        cost_estimate = await self.simulate_credential_acquisition(
            scenario.num_attacker_credentials
        )
        
        result = AttackResult(
            scenario_name=scenario.name,
            successful_attacks=successful_attacks,
            total_attempts=total_attempts,
            success_rate=success_rate,
            avg_attacker_influence=avg_influence,
            detection_rate=detection_rate,
            cost_estimate=cost_estimate,
            timestamp=datetime.utcnow().isoformat()
        )
        
        self.results.append(result)
        
        print(f"\n📊 Results for {scenario.name}:")
        print(f"   Success rate: {success_rate:.1%}")
        print(f"   Average influence: {avg_influence:.1%}")
        print(f"   Detection rate: {detection_rate:.1%}")
        print(f"   Estimated cost: ${cost_estimate['monetary_usd']:,.0f}")
        
        return result
    
    def generate_report(self, output_file: str = "sybil_attack_report.json"):
        """Generate comprehensive report of all attack simulations"""
        
        # Calculate summary statistics
        if HAS_NUMPY:
            avg_success = np.mean([r.success_rate for r in self.results])
            avg_detection = np.mean([r.detection_rate for r in self.results])
        else:
            avg_success = sum([r.success_rate for r in self.results]) / len(self.results) if self.results else 0
            avg_detection = sum([r.detection_rate for r in self.results]) / len(self.results) if self.results else 0
        
        costs = [r.cost_estimate["monetary_usd"] for r in self.results]
        
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_scenarios": len(self.results),
            "scenarios": [
                {
                    "name": result.scenario_name,
                    "success_rate": result.success_rate,
                    "avg_influence": result.avg_attacker_influence,
                    "detection_rate": result.detection_rate,
                    "cost_usd": result.cost_estimate["monetary_usd"],
                    "cost_time_weeks": result.cost_estimate["time_weeks"],
                    "detection_risk": result.cost_estimate["detection_risk"]
                }
                for result in self.results
            ],
            "summary": {
                "avg_success_rate": avg_success,
                "avg_detection_rate": avg_detection,
                "total_cost_range": {
                    "min_usd": min(costs) if costs else 0,
                    "max_usd": max(costs) if costs else 0
                }
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Report generated: {output_file}")
        
        return report


# ============================================================================
# Test Scenarios
# ============================================================================

STANDARD_SCENARIOS = [
    AttackScenario(
        name="Small-scale attack (10 credentials, ring size 5)",
        num_honest_reviewers=50,
        num_attacker_credentials=10,
        ring_size=5,
        target_submissions=20,
        attack_strategy="coordinated"
    ),
    AttackScenario(
        name="Medium-scale attack (25 credentials, ring size 11)",
        num_honest_reviewers=100,
        num_attacker_credentials=25,
        ring_size=11,
        target_submissions=20,
        attack_strategy="coordinated"
    ),
    AttackScenario(
        name="Large-scale attack (50 credentials, ring size 11)",
        num_honest_reviewers=100,
        num_attacker_credentials=50,
        ring_size=11,
        target_submissions=20,
        attack_strategy="coordinated"
    ),
]


# ============================================================================
# Main Execution
# ============================================================================

async def run_all_scenarios():
    """Run all predefined attack scenarios"""
    
    print("="*80)
    print("ProofPals Sybil Attack Resistance Analysis")
    print("="*80)
    
    if not MODELS_AVAILABLE:
        print("⚠️  Models not available - using mock data")
        return None
    
    # Initialize simulator
    simulator = SybilAttackSimulator()
    
    # Run each scenario
    for scenario in STANDARD_SCENARIOS:
        print(f"\n{'='*80}")
        
        async for db in get_db():
            await simulator.setup_environment(scenario, db)
            result = await simulator.simulate_attack(scenario, db)
            await db.rollback()
            break
    
    # Generate report
    report = simulator.generate_report()
    
    print("\n" + "="*80)
    print("Summary of All Scenarios")
    print("="*80)
    print(f"Average attack success rate: {report['summary']['avg_success_rate']:.1%}")
    print(f"Average detection rate: {report['summary']['avg_detection_rate']:.1%}")
    print(f"Cost range: ${report['summary']['total_cost_range']['min_usd']:,.0f} - ${report['summary']['total_cost_range']['max_usd']:,.0f}")
    
    return report


if __name__ == "__main__":
    report = asyncio.run(run_all_scenarios())
    print("\n✅ Sybil resistance analysis complete!")

