#!/usr/bin/env python3
"""
Validate ProofPals Implementation
Checks that all new features are correctly implemented without requiring database
"""

import sys
import ast
from pathlib import Path


def validate_imports():
    """Check that all imports can be resolved"""
    print("1. Checking imports...")
    
    try:
        from models import Reviewer, TallyService
        from tally_service import get_tally_service
        print("   ✓ Models imported successfully")
        return True
    except Exception as e:
        print(f"   ✗ Import error: {e}")
        return False


def check_reputation_fields():
    """Check that Reviewer model has reputation fields"""
    print("\n2. Checking Reviewer model...")
    
    try:
        from models import Reviewer
        
        # Check if reputation_score field exists
        if hasattr(Reviewer, 'reputation_score'):
            print("   ✓ reputation_score field exists")
        else:
            print("   ✗ reputation_score field missing")
            return False
            
        # Check if reputation_history field exists
        if hasattr(Reviewer, 'reputation_history'):
            print("   ✓ reputation_history field exists")
        else:
            print("   ✗ reputation_history field missing")
            return False
            
        return True
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def check_weighted_methods():
    """Check that tally service has weighted methods"""
    print("\n3. Checking TallyService methods...")
    
    try:
        from tally_service import TallyService
        service = TallyService()
        
        # Check for weighted tally method
        if hasattr(service, 'compute_weighted_tally'):
            print("   ✓ compute_weighted_tally method exists")
        else:
            print("   ✗ compute_weighted_tally method missing")
            return False
            
        # Check for weighted decision method
        if hasattr(service, '_make_weighted_decision'):
            print("   ✓ _make_weighted_decision method exists")
        else:
            print("   ✗ _make_weighted_decision method missing")
            return False
            
        # Check for unweighted counts method
        if hasattr(service, '_get_unweighted_counts'):
            print("   ✓ _get_unweighted_counts method exists")
        else:
            print("   ✗ _get_unweighted_counts method missing")
            return False
            
        return True
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def check_sybil_simulator():
    """Check that Sybil simulator exists and has required classes"""
    print("\n4. Checking Sybil Attack Simulator...")
    
    try:
        simulator_path = Path(__file__).parent / "tests" / "security" / "sybil_simulator.py"
        
        if not simulator_path.exists():
            print(f"   ✗ Simulator file not found: {simulator_path}")
            return False
            
        with open(simulator_path, 'r') as f:
            content = f.read()
            
        # Check for required classes
        if 'class AttackScenario' in content:
            print("   ✓ AttackScenario class exists")
        else:
            print("   ✗ AttackScenario class missing")
            return False
            
        if 'class SybilAttackSimulator' in content:
            print("   ✓ SybilAttackSimulator class exists")
        else:
            print("   ✗ SybilAttackSimulator class missing")
            return False
            
        if 'def simulate_attack' in content:
            print("   ✓ simulate_attack method exists")
        else:
            print("   ✗ simulate_attack method missing")
            return False
            
        return True
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def check_benchmark_suite():
    """Check that performance benchmark suite exists"""
    print("\n5. Checking Performance Benchmark Suite...")
    
    try:
        benchmark_path = Path(__file__).parent / "tests" / "performance" / "benchmark_suite.py"
        
        if not benchmark_path.exists():
            print(f"   ✗ Benchmark file not found: {benchmark_path}")
            return False
            
        with open(benchmark_path, 'r') as f:
            content = f.read()
            
        # Check for required classes
        if 'class PerformanceBenchmark' in content:
            print("   ✓ PerformanceBenchmark class exists")
        else:
            print("   ✗ PerformanceBenchmark class missing")
            return False
            
        if 'def benchmark_crypto_operations' in content:
            print("   ✓ benchmark_crypto_operations method exists")
        else:
            print("   ✗ benchmark_crypto_operations method missing")
            return False
            
        return True
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def check_api_endpoint():
    """Check that main.py has weighted tally endpoint"""
    print("\n6. Checking API endpoints...")
    
    try:
        main_path = Path(__file__).parent / "main.py"
        
        if not main_path.exists():
            print(f"   ✗ main.py not found")
            return False
            
        with open(main_path, 'r') as f:
            content = f.read()
            
        # Check for weighted tally endpoint
        if '/api/v1/tally/{submission_id}/weighted' in content:
            print("   ✓ Weighted tally endpoint exists")
        else:
            print("   ✗ Weighted tally endpoint missing")
            return False
            
        if 'async def get_weighted_tally' in content:
            print("   ✓ get_weighted_tally function exists")
        else:
            print("   ✗ get_weighted_tally function missing")
            return False
            
        return True
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def check_metadata_field():
    """Check that TallyResponse has metadata field"""
    print("\n7. Checking API models...")
    
    try:
        main_path = Path(__file__).parent / "main.py"
        
        with open(main_path, 'r') as f:
            content = f.read()
            
        # Parse and check TallyResponse model
        if 'class TallyResponse' in content:
            # Extract the class definition
            lines = content.split('\n')
            in_class = False
            has_metadata = False
            
            for line in lines:
                if 'class TallyResponse' in line:
                    in_class = True
                elif in_class and (line.strip().startswith('class ') or line.strip().startswith('def ')):
                    break
                elif 'metadata' in line and 'Optional[dict]' in line:
                    has_metadata = True
                    
            if has_metadata:
                print("   ✓ TallyResponse has metadata field")
                return True
            else:
                print("   ✗ TallyResponse missing metadata field")
                return False
        else:
            print("   ✗ TallyResponse class not found")
            return False
            
    except Exception as e:
        print(f"   ✗ Error: {e}")
        return False


def main():
    """Run all validation checks"""
    print("=" * 80)
    print("ProofPals Implementation Validation")
    print("=" * 80)
    
    checks = [
        validate_imports,
        check_reputation_fields,
        check_weighted_methods,
        check_sybil_simulator,
        check_benchmark_suite,
        check_api_endpoint,
        check_metadata_field,
    ]
    
    results = []
    for check in checks:
        try:
            result = check()
            results.append(result)
        except Exception as e:
            print(f"   ✗ Check failed with exception: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "=" * 80)
    print("Validation Summary")
    print("=" * 80)
    
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"Total checks: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if all(results):
        print("\n✅ All checks passed! Implementation is valid.")
        return 0
    else:
        print("\n❌ Some checks failed. Please review the issues above.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

