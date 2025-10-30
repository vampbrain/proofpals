
#!/usr/bin/env python3
"""
ProofPals Master Test Runner
Runs all comprehensive tests and generates final report
"""

import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'


def print_header(text):
    """Print formatted header"""
    print(f"\n{BLUE}{BOLD}{'='*80}")
    print(f"{text}")
    print(f"{'='*80}{RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓ {text}{RESET}")


def print_error(text):
    """Print error message"""
    print(f"{RED}✗ {text}{RESET}")


def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠ {text}{RESET}")


def run_test(script_name, description):
    """Run a test script"""
    print_header(f"Running: {description}")
    
    try:
        result = subprocess.run(
            [sys.executable, script_name],
            cwd=Path(__file__).parent,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        print(result.stdout)
        
        if result.returncode == 0:
            print_success(f"{description} completed successfully")
            return True, result.stdout
        else:
            print_error(f"{description} failed with code {result.returncode}")
            if result.stderr:
                print(f"Error output:\n{result.stderr}")
            return False, result.stderr
    
    except subprocess.TimeoutExpired:
        print_error(f"{description} timed out after 5 minutes")
        return False, "Timeout"
    
    except Exception as e:
        print_error(f"{description} failed with exception: {e}")
        return False, str(e)


def check_prerequisites():
    """Check if all prerequisites are met"""
    print_header("Checking Prerequisites")
    
    checks = {
        "Python 3.11+": sys.version_info >= (3, 11),
        "Backend directory": Path("backend").exists(),
        "Database config": Path("backend/.env").exists(),
    }
    
    all_passed = True
    for check, passed in checks.items():
        if passed:
            print_success(check)
        else:
            print_error(check)
            all_passed = False
    
    # Check if server is running
    import requests
    try:
        response = requests.get("http://localhost:8000/health", timeout=2)
        if response.status_code == 200:
            print_success("Backend server is running")
        else:
            print_error(f"Backend server returned status {response.status_code}")
            all_passed = False
    except Exception as e:
        print_error(f"Backend server not reachable: {e}")
        all_passed = False
    
    # Check crypto library
    try:
        import pp_clsag_core
        print_success("Crypto library (pp_clsag_core) is available")
    except ImportError:
        print_error("Crypto library not available")
        all_passed = False
    
    return all_passed


def generate_final_report(results):
    """Generate final comprehensive report"""
    print_header("FINAL TEST REPORT")
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"Generated: {timestamp}\n")
    
    # Test results
    print(f"{BOLD}Test Results:{RESET}")
    for test_name, (passed, output) in results.items():
        status = f"{GREEN}PASSED{RESET}" if passed else f"{RED}FAILED{RESET}"
        print(f"  {test_name}: {status}")
    
    # Summary
    total = len(results)
    passed = sum(1 for p, _ in results.values() if p)
    failed = total - passed
    
    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Total tests: {total}")
    print(f"  Passed: {GREEN}{passed}{RESET}")
    print(f"  Failed: {RED}{failed}{RESET}")
    
    # Overall status
    if failed == 0:
        print(f"\n{GREEN}{BOLD}✅ ALL TESTS PASSED!{RESET}")
        print(f"\n{GREEN}Your backend is ready for production!{RESET}")
        print(f"\n{BOLD}Next steps:{RESET}")
        print(f"  1. Review the detailed performance report")
        print(f"  2. Check sybil_attack_report.json for resistance analysis")
        print(f"  3. Share backend API docs with frontend developer")
        print(f"  4. Provide API endpoint: http://localhost:8000")
        print(f"  5. Share OpenAPI docs: http://localhost:8000/docs")
    else:
        print(f"\n{RED}{BOLD}❌ SOME TESTS FAILED{RESET}")
        print(f"\nPlease review the failures above and fix issues before proceeding.")
    
    # Save report
    report_file = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w') as f:
        f.write(f"ProofPals Test Report\n")
        f.write(f"Generated: {timestamp}\n\n")
        f.write(f"Test Results:\n")
        for test_name, (passed, output) in results.items():
            f.write(f"\n{'='*80}\n")
            f.write(f"{test_name}: {'PASSED' if passed else 'FAILED'}\n")
            f.write(f"{'='*80}\n")
            f.write(output[:5000])  # Limit output size
            f.write("\n\n")
        
        f.write(f"\nSummary:\n")
        f.write(f"Total: {total}, Passed: {passed}, Failed: {failed}\n")
    
    print(f"\n📄 Full report saved to: {report_file}")


def main():
    """Main test runner"""
    print_header("ProofPals Comprehensive Test Suite")
    
    # Check prerequisites
    if not check_prerequisites():
        print_error("Prerequisites check failed. Please fix issues and try again.")
        return 1
    
    # Define tests
    tests = [
        ("five_person_test.py", "5-Person Voting Scenarios"),
        ("sybil_attack_test.py", "Sybil Attack Resistance"),
        ("performance_metrics.py", "Performance Metrics & Benchmarks"),
    ]
    
    # Ask user which tests to run
    print(f"\n{BOLD}Available tests:{RESET}")
    for i, (_, description) in enumerate(tests, 1):
        print(f"  {i}. {description}")
    print(f"  {len(tests)+1}. Run all tests")
    
    try:
        choice = input(f"\n{BOLD}Select test to run (1-{len(tests)+1}): {RESET}").strip()
        choice_num = int(choice)
    except (ValueError, KeyboardInterrupt):
        print("\nAborted.")
        return 1
    
    # Run selected tests
    results = {}
    
    if choice_num == len(tests) + 1:
        # Run all tests
        for script, description in tests:
            passed, output = run_test(script, description)
            results[description] = (passed, output)
    elif 1 <= choice_num <= len(tests):
        # Run single test
        script, description = tests[choice_num - 1]
        passed, output = run_test(script, description)
        results[description] = (passed, output)
    else:
        print_error("Invalid choice")
        return 1
    
    # Generate report
    generate_final_report(results)
    
    # Return exit code
    return 0 if all(p for p, _ in results.values()) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Test suite interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}Fatal error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

