import time
from .schema import GraphState, TestResult, TestFailure

def execution_node(state: GraphState) -> dict:
    """
    Mock ExecutionAgent that simulates the Docker sandboxed testing environment.
    Pauses for 2 seconds to mimic I/O overhead before yielding a deterministic 
    failure, enabling us to test the LangGraph conditional routing logic loops.
    """
    
    # Simulate execution delay
    time.sleep(2)
    
    # Hardcode a deterministic failure to trigger Track A's DebugAgent
    mock_failure = TestFailure(
        test_name="test_theoretical_boundary_condition",
        error_message="AssertionError: Formal verification failed. Expected 42, got 0.",
        stack_trace="Traceback (most recent call last):\n  File 'test_synthesized_logic.py', line 14, in test_theoretical_boundary_condition\n    assert component_execution() == 42\nAssertionError: Formal verification failed. Expected 42, got 0."
    )
    
    mock_result = TestResult(
        success=False,
        total_tests=10,
        passed_tests=9,
        failed_tests=1,
        failures=[mock_failure],
        execution_time_seconds=2.0
    )
    
    return {
        "test_result": mock_result,
        "revision_count": state.revision_count + 1
    }
