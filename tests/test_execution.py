"""Unit tests for bounded retry execution primitives.

Verifies policy validation, exponential delay bounds, complete attempt traces,
root-cause preservation, and immediate handling of non-transient failures.
"""

import pytest

from provenance_agent.execution import (
    RetryExhaustedError,
    RetryPolicy,
    run_with_retry,
)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"max_attempts": 0}, "max_attempts must be at least 1"),
        ({"base_delay_seconds": -0.1}, "base_delay_seconds cannot be negative"),
    ],
)
def test_retry_policy_rejects_unbounded_configuration(kwargs, message):
    with pytest.raises(ValueError, match=message):
        RetryPolicy(**kwargs)


def test_retry_uses_bounded_exponential_delays():
    calls = 0
    delays = []
    attempts = []

    def eventually_succeeds():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise TimeoutError(f"timeout {calls}")
        return "ok"

    result = run_with_retry(
        eventually_succeeds,
        policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.1),
        on_attempt=attempts.append,
        sleep=delays.append,
    )

    assert result == "ok"
    assert calls == 3
    assert delays == [0.1, 0.2]
    assert [attempt.attempt for attempt in attempts] == [1, 2]
    assert all(attempt.retrying for attempt in attempts)


def test_retry_exhaustion_preserves_every_attempt_and_root_cause():
    attempts = []

    def unavailable():
        raise ConnectionError("adapter unavailable")

    with pytest.raises(RetryExhaustedError) as error:
        run_with_retry(
            unavailable,
            policy=RetryPolicy(max_attempts=3, base_delay_seconds=0),
            on_attempt=attempts.append,
            sleep=lambda _: None,
        )

    assert [attempt.attempt for attempt in attempts] == [1, 2, 3]
    assert [attempt.retrying for attempt in attempts] == [True, True, False]
    assert error.value.attempts == attempts
    assert isinstance(error.value.__cause__, ConnectionError)


def test_non_transient_error_is_not_retried():
    attempts = []
    delays = []

    def invalid_contract():
        raise ValueError("invalid contract")

    with pytest.raises(ValueError, match="invalid contract"):
        run_with_retry(
            invalid_contract,
            on_attempt=attempts.append,
            sleep=delays.append,
        )

    assert attempts == []
    assert delays == []
