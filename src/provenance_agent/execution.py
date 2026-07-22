from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: float = 0.05
    retryable_errors: tuple[type[Exception], ...] = (
        TimeoutError,
        ConnectionError,
        OSError,
    )

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay_seconds < 0:
            raise ValueError("base_delay_seconds cannot be negative")


@dataclass(frozen=True)
class RetryAttempt:
    attempt: int
    error_type: str
    error: str
    retrying: bool
    next_delay_seconds: float


class RetryExhaustedError(RuntimeError):
    def __init__(self, attempts: list[RetryAttempt], cause: Exception) -> None:
        super().__init__(
            f"Operation failed after {len(attempts)} attempt(s): {cause}"
        )
        self.attempts = attempts
        self.__cause__ = cause


def run_with_retry(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    on_attempt: Callable[[RetryAttempt], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    policy = policy or RetryPolicy()
    attempts: list[RetryAttempt] = []
    for attempt_number in range(1, policy.max_attempts + 1):
        try:
            return operation()
        except policy.retryable_errors as exc:
            retrying = attempt_number < policy.max_attempts
            delay = (
                policy.base_delay_seconds * (2 ** (attempt_number - 1))
                if retrying
                else 0.0
            )
            attempt = RetryAttempt(
                attempt=attempt_number,
                error_type=type(exc).__name__,
                error=str(exc),
                retrying=retrying,
                next_delay_seconds=delay,
            )
            attempts.append(attempt)
            if on_attempt:
                on_attempt(attempt)
            if not retrying:
                raise RetryExhaustedError(attempts, exc) from exc
            sleep(delay)
    raise AssertionError("retry loop exited without a result")
