#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Rate Limiting & Stealth
Controls request rates, delays, and stealth behaviors.
"""
import asyncio
import random
import time
from collections import defaultdict, deque
from typing import Optional
from core.config import Config
from core.logger import Logger


class RateLimiter:
    """
    Token bucket rate limiter with per-domain tracking.
    Ensures compliance with bug bounty program rate limits.
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("RateLimiter")
        self.rate = config.get("target", "rate_limit", default=10)  # req/sec
        self.stealth = config.get("stealth", "enabled", default=False)
        self.random_delays = config.get("stealth", "random_delays", default=True)

        # Per-domain token buckets
        self._buckets: dict = defaultdict(lambda: {"tokens": self.rate, "last_refill": time.monotonic()})
        self._lock = asyncio.Lock()

        # Request history for adaptive rate limiting
        self._request_times: dict = defaultdict(lambda: deque(maxlen=100))

    async def acquire(self, domain: str = "default"):
        """Acquire a rate limit token. Blocks if rate limit is exceeded."""
        async with self._lock:
            bucket = self._buckets[domain]
            now = time.monotonic()

            # Refill tokens
            elapsed = now - bucket["last_refill"]
            bucket["tokens"] = min(self.rate, bucket["tokens"] + elapsed * self.rate)
            bucket["last_refill"] = now

            if bucket["tokens"] < 1:
                wait = (1 - bucket["tokens"]) / self.rate
                self.logger.debug(f"Rate limit hit for {domain}. Waiting {wait:.2f}s")
                await asyncio.sleep(wait)
                bucket["tokens"] = 0
            else:
                bucket["tokens"] -= 1

        # Apply stealth delays
        if self.stealth and self.random_delays:
            delay = random.uniform(0.5, 2.0)
            await asyncio.sleep(delay)
        elif self.random_delays:
            await asyncio.sleep(random.uniform(0.05, 0.2))

    def adapt_rate(self, domain: str, response_time: float):
        """Adapt rate based on server response times (slow down if server is slow)."""
        if response_time > 5.0:
            current = self._buckets[domain]["tokens"]
            self._buckets[domain]["tokens"] = max(1, current * 0.8)
            self.logger.debug(f"Slowing down for {domain}: response time {response_time:.1f}s")


class StealthManager:
    """
    Stealth scanning manager. Manages all evasion techniques:
    - Random delays
    - Request ordering randomization
    - Human-like browsing patterns
    - Rate adaptation based on responses
    """

    def __init__(self, config: Config):
        self.config = config
        self.enabled = config.get("stealth", "enabled", default=False)
        self.rate_limiter = RateLimiter(config)

    async def pre_request(self, domain: str = "default"):
        """Call before each request to apply stealth behaviors."""
        await self.rate_limiter.acquire(domain)

    def randomize_order(self, items: list) -> list:
        """Randomize the order of items to appear more human-like."""
        if self.enabled:
            shuffled = items.copy()
            random.shuffle(shuffled)
            return shuffled
        return items
