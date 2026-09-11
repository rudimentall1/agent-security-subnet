"""Tests for the miner HTTP service's security controls.

Covers three things that had zero test coverage before this change:

1. verify_request() previously returned the miner's own configured hotkey
   instead of the actual caller's hotkey (bt.http_auth.verify()'s real
   return value, a Caller, was computed and silently discarded). This is
   fixed in bittensor_subnet/miner.py; these tests pin the fix.
2. ValidatorPermitChecker: any Bittensor wallet could previously call
   /generate -- only the request signature was checked, never subnet
   membership.
3. RateLimiter: there was no rate limiting at all on /generate.
"""

import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from bittensor_subnet.miner import (
    MinerConfig,
    MinerService,
    RateLimiter,
    ValidatorPermitChecker,
    create_app,
)
from subnet.stateful_target import build_target


class FakeCaller:
    def __init__(self, hotkey_ss58: str) -> None:
        self.hotkey_ss58 = hotkey_ss58
        self.nonce_ns = 0
        self.crypto_type = 0


def local_target_factory(_request):
    return build_target("privilege_boundary")


def make_service(**config_overrides) -> MinerService:
    config = MinerConfig(miner_id="miner-test", **config_overrides)
    return MinerService(config=config, target_factory=local_target_factory)


class TestVerifyRequestReturnsRealCaller(unittest.TestCase):
    def setUp(self):
        import os

        os.environ["VERITENSOR_MINER_HOTKEY_SS58"] = "5MinerOwnHotkey"

    def test_returns_actual_caller_not_miners_own_hotkey(self):
        service = make_service(require_auth=True)
        fake_request = Mock()
        fake_request.headers = {}
        fake_request.method = "POST"
        fake_request.url.path = "/generate"

        with patch(
            "bittensor_subnet.miner.bt.http_auth.verify",
            return_value=FakeCaller("5RealValidatorHotkey"),
        ):
            result = service.verify_request(fake_request, b"{}")

        self.assertEqual(
            result,
            "5RealValidatorHotkey",
            "verify_request must return the authenticated caller's hotkey, "
            "not the miner's own configured hotkey",
        )
        self.assertNotEqual(result, "5MinerOwnHotkey")


class TestValidatorPermitChecker(unittest.TestCase):
    def test_fails_closed_before_first_successful_refresh(self):
        checker = ValidatorPermitChecker(
            netuid=557,
            subtensor_factory=Mock(side_effect=RuntimeError("chain unreachable")),
        )
        self.assertFalse(checker.is_validator("5AnyHotkey"))

    def test_allows_hotkey_with_validator_permit_after_refresh(self):
        fake_neuron_validator = Mock(hotkey="5Validator", validator_permit=True)
        fake_neuron_miner = Mock(hotkey="5Miner", validator_permit=False)
        fake_sub = Mock()
        fake_sub.read.return_value = [fake_neuron_validator, fake_neuron_miner]

        checker = ValidatorPermitChecker(
            netuid=557,
            subtensor_factory=lambda: fake_sub,
        )

        self.assertTrue(checker.is_validator("5Validator"))
        self.assertFalse(checker.is_validator("5Miner"))
        self.assertFalse(checker.is_validator("5SomeRandomWallet"))

    def test_keeps_last_known_good_set_when_refresh_later_fails(self):
        fake_neuron = Mock(hotkey="5Validator", validator_permit=True)
        calls = {"n": 0}

        def flaky_factory():
            calls["n"] += 1
            if calls["n"] == 1:
                fake_sub = Mock()
                fake_sub.read.return_value = [fake_neuron]
                return fake_sub
            raise RuntimeError("chain temporarily unreachable")

        clock = {"t": 0.0}
        checker = ValidatorPermitChecker(
            netuid=557,
            refresh_interval_seconds=10.0,
            clock=lambda: clock["t"],
            subtensor_factory=flaky_factory,
        )

        self.assertTrue(checker.is_validator("5Validator"))  # first refresh succeeds

        clock["t"] = 20.0  # force a refresh attempt, which will fail
        self.assertTrue(
            checker.is_validator("5Validator"),
            "a later refresh failure must not drop a previously-known "
            "validator permit",
        )


class TestRateLimiter(unittest.TestCase):
    def test_allows_up_to_the_limit_then_blocks(self):
        clock = {"t": 0.0}
        limiter = RateLimiter(max_requests=2, window_seconds=60.0, clock=lambda: clock["t"])

        self.assertTrue(limiter.allow("5Hotkey"))
        self.assertTrue(limiter.allow("5Hotkey"))
        self.assertFalse(limiter.allow("5Hotkey"))

    def test_window_expiry_frees_up_capacity(self):
        clock = {"t": 0.0}
        limiter = RateLimiter(max_requests=1, window_seconds=10.0, clock=lambda: clock["t"])

        self.assertTrue(limiter.allow("5Hotkey"))
        self.assertFalse(limiter.allow("5Hotkey"))

        clock["t"] = 11.0
        self.assertTrue(
            limiter.allow("5Hotkey"),
            "requests outside the window must not count against the limit",
        )

    def test_limits_are_independent_per_key(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60.0)

        self.assertTrue(limiter.allow("5Validator1"))
        self.assertTrue(
            limiter.allow("5Validator2"),
            "one caller hitting its limit must not affect another caller",
        )


class TestMinerServiceEndToEndSecurityChecks(unittest.TestCase):
    """Wires permit-check + rate-limit through the real FastAPI app."""

    def setUp(self):
        import os

        os.environ["VERITENSOR_MINER_HOTKEY_SS58"] = "5MinerOwnHotkey"

    def _client_with(self, permit_checker=None, rate_limiter=None) -> TestClient:
        config = MinerConfig(miner_id="miner-test", require_auth=True)
        service = MinerService(
            config=config,
            target_factory=local_target_factory,
            permit_checker=permit_checker,
            rate_limiter=rate_limiter or RateLimiter(max_requests=1000, window_seconds=60),
        )

        from fastapi import FastAPI, HTTPException as _HTTPException, Request

        app = FastAPI()

        @app.post("/generate")
        async def generate(request: Request):
            body = await request.body()
            service.verify_request(request, body)
            return {"ok": True}

        return TestClient(app)

    def _post(self, client: TestClient, caller_hotkey: str):
        with patch(
            "bittensor_subnet.miner.bt.http_auth.verify",
            return_value=FakeCaller(caller_hotkey),
        ):
            return client.post("/generate", json={})

    def test_non_validator_caller_is_rejected(self):
        permit_checker = ValidatorPermitChecker(
            netuid=557,
            subtensor_factory=lambda: Mock(
                read=Mock(return_value=[Mock(hotkey="5Validator", validator_permit=True)])
            ),
        )
        client = self._client_with(permit_checker=permit_checker)

        response = self._post(client, "5RandomWalletNotAValidator")
        self.assertEqual(response.status_code, 403)

    def test_registered_validator_is_accepted(self):
        permit_checker = ValidatorPermitChecker(
            netuid=557,
            subtensor_factory=lambda: Mock(
                read=Mock(return_value=[Mock(hotkey="5Validator", validator_permit=True)])
            ),
        )
        client = self._client_with(permit_checker=permit_checker)

        response = self._post(client, "5Validator")
        self.assertEqual(response.status_code, 200)

    def test_rate_limit_returns_429(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = self._client_with(rate_limiter=limiter)

        first = self._post(client, "5Validator")
        second = self._post(client, "5Validator")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)


if __name__ == "__main__":
    unittest.main()
