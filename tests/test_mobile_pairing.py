"""Volatile pairing checks; credentials never leave memory in these tests."""
from __future__ import annotations

import unittest

from xnet.mobile_pairing import PairingAuthority, PairingError


class Entropy:
    def __init__(self):
        self.value = 0

    def __call__(self, size):
        self.value += 1
        return bytes([self.value]) * size


class MobilePairingTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000]
        self.authority = PairingAuthority(clock=lambda: self.now[0], random_bytes=Entropy(),
                                          code_ttl_seconds=30, token_ttl_seconds=60)

    def pair(self, *, address="100.64.4.2"):
        invitation = self.authority.issue()
        credential = self.authority.redeem(code=invitation.code, device_id="iphone-1",
                                           device_name="Felix iPhone", bound_address=address)
        return invitation, credential

    def test_pairing_code_is_single_use_and_secret_representations_are_redacted(self):
        invitation, credential = self.pair()
        self.assertNotIn(invitation.code, repr(invitation))
        self.assertNotIn(credential.bearer_token, repr(credential))
        principal = self.authority.authenticate(credential.bearer_token,
                                                bound_address="100.64.4.2")
        self.assertEqual(principal.device_id, "iphone-1")
        with self.assertRaisesRegex(PairingError, "already used"):
            self.authority.redeem(code=invitation.code, device_id="iphone-2",
                                  device_name="Other", bound_address="100.64.4.3")

    def test_pairing_and_tokens_expire_without_refresh(self):
        invitation = self.authority.issue()
        self.now[0] = invitation.expires_at
        with self.assertRaises(PairingError):
            self.authority.redeem(code=invitation.code, device_id="iphone-1",
                                  device_name="Phone", bound_address="100.64.4.2")
        self.now[0] = 2000
        _, credential = self.pair()
        self.now[0] = credential.expires_at
        with self.assertRaises(PairingError):
            self.authority.authenticate(credential.bearer_token,
                                        bound_address="100.64.4.2")
        self.assertEqual(self.authority.active_device_ids(), ())

    def test_credential_is_address_bound_and_revocable(self):
        _, credential = self.pair()
        with self.assertRaises(PairingError):
            self.authority.authenticate(credential.bearer_token,
                                        bound_address="100.64.4.9")
        self.assertTrue(self.authority.revoke_device("iphone-1"))
        self.assertFalse(self.authority.revoke_device("iphone-1"))
        with self.assertRaises(PairingError):
            self.authority.authenticate(credential.bearer_token,
                                        bound_address="100.64.4.2")

    def test_existing_device_must_be_revoked_before_repairing(self):
        self.pair()
        second = self.authority.issue()
        with self.assertRaisesRegex(PairingError, "already paired"):
            self.authority.redeem(code=second.code, device_id="iphone-1",
                                  device_name="Renamed", bound_address="100.64.4.2")
        self.assertTrue(self.authority.revoke_device("iphone-1"))
        credential = self.authority.redeem(code=second.code, device_id="iphone-1",
                                           device_name="Renamed", bound_address="100.64.4.2")
        self.assertEqual(credential.device_name, "Renamed")

    def test_public_loopback_and_hostname_binding_are_refused(self):
        for address in ("127.0.0.1", "8.8.8.8", "phone.example"):
            invitation = self.authority.issue()
            with self.subTest(address=address), self.assertRaises(PairingError):
                self.authority.redeem(code=invitation.code, device_id="iphone-1",
                                      device_name="Phone", bound_address=address)


if __name__ == "__main__":
    unittest.main()
