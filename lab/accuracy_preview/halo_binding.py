"""Explicit staged/active current-profile and launch-process HALO binding."""
from dataclasses import asdict
import json
from pathlib import Path
from frozen_integrations import adapter, halo


class HaloBinding:
    def __init__(self, proposal_path=None, *, mode="staged", observer=None):
        if mode not in {"staged", "active"}: raise adapter.AdapterError("HALO mode must be explicit")
        self.mode, self.observer, self.registry = mode, observer, None
        self.path, self.receipt, self.source_hash = None, None, None
        if proposal_path is not None:
            self.path = Path(proposal_path).resolve()
            if self.path.stat().st_size > 65536: raise adapter.AdapterError("HALO proposal exceeds bound")
            raw = self.path.read_bytes(); self.source_hash = adapter.digest(raw); self.receipt = json.loads(raw)
            self.profile = halo.EngineProfile(**self.receipt["profile"])
            proposal = self.receipt["proposal"] | {"evidence_sha256s": tuple(self.receipt["proposal"]["evidence_sha256s"])}
            self.proposal = halo.ContextPinProposal(**proposal)
            self.proposal.validate_for(self.profile)
            if self.receipt["profile_sha256"] != self.profile.sha256 or self.proposal.review_tokens != 6400 or \
                    self.profile.generation_reserve_tokens != 1300:
                raise adapter.AdapterError("HALO proposal does not bind the preview pin/reserve")
        if mode == "active":
            if self.receipt is None or not callable(observer):
                raise adapter.AdapterError("active HALO requires actual current runtime observer and proposal")
            self.registry = halo.HaloPinRegistry(); self.registry.register(self.profile, self.proposal)
            self.verify()

    def plan(self):
        return {"mode": self.mode, "active": self.registry is not None, "proposal_sha256": self.source_hash,
                "profile_sha256": None if self.receipt is None else self.profile.sha256,
                "identity_basis": "staged-only" if self.mode == "staged" else "caller-attested-actual-current-profile-and-process",
                "reasoning_quality_claim": False}

    def verify(self):
        if self.path is not None and adapter.digest(self.path.read_bytes()) != self.source_hash:
            raise adapter.AdapterError("HALO proposal source drift")
        if self.registry is None: return None
        observed = self.observer()
        if not isinstance(observed, dict) or observed.get("artifact_pins_verified") is not True or \
                observed.get("attestation_kind") != "actual-current-profile-and-process" or \
                observed.get("profile") != asdict(self.profile) or \
                observed.get("runtime_process_binding") != self.receipt["runtime_process_binding"]:
            raise adapter.AdapterError("HALO actual model/tokenizer/template/configuration or launch PID/start pins drifted")
        runtime = observed["runtime_process_binding"]
        if runtime.get("profile_sha256") != self.profile.sha256 or runtime.get("runtime_bundle_sha256") != self.profile.runner_bundle_sha256 or \
                not runtime.get("process_id") or not runtime.get("process_started_at_utc") or not runtime.get("actual_command_sha256"):
            raise adapter.AdapterError("HALO complete runtime process binding is required")
        return self.profile.sha256

    def advise(self, measured_tokens, rendered_sha256):
        current = self.verify()
        if self.registry is None: return {"mode": "staged-only", "activation_performed": False}
        return self.registry.advise(profile_sha256=self.profile.sha256, observed_profile_sha256=current,
            rendered_prompt_sha256=rendered_sha256, measured_prompt_tokens=measured_tokens)
