use jcode_xnet_scope::{
    Action, AdapterBinding, AdapterPolicyId, AdapterRegistry, EngagementScope, GateErrorCode,
    SCOPE_SCHEMA, ScopeMode, ScopeTargets, ScopeTrustKey, Target, admit_adapter_request,
    canonical_scope_json, sign_scope, verify_admission_receipt, verify_scope, verify_target,
};

const NOW: u64 = 1_800_000_000;
const FIXED_SIGNATURE: &str = "69763ef7ecead4d12c6387489f62eb30920662899732be3c7653bd659051f8fa";

fn trust_key() -> ScopeTrustKey {
    ScopeTrustKey::new(b"scope-test-key-32-bytes-minimum!!").unwrap()
}

fn registry() -> AdapterRegistry {
    AdapterRegistry::initial("c".repeat(64), "b".repeat(64)).unwrap()
}

fn scope(mode: ScopeMode) -> EngagementScope {
    EngagementScope {
        schema: SCOPE_SCHEMA.to_string(),
        scope_id: "engagement-001".to_string(),
        program_id: "private-bounty-program".to_string(),
        mode,
        policy_capture_sha256: "a".repeat(64),
        tool_registry_sha256: registry().registry_sha256().unwrap(),
        issued_at: NOW - 60,
        expires_at: NOW + 3_600,
        allow_live_network: true,
        requests_per_minute: 30,
        max_parallel: 2,
        methods: vec![
            Action::HttpProbe,
            Action::ServiceProbe,
            Action::TcpConnectScan,
        ],
        allowed: ScopeTargets {
            domains: vec!["example.test".to_string(), "*.example.test".to_string()],
            cidrs: vec!["2001:db8::/48".to_string(), "192.0.2.0/24".to_string()],
            wifi_bssids: vec!["02:00:00:00:00:01".to_string()],
            ble_macs: vec!["02:00:00:00:00:02".to_string()],
        },
        excluded: ScopeTargets {
            domains: vec!["admin.example.test".to_string()],
            cidrs: vec!["192.0.2.128/25".to_string()],
            wifi_bssids: Vec::new(),
            ble_macs: Vec::new(),
        },
    }
}

fn verified() -> jcode_xnet_scope::VerifiedScope {
    let signed = sign_scope(&scope(ScopeMode::Bounty), &trust_key()).unwrap();
    verify_scope(&signed, &trust_key(), NOW).unwrap()
}

#[test]
fn canonical_scope_matches_the_domain_separated_fixed_vector() {
    let signed = sign_scope(&scope(ScopeMode::Bounty), &trust_key()).unwrap();
    assert_eq!(signed.signature_hmac_sha256, FIXED_SIGNATURE);

    let canonical = canonical_scope_json(&signed.scope).unwrap();
    assert!(canonical.starts_with("{\"allow_live_network\":true,\"allowed\":"));
    assert!(!canonical.contains("\n"));
    assert_eq!(
        signed.scope.allowed.domains,
        ["*.example.test", "example.test"]
    );
    assert_eq!(
        signed.scope.allowed.cidrs,
        ["192.0.2.0/24", "2001:db8::/48"]
    );
}

#[test]
fn canonical_serialization_and_signature_ignore_declaration_order() {
    let first = scope(ScopeMode::Bounty);
    let mut second = first.clone();
    second.methods.reverse();
    second.allowed.domains.reverse();
    second.allowed.cidrs.reverse();

    let first = sign_scope(&first, &trust_key()).unwrap();
    let second = sign_scope(&second, &trust_key()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        canonical_scope_json(&first.scope).unwrap(),
        canonical_scope_json(&second.scope).unwrap()
    );
}

#[test]
fn signature_tamper_wrong_key_and_noncanonical_signed_input_fail_closed() {
    let key = trust_key();
    let mut signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    signed.scope.max_parallel = 3;
    assert_eq!(
        verify_scope(&signed, &key, NOW).err().unwrap(),
        GateErrorCode::SignatureMismatch
    );

    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    let wrong_key = ScopeTrustKey::new(b"different-key-material-at-least-32!").unwrap();
    assert_eq!(
        verify_scope(&signed, &wrong_key, NOW).err().unwrap(),
        GateErrorCode::SignatureMismatch
    );

    let mut reordered = signed;
    reordered.scope.allowed.domains.reverse();
    assert_eq!(
        verify_scope(&reordered, &key, NOW).err().unwrap(),
        GateErrorCode::NonCanonicalScope
    );
}

#[test]
fn stale_and_not_yet_active_scopes_fail_against_the_caller_clock() {
    let key = trust_key();
    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    assert_eq!(
        verify_scope(&signed, &key, NOW - 61).err().unwrap(),
        GateErrorCode::ScopeNotActive
    );
    assert_eq!(
        verify_scope(&signed, &key, NOW + 3_600).err().unwrap(),
        GateErrorCode::ScopeNotActive
    );
}

#[test]
fn ipv4_and_ipv6_zero_prefixes_and_host_bit_cidrs_are_rejected() {
    for cidr in ["0.0.0.0/0", "::/0"] {
        let mut changed = scope(ScopeMode::Bounty);
        changed.allowed.cidrs = vec![cidr.to_string()];
        assert_eq!(
            sign_scope(&changed, &trust_key()).unwrap_err(),
            GateErrorCode::UnboundedCidr
        );
    }

    let mut changed = scope(ScopeMode::Bounty);
    changed.allowed.cidrs = vec!["192.0.2.1/24".to_string()];
    assert_eq!(
        sign_scope(&changed, &trust_key()).unwrap_err(),
        GateErrorCode::NonCanonicalCidr
    );
}

#[test]
fn unicode_domains_normalize_to_idna_and_hash_identically() {
    let mut changed = scope(ScopeMode::Bounty);
    changed.allowed.domains = vec!["BÜCHER.Example.".to_string()];
    changed.excluded.domains.clear();
    let signed = sign_scope(&changed, &trust_key()).unwrap();
    assert_eq!(signed.scope.allowed.domains, ["xn--bcher-kva.example"]);
    let verified = verify_scope(&signed, &trust_key(), NOW).unwrap();
    let unicode = verify_target(
        &verified,
        &trust_key(),
        &Target::Domain("bücher.example".to_string()),
    )
    .unwrap();
    let ascii = verify_target(
        &verified,
        &trust_key(),
        &Target::Domain("xn--bcher-kva.example".to_string()),
    )
    .unwrap();
    assert_eq!(unicode, ascii);

    changed.allowed.domains = vec!["bad..example".to_string()];
    assert_eq!(
        sign_scope(&changed, &trust_key()).unwrap_err(),
        GateErrorCode::InvalidDomain
    );
}

#[test]
fn wildcard_matching_honors_label_boundaries_and_forbids_wildcard_targets() {
    let mut changed = scope(ScopeMode::Bounty);
    changed.allowed.domains = vec!["*.example.test".to_string()];
    changed.excluded.domains.clear();
    let signed = sign_scope(&changed, &trust_key()).unwrap();
    let verified = verify_scope(&signed, &trust_key(), NOW).unwrap();

    for admitted in ["api.example.test", "deep.api.example.test"] {
        verify_target(
            &verified,
            &trust_key(),
            &Target::Domain(admitted.to_string()),
        )
        .unwrap();
    }
    for denied in [
        "example.test",
        "notexample.test",
        "example.test.attacker.test",
    ] {
        assert_eq!(
            verify_target(&verified, &trust_key(), &Target::Domain(denied.to_string()))
                .unwrap_err(),
            GateErrorCode::TargetOutsideScope
        );
    }
    assert_eq!(
        verify_target(
            &verified,
            &trust_key(),
            &Target::Domain("*.example.test".to_string())
        )
        .unwrap_err(),
        GateErrorCode::WildcardTargetForbidden
    );
}

#[test]
fn exclusions_win_over_domain_ip_cidr_and_mac_allowances() {
    let mut changed = scope(ScopeMode::Bounty);
    changed.excluded.domains = vec!["*.example.test".to_string()];
    changed.excluded.wifi_bssids = vec!["02:00:00:00:00:01".to_string()];
    changed.excluded.ble_macs = vec!["02:00:00:00:00:02".to_string()];
    let signed = sign_scope(&changed, &trust_key()).unwrap();
    let verified = verify_scope(&signed, &trust_key(), NOW).unwrap();

    for target in [
        Target::Domain("api.example.test".to_string()),
        Target::Ip("192.0.2.200".to_string()),
        Target::Cidr("192.0.2.128/26".to_string()),
        Target::WifiBssid("02:00:00:00:00:01".to_string()),
        Target::BleMac("02:00:00:00:00:02".to_string()),
    ] {
        assert_eq!(
            verify_target(&verified, &trust_key(), &target).unwrap_err(),
            GateErrorCode::TargetExcluded
        );
    }
}

#[test]
fn nmap_accepts_only_admitted_ipv4_ipv6_or_contained_cidrs() {
    let key = trust_key();
    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    let registry = registry();

    for target in [
        Target::Ip("192.0.2.42".to_string()),
        Target::Ip("2001:0db8:0:0:0:0:0:42".to_string()),
        Target::Cidr("192.0.2.0/26".to_string()),
        Target::Cidr("2001:db8:0:1::/64".to_string()),
    ] {
        admit_adapter_request(
            &signed,
            &key,
            NOW,
            &registry,
            AdapterPolicyId::NmapV1,
            Action::ServiceProbe,
            &target,
            None,
        )
        .unwrap();
    }

    for (target, expected) in [
        (
            Target::Ip("198.51.100.1".to_string()),
            GateErrorCode::TargetOutsideScope,
        ),
        (
            Target::Cidr("198.51.100.0/24".to_string()),
            GateErrorCode::TargetOutsideScope,
        ),
        (
            Target::Cidr("192.0.2.128/26".to_string()),
            GateErrorCode::TargetExcluded,
        ),
        (
            Target::Cidr("192.0.2.0/24".to_string()),
            GateErrorCode::TargetExcluded,
        ),
    ] {
        assert_eq!(
            admit_adapter_request(
                &signed,
                &key,
                NOW,
                &registry,
                AdapterPolicyId::NmapV1,
                Action::ServiceProbe,
                &target,
                None,
            )
            .unwrap_err(),
            expected
        );
    }

    assert_eq!(
        admit_adapter_request(
            &signed,
            &key,
            NOW,
            &registry,
            AdapterPolicyId::NmapV1,
            Action::ServiceProbe,
            &Target::Domain("example.test".to_string()),
            None,
        )
        .unwrap_err(),
        GateErrorCode::TargetKindOutsideAdapterPolicy
    );
}

#[test]
fn wifi_and_ble_membership_normalizes_mac_but_rejects_malformed_values() {
    let verified = verified();
    let colon = verify_target(
        &verified,
        &trust_key(),
        &Target::WifiBssid("02:00:00:00:00:01".to_string()),
    )
    .unwrap();
    let hyphen = verify_target(
        &verified,
        &trust_key(),
        &Target::WifiBssid("02-00-00-00-00-01".to_string()),
    )
    .unwrap();
    assert_eq!(colon, hyphen);
    verify_target(
        &verified,
        &trust_key(),
        &Target::BleMac("02-00-00-00-00-02".to_string()),
    )
    .unwrap();

    for malformed in ["02:00:00:00:00", "gg:00:00:00:00:01", "020000000001"] {
        assert_eq!(
            verify_target(
                &verified,
                &trust_key(),
                &Target::WifiBssid(malformed.to_string())
            )
            .unwrap_err(),
            GateErrorCode::InvalidMac
        );
    }
}

#[test]
fn duplicates_after_normalization_are_rejected() {
    let mut duplicate_domain = scope(ScopeMode::Bounty);
    duplicate_domain.allowed.domains =
        vec!["EXAMPLE.TEST".to_string(), "example.test.".to_string()];
    assert_eq!(
        sign_scope(&duplicate_domain, &trust_key()).unwrap_err(),
        GateErrorCode::DuplicateEntry
    );

    let mut duplicate_method = scope(ScopeMode::Bounty);
    duplicate_method.methods.push(Action::HttpProbe);
    assert_eq!(
        sign_scope(&duplicate_method, &trust_key()).unwrap_err(),
        GateErrorCode::DuplicateEntry
    );

    let mut duplicate_mac = scope(ScopeMode::Bounty);
    duplicate_mac.allowed.wifi_bssids = vec![
        "02:00:00:00:00:01".to_string(),
        "02-00-00-00-00-01".to_string(),
    ];
    assert_eq!(
        sign_scope(&duplicate_mac, &trust_key()).unwrap_err(),
        GateErrorCode::DuplicateEntry
    );
}

#[test]
fn action_must_be_in_both_scope_and_fixed_adapter_policy() {
    let key = trust_key();
    let registry = registry();

    let mut http_only = scope(ScopeMode::Bounty);
    http_only.methods = vec![Action::HttpProbe];
    let signed = sign_scope(&http_only, &key).unwrap();
    assert_eq!(
        admit_adapter_request(
            &signed,
            &key,
            NOW,
            &registry,
            AdapterPolicyId::NmapV1,
            Action::ServiceProbe,
            &Target::Ip("192.0.2.42".to_string()),
            None,
        )
        .unwrap_err(),
        GateErrorCode::MethodOutsideScope
    );

    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    assert_eq!(
        admit_adapter_request(
            &signed,
            &key,
            NOW,
            &registry,
            AdapterPolicyId::HttpxV1,
            Action::ServiceProbe,
            &Target::Domain("example.test".to_string()),
            None,
        )
        .unwrap_err(),
        GateErrorCode::MethodOutsideAdapterPolicy
    );
}

#[test]
fn admission_receipt_is_deterministic_and_contains_no_raw_request_content() {
    let key = trust_key();
    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    let registry = registry();
    let target = Target::Domain("api.example.test".to_string());

    let first = admit_adapter_request(
        &signed,
        &key,
        NOW,
        &registry,
        AdapterPolicyId::HttpxV1,
        Action::HttpProbe,
        &target,
        None,
    )
    .unwrap();
    let second = admit_adapter_request(
        &signed,
        &key,
        NOW,
        &registry,
        AdapterPolicyId::HttpxV1,
        Action::HttpProbe,
        &target,
        None,
    )
    .unwrap();
    assert_eq!(first, second);
    assert!(!first.execution_ready);
    assert_eq!(
        verify_admission_receipt(
            &first,
            &key,
            NOW,
            &first.scope_sha256,
            &registry.registry_sha256().unwrap(),
        )
        .unwrap(),
        first.reason
    );

    let serialized = serde_json::to_string(&first).unwrap();
    for forbidden in ["api.example.test", "httpx-v1", "http-probe", "argv"] {
        assert!(!serialized.contains(forbidden));
    }
    assert!(!serialized.contains("override"));
}

#[test]
fn registry_substitution_and_authorization_tamper_fail_closed() {
    let key = trust_key();
    let signed = sign_scope(&scope(ScopeMode::Bounty), &key).unwrap();
    let registry = registry();
    let target = Target::Domain("example.test".to_string());
    let receipt = admit_adapter_request(
        &signed,
        &key,
        NOW,
        &registry,
        AdapterPolicyId::HttpxV1,
        Action::HttpProbe,
        &target,
        None,
    )
    .unwrap();

    let substituted = AdapterRegistry::initial("d".repeat(64), "b".repeat(64)).unwrap();
    assert_eq!(
        admit_adapter_request(
            &signed,
            &key,
            NOW,
            &substituted,
            AdapterPolicyId::HttpxV1,
            Action::HttpProbe,
            &target,
            None,
        )
        .unwrap_err(),
        GateErrorCode::RegistryBindingMismatch
    );

    let registry_hash = registry.registry_sha256().unwrap();
    let mut tampered = receipt.clone();
    tampered.expires_at += 1;
    assert_eq!(
        verify_admission_receipt(&tampered, &key, NOW, &receipt.scope_sha256, &registry_hash,)
            .unwrap_err(),
        GateErrorCode::AuthorizationHashMismatch
    );

    let mut forged_signature = receipt.clone();
    forged_signature.authorization_hmac_sha256 = "f".repeat(64);
    assert_eq!(
        verify_admission_receipt(
            &forged_signature,
            &key,
            NOW,
            &receipt.scope_sha256,
            &registry_hash,
        )
        .unwrap_err(),
        GateErrorCode::AuthorizationSignatureMismatch
    );

    assert_eq!(
        verify_admission_receipt(
            &receipt,
            &key,
            receipt.expires_at,
            &receipt.scope_sha256,
            &registry_hash,
        )
        .unwrap_err(),
        GateErrorCode::AuthorizationNotActive
    );
    assert_eq!(
        verify_admission_receipt(&receipt, &key, NOW, &"e".repeat(64), &registry_hash,)
            .unwrap_err(),
        GateErrorCode::AuthorizationBindingMismatch
    );

    let mut execution_ready = receipt.clone();
    execution_ready.execution_ready = true;
    assert_eq!(
        verify_admission_receipt(
            &execution_ready,
            &key,
            NOW,
            &receipt.scope_sha256,
            &registry_hash,
        )
        .unwrap_err(),
        GateErrorCode::InvalidExecutionBoundary
    );
}

#[test]
fn adapter_bindings_reject_non_hash_identity_and_no_arbitrary_adapter_exists() {
    assert!(matches!(
        AdapterBinding::httpx("not-a-hash"),
        Err(GateErrorCode::InvalidHash)
    ));
    assert!(matches!(
        AdapterBinding::nmap("A".repeat(64)),
        Err(GateErrorCode::InvalidHash)
    ));
}
