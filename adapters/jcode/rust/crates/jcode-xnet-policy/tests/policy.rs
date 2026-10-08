use jcode_xnet_policy::{
    AvailabilitySnapshot, POLICY_VERSION, PolicyError, RouteConfig, RoutingPolicy, SelectionReason,
    XnetRole,
};

fn fixture() -> RoutingPolicy {
    toml::from_str(include_str!("fixtures/xnet-routing-v1.toml"))
        .expect("checked-in XNET policy fixture must parse")
}

fn all_available() -> AvailabilitySnapshot {
    AvailabilitySnapshot::new(
        true,
        [
            "daybreak-primary",
            "luna-fast-worker",
            "terra-balanced-worker",
            "qwen-local-fallback",
        ],
    )
}

#[test]
fn fixture_binds_the_four_declared_xnet_roles() {
    let policy = fixture();
    policy.validate().unwrap();

    let cases = [
        (XnetRole::Primary, "daybreak-primary"),
        (XnetRole::FastWorker, "luna-fast-worker"),
        (XnetRole::BalancedWorker, "terra-balanced-worker"),
        (XnetRole::OfflineFallback, "qwen-local-fallback"),
    ];
    for (role, expected_route) in cases {
        let availability = if role == XnetRole::OfflineFallback {
            all_available().with_offline_fallback_authorized(true)
        } else {
            all_available()
        };
        let decision = policy.select(role, &availability).unwrap();
        assert_eq!(decision.route_id, expected_route);
        assert_eq!(decision.policy_version, POLICY_VERSION);
    }
}

#[test]
fn requested_cloud_role_has_precedence_over_other_cloud_roles_and_local() {
    let policy = fixture();
    let decision = policy.select(XnetRole::Primary, &all_available()).unwrap();
    assert_eq!(decision.selected_role, XnetRole::Primary);
    assert_eq!(decision.reason, SelectionReason::RequestedRoleAvailable);
}

#[test]
fn cloud_fallback_precedence_is_explicit_for_each_requested_role() {
    let policy = fixture();
    let cases = [
        (
            XnetRole::Primary,
            vec!["luna-fast-worker", "terra-balanced-worker"],
            "terra-balanced-worker",
        ),
        (
            XnetRole::FastWorker,
            vec!["terra-balanced-worker"],
            "terra-balanced-worker",
        ),
        (
            XnetRole::BalancedWorker,
            vec!["luna-fast-worker"],
            "luna-fast-worker",
        ),
    ];

    for (requested, available, expected) in cases {
        let decision = policy
            .select(requested, &AvailabilitySnapshot::new(true, available))
            .unwrap();
        assert_eq!(decision.route_id, expected);
        assert_eq!(decision.reason, SelectionReason::CloudRoleFallback);
    }
}

#[test]
fn equal_priority_routes_use_stable_id_order() {
    let mut policy = fixture();
    policy.routes.push(RouteConfig {
        id: "a-luna-secondary".to_string(),
        role: XnetRole::FastWorker,
        model_spec: "openai-oauth:gpt-5.6-luna".to_string(),
        priority: 10,
        offline: false,
    });
    policy.routes.reverse();
    let availability = AvailabilitySnapshot::new(
        true,
        [
            "luna-fast-worker",
            "a-luna-secondary",
            "qwen-local-fallback",
        ],
    );
    let decision = policy.select(XnetRole::FastWorker, &availability).unwrap();
    assert_eq!(decision.route_id, "a-luna-secondary");
}

#[test]
fn cloud_unavailable_does_not_silently_select_local_fallback() {
    let policy = fixture();
    let availability = AvailabilitySnapshot::new(
        false,
        [
            "daybreak-primary",
            "luna-fast-worker",
            "terra-balanced-worker",
            "qwen-local-fallback",
        ],
    );
    assert_eq!(
        policy.select(XnetRole::Primary, &availability),
        Err(PolicyError::NoEligibleRoute(XnetRole::Primary))
    );
}

#[test]
fn explicit_offline_authorization_allows_local_when_cloud_is_unavailable() {
    let policy = fixture();
    let availability = AvailabilitySnapshot::new(
        false,
        [
            "daybreak-primary",
            "luna-fast-worker",
            "terra-balanced-worker",
            "qwen-local-fallback",
        ],
    )
    .with_offline_fallback_authorized(true);
    let decision = policy.select(XnetRole::Primary, &availability).unwrap();
    assert_eq!(decision.route_id, "qwen-local-fallback");
    assert_eq!(
        decision.reason,
        SelectionReason::CloudUnavailableOfflineFallback
    );
}

#[test]
fn explicit_offline_role_never_selects_a_cloud_route() {
    let policy = fixture();
    let decision = policy
        .select(
            XnetRole::OfflineFallback,
            &all_available().with_offline_fallback_authorized(true),
        )
        .unwrap();
    assert_eq!(decision.route_id, "qwen-local-fallback");
    assert_eq!(decision.reason, SelectionReason::ExplicitOfflineFallback);
}

#[test]
fn local_is_used_only_after_cloud_precedence_is_exhausted() {
    let policy = fixture();
    let availability = AvailabilitySnapshot::new(true, ["qwen-local-fallback"])
        .with_offline_fallback_authorized(true);
    let decision = policy
        .select(XnetRole::BalancedWorker, &availability)
        .unwrap();
    assert_eq!(decision.route_id, "qwen-local-fallback");
    assert_eq!(
        decision.reason,
        SelectionReason::CloudRoutesUnavailableOfflineFallback
    );
}

#[test]
fn unavailable_routes_fail_closed() {
    let policy = fixture();
    let error = policy
        .select(
            XnetRole::Primary,
            &AvailabilitySnapshot::new(true, std::iter::empty::<String>()),
        )
        .unwrap_err();
    assert_eq!(error, PolicyError::NoEligibleRoute(XnetRole::Primary));
}

#[test]
fn unavailable_local_route_fails_closed_when_cloud_is_disabled() {
    let policy = fixture();
    let error = policy
        .select(
            XnetRole::Primary,
            &AvailabilitySnapshot::new(false, ["daybreak-primary"]),
        )
        .unwrap_err();
    assert_eq!(error, PolicyError::NoEligibleRoute(XnetRole::Primary));
}

#[test]
fn explicit_offline_request_without_authorization_fails_closed() {
    let policy = fixture();
    let error = policy
        .select(XnetRole::OfflineFallback, &all_available())
        .unwrap_err();
    assert_eq!(
        error,
        PolicyError::NoEligibleRoute(XnetRole::OfflineFallback)
    );
}

#[test]
fn invalid_route_shapes_and_offline_mismatches_are_rejected() {
    let mut invalid_spec = fixture();
    invalid_spec.routes[0].model_spec = "missing-route-prefix".to_string();
    assert!(matches!(
        invalid_spec.validate(),
        Err(PolicyError::InvalidModelSpec { .. })
    ));

    let mut mismatch = fixture();
    mismatch.routes[0].offline = true;
    assert!(matches!(
        mismatch.validate(),
        Err(PolicyError::OfflineRoleMismatch { .. })
    ));

    let mut missing_role = fixture();
    missing_role
        .routes
        .retain(|route| route.role != XnetRole::BalancedWorker);
    assert_eq!(
        missing_role.validate(),
        Err(PolicyError::MissingRole(XnetRole::BalancedWorker))
    );

    let mut invalid_id = fixture();
    invalid_id.routes[0].id = "bad route".to_string();
    assert_eq!(
        invalid_id.validate(),
        Err(PolicyError::InvalidRouteId("bad route".to_string()))
    );

    let mut wrong_version = fixture();
    wrong_version.version = "xnet-routing-v999".to_string();
    assert_eq!(
        wrong_version.validate(),
        Err(PolicyError::UnsupportedVersion(
            "xnet-routing-v999".to_string()
        ))
    );
}

#[test]
fn duplicate_ids_and_model_specs_are_rejected() {
    let mut duplicate_id = fixture();
    let mut repeated = duplicate_id.routes[0].clone();
    repeated.model_spec = "openai-oauth:gpt-6-astra".to_string();
    duplicate_id.routes.push(repeated);
    assert_eq!(
        duplicate_id.validate(),
        Err(PolicyError::DuplicateRouteId(
            "daybreak-primary".to_string()
        ))
    );

    let mut duplicate_model = fixture();
    let mut repeated = duplicate_model.routes[0].clone();
    repeated.id = "second-primary".to_string();
    duplicate_model.routes.push(repeated);
    assert_eq!(
        duplicate_model.validate(),
        Err(PolicyError::DuplicateModelSpec(
            "openai-oauth:gpt-daybreak-blue-latest".to_string()
        ))
    );
}

#[test]
fn unknown_availability_ids_fail_closed() {
    let error = fixture()
        .select(
            XnetRole::Primary,
            &AvailabilitySnapshot::new(true, ["unsealed-route"]),
        )
        .unwrap_err();
    assert_eq!(
        error,
        PolicyError::UnknownAvailabilityRoute("unsealed-route".to_string())
    );
}

#[test]
fn canonical_serialization_is_compact_and_independent_of_declaration_order() {
    let first = fixture();
    let mut second = first.clone();
    second.routes.reverse();

    let first_json = first.canonical_json().unwrap();
    let second_json = second.canonical_json().unwrap();
    assert_eq!(first_json, second_json);
    assert!(!first_json.contains('\n'));
    assert_eq!(
        serde_json::from_str::<RoutingPolicy>(&first_json).unwrap(),
        serde_json::from_str::<RoutingPolicy>(&second_json).unwrap()
    );
}
