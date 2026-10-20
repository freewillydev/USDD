    const SELECTED_TEN: [&str; 10] = [
        "-ecxbondv2ecxbtcprogramid",
        "-ecxbondv2ecxbtcredemptioncovenant",
        "-ecxbondv2ecxbtcsourcecheckpoint",
        "-ecxbondv2usddusdprogramid",
        "-ecxbondv2usddusdredemptioncovenant",
        "-ecxbondv2usddusdsourcecheckpoint",
        "-ecxbondv2configurationbytes",
        "-ecxbondv2configurationhash",
        "-ecxbondv2incrementalactivationconfigurationhash",
        "-ecxbondv2incrementalsuccessorconfigurationhash",
    ];
    /// Setup-only LightProver identity of `ecx-btc-conversion-v2-guest`.
    /// `logs/ecx-btc-conversion-identity-2026-09-04.md` says this is not
    /// `-ecxbondv2ecxbtcprogramid` (`witness_executed=false`).
    const SETUP_ONLY_ECX_BTC_CONVERSION_GUEST: &str =
        "2f5f873a0d6628394d0d795f35fe2526237281093ee197230bab2886288e0995";
    /// Identity-only setup of `usdd-usd-ownerless-v3-guest` (`guestRole` ownerless-outer).
    /// Not the USDD/USD conversion program id.
    const SETUP_ONLY_USDD_OWNERLESS_OUTER: &str =
        "5875cbdb05b55a3d633c54b9736f7c365016a25839f716447ddc797016356d2c";
    /// Tagged commitments of `structurally_bounded_witness()`, not a live
    /// covenant deployment or authenticated checkpoint.
    const STRUCTURAL_DUMMY_ECX_BTC_COVENANT: &str =
        "08022305187505b22d9b8190a1f88c91a4ef2a64b3234a1c05ddb18daadef495";
    const STRUCTURAL_DUMMY_ECX_BTC_CHECKPOINT: &str =
        "97cad394b937702255d8b105361f9bbf381cdd2dc06e02f4a0a3b58a0fd9233e";

    fn pending_arguments() -> serde_json::Map<String, serde_json::Value> {
        let profile: serde_json::Value = serde_json::from_str(include_str!(
            "/Volumes/T705/alpha-production-profile.jwOCQn/alpha-profile.pending.json"
        ))
        .expect("pending profile");
        profile["arguments"]
            .as_object()
            .expect("arguments")
            .clone()
    }

    fn optional_arg<'a>(
        arguments: &'a serde_json::Map<String, serde_json::Value>,
        name: &str,
    ) -> Option<&'a str> {
        match arguments.get(name) {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(value)) if !value.is_empty() => Some(value.as_str()),
            other => panic!("{name} must be JSON null or a nonempty string, got {other:?}"),
        }
    }

    #[test]
    fn pending_profile_rejects_setup_only_conversion_identities_and_fixture_bytes() {
        let arguments = pending_arguments();
        let ecx_btc_program = optional_arg(&arguments, "-ecxbondv2ecxbtcprogramid");
        let usdd_program = optional_arg(&arguments, "-ecxbondv2usddusdprogramid");
        let ecx_btc_covenant = optional_arg(&arguments, "-ecxbondv2ecxbtcredemptioncovenant");
        let ecx_btc_checkpoint = optional_arg(&arguments, "-ecxbondv2ecxbtcsourcecheckpoint");
        let configuration_bytes = optional_arg(&arguments, "-ecxbondv2configurationbytes");

        assert_ne!(ecx_btc_program, Some(SETUP_ONLY_ECX_BTC_CONVERSION_GUEST));
        assert_ne!(usdd_program, Some(SETUP_ONLY_USDD_OWNERLESS_OUTER));
        assert_ne!(ecx_btc_covenant, Some(STRUCTURAL_DUMMY_ECX_BTC_COVENANT));
        assert_ne!(ecx_btc_checkpoint, Some(STRUCTURAL_DUMMY_ECX_BTC_CHECKPOINT));

        if let Some(hex_bytes) = configuration_bytes {
            let bytes = hex::decode(hex_bytes).expect("configuration hex");
            assert_eq!(bytes.len(), 1977);
            assert_eq!(&bytes[..2], &[5, 3]);
            // frozen_configuration_fixture() uses ecx_asset_id = [0x61; 32] at
            // V18 offset 50.
            assert_ne!(&bytes[50..82], &[0x61u8; 32], "fixture ecx_asset_id");
            if let Some(program) = ecx_btc_program {
                assert_eq!(&bytes[1753..1785], hex::decode(program).unwrap().as_slice());
            }
            if let Some(program) = usdd_program {
                assert_eq!(&bytes[1785..1817], hex::decode(program).unwrap().as_slice());
            }
        }

        let populated: Vec<_> = SELECTED_TEN
            .iter()
            .copied()
            .filter(|name| optional_arg(&arguments, name).is_some())
            .collect();
        assert!(
            populated.is_empty() || populated.len() == SELECTED_TEN.len(),
            "selected conversion/configuration arguments must stay null together or be filled together: {populated:?}"
        );
    }

    #[test]
    fn already_populated_program_ids_are_distinct_from_forbidden_setup_identities() {
        let arguments = pending_arguments();
        let transition = arguments["-ecxbondv2transitionprogramid"].as_str().unwrap();
        let activation = arguments["-ecxbondv2incrementalactivationprogramid"]
            .as_str()
            .unwrap();
        let successor = arguments["-ecxbondv2incrementalsuccessorprogramid"]
            .as_str()
            .unwrap();
        for (name, value) in [
            ("-ecxbondv2transitionprogramid", transition),
            ("-ecxbondv2incrementalactivationprogramid", activation),
            ("-ecxbondv2incrementalsuccessorprogramid", successor),
        ] {
            assert_ne!(value, SETUP_ONLY_ECX_BTC_CONVERSION_GUEST, "{name}");
            assert_ne!(value, SETUP_ONLY_USDD_OWNERLESS_OUTER, "{name}");
            assert_eq!(value.len(), 64, "{name}");
        }
        assert_ne!(transition, activation);
        assert_ne!(transition, successor);
        assert_ne!(activation, successor);
    }
