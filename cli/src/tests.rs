use super::*;

#[test]
fn test_cli_parser_and_fixture_loading() {
    let args = vec!["mosoo", "demo", "--mode", "fixture", "--chain-id", "1"];
    let cli = Cli::try_parse_from(args).expect("Failed to parse CLI args");
    match cli.command {
        Commands::Demo {
            mode,
            chain_id,
            amount,
        } => {
            assert_eq!(mode, "fixture");
            assert_eq!(chain_id, 1);
            assert_eq!(amount, 1000);
        }
        _ => panic!("Expected Demo command"),
    }

    // Verify new RFP-021 CLI subcommands parse correctly
    let attest_args = vec!["mosoo", "attest", "--chain-id", "1", "--dry-run"];
    let attest_cli = Cli::try_parse_from(attest_args).expect("Parse attest");
    assert!(matches!(
        attest_cli.command,
        Commands::Attest { dry_run: true, .. }
    ));

    let attest_rpc_args = vec![
        "mosoo",
        "attest",
        "--chain-id",
        "1",
        "--rpc-url",
        "https://eth.llamarpc.com",
    ];
    let attest_rpc_cli = Cli::try_parse_from(attest_rpc_args).expect("Parse attest with rpc-url");
    assert!(matches!(
        attest_rpc_cli.command,
        Commands::Attest {
            rpc_url: Some(ref url),
            ..
        } if url == "https://eth.llamarpc.com"
    ));

    let dry_run_args = vec!["mosoo", "dry-run", "--chain-id", "11155111"];
    let dry_run_cli = Cli::try_parse_from(dry_run_args).expect("Parse dry-run");
    assert!(matches!(
        dry_run_cli.command,
        Commands::DryRun {
            chain_id: 11155111,
            ..
        }
    ));

    let submit_args = vec!["mosoo", "submit-update", "--chain-id", "1"];
    let submit_cli = Cli::try_parse_from(submit_args).expect("Parse submit-update");
    assert!(matches!(
        submit_cli.command,
        Commands::SubmitUpdate { chain_id: 1, .. }
    ));

    let config_args = vec![
        "mosoo",
        "config",
        "--chain-id",
        "1",
        "--instance",
        "0x4242424242424242424242424242424242424242424242424242424242424242",
    ];
    let config_cli = Cli::try_parse_from(config_args).expect("Parse config");
    assert!(matches!(
        config_cli.command,
        Commands::Config { chain_id: 1, instance: Some(ref s) } if s == "0x4242424242424242424242424242424242424242424242424242424242424242"
    ));

    let privacy_args = vec![
        "mosoo",
        "attest",
        "--chain-id",
        "1",
        "--privacy-mode",
        "address-private",
        "--privacy-salt",
        "0x0102030405060708010203040506070801020304050607080102030405060708",
        "--dry-run",
    ];
    let privacy_cli = Cli::try_parse_from(privacy_args).expect("Parse privacy attest");
    assert!(matches!(
        privacy_cli.command,
        Commands::Attest {
            ref privacy_mode,
            privacy_salt: Some(ref s),
            ..
        } if privacy_mode == "address-private" && s.starts_with("0x0102")
    ));

    let verify_args = vec![
        "mosoo",
        "verify-checkpoint",
        "--chain-id",
        "1",
        "--trusted-head-slot",
        "15450000",
    ];
    let verify_cli = Cli::try_parse_from(verify_args).expect("Parse verify-checkpoint");
    assert!(matches!(
        verify_cli.command,
        Commands::VerifyCheckpoint {
            chain_id: 1,
            trusted_head_slot: 15450000,
            ..
        }
    ));

    // Verify committed real-chain vector exists and parses cleanly
    let fixture_path = "vectors/mainnet/finality_update.json";
    if std::path::Path::new(fixture_path).exists() {
        let content = std::fs::read_to_string(fixture_path).expect("Read fixture");
        let json: serde_json::Value = serde_json::from_str(&content).expect("Parse JSON");
        assert!(json.pointer("/data/finalized_header/beacon/slot").is_some());
    }
}

#[test]
fn test_cli_attest_storage_and_deposit_targets_run_successfully() {
    // Storage slot target
    let storage_args = AttestArgs {
        chain_id: 1,
        address_str: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        owner_str: None,
        mapping_slot: 0,
        tx_hash: None,
        demo: true,
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "storage",
        min_value: 100,
        rpc_url: None,
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "public",
        privacy_salt: None,
        bootstrap_file: None,
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    assert!(run_attest(storage_args).is_ok());

    // Deposit receipt target with address-private shielding (RFP-021 F#8)
    let deposit_args = AttestArgs {
        chain_id: 1,
        address_str: "0x4299900000000000000000000000000000000001",
        owner_str: None,
        mapping_slot: 0,
        tx_hash: None,
        demo: true,
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "deposit",
        min_value: 1_000_000_000,
        rpc_url: None,
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "address-private",
        privacy_salt: Some("0x1122334455667788112233445566778811223344556677881122334455667788"),
        bootstrap_file: None,
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    assert!(run_attest(deposit_args).is_ok());

    // ERC-20 deposit target with owner token address parameter
    let erc20_deposit_args = AttestArgs {
        chain_id: 1,
        address_str: "0x4299900000000000000000000000000000000001",
        owner_str: Some("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        mapping_slot: 0,
        tx_hash: None,
        demo: true,
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "deposit",
        min_value: 1_000_000,
        rpc_url: None,
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "public",
        privacy_salt: None,
        bootstrap_file: None,
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    assert!(run_attest(erc20_deposit_args).is_ok());

    // ERC-20 target with custom owner address parameter
    let erc20_args = AttestArgs {
        chain_id: 1,
        address_str: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        owner_str: Some("0x1111111111111111111111111111111111111111"),
        mapping_slot: 0,
        tx_hash: None,
        demo: true,
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "erc20",
        min_value: 100,
        rpc_url: None,
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "confidential",
        privacy_salt: None,
        bootstrap_file: None,
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    assert!(run_attest(erc20_args).is_ok());
}

#[test]
fn test_cli_production_attest_fails_closed_without_authentic_committee() {
    let prod_args = AttestArgs {
        chain_id: 1,
        address_str: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        owner_str: None,
        mapping_slot: 0,
        tx_hash: None,
        demo: false, // Production mode
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "storage",
        min_value: 100,
        rpc_url: Some("http://127.0.0.1:8545"),
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "public",
        privacy_salt: None,
        bootstrap_file: None,
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    // In production with RPC but without --bootstrap-file or --beacon-rpc, MUST fail closed
    let res = run_attest(prod_args);
    assert!(
        res.is_err(),
        "Production mode must reject synthetic committee"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg
        .contains("Production consensus attestation requires authentic validator committee data"));
}

#[test]
fn test_cli_production_attest_fails_closed_without_rpc() {
    let prod_args = AttestArgs {
        chain_id: 1,
        address_str: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        owner_str: None,
        mapping_slot: 0,
        tx_hash: None,
        demo: false,
        allow_unfinalized: false,
        slot: 15_433_760,
        target: "storage",
        min_value: 100,
        rpc_url: None,
        logos_core_rpc: None,
        dry_run: true,
        privacy_mode: "public",
        privacy_salt: None,
        bootstrap_file: Some("vectors/mainnet/bootstrap.json"),
        beacon_rpc: None,
        sequencer_url: None,
        broadcast: false,
    };
    let res = run_attest(prod_args);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains(
        "Production consensus and state attestation requires an active Ethereum JSON-RPC endpoint"
    ));
}

#[test]
fn test_cli_production_verify_checkpoint_fails_closed_without_anchor() {
    let res = run_verify_checkpoint(1, None, 15_433_728, None, None, false);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains(
        "Production checkpoint verification requires an authentic trusted block root anchor"
    ));
}

#[test]
fn test_cli_demo_verify_checkpoint_succeeds() {
    let res = run_verify_checkpoint(1, None, 15_433_728, None, None, true);
    assert!(res.is_ok());
}

#[test]
fn test_cli_submit_update_dry_run_executes_cleanly() {
    assert!(run_submit_update(1, None, "http://127.0.0.1:8545", None).is_ok());
}
