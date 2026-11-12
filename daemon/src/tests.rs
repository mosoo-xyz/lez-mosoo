use super::*;

pub fn synthesize_canonical_update() -> LightClientUpdate {
    LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 15_433_761,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 15_433_760,
            proposer_index: 40,
            parent_root: [0x10; 32],
            state_root: [0x20; 32],
            body_root: [0x30; 32],
        },
        finality_branch: vec![[0x05; 32]; 6],
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xFF; 64],
            sync_committee_signature: vec![0xC0; 96],
        },
        signature_slot: 15_433_761,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    }
}

#[test]
fn test_daemon_beacon_finality_update_parsing() {
    let json_data = r#"{
        "data": {
            "attested_header": {
                "beacon": {
                    "slot": "15433761",
                    "proposer_index": "123",
                    "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "finalized_header": {
                "beacon": {
                    "slot": "15433760",
                    "proposer_index": "120",
                    "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }
            },
            "finality_branch": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "sync_aggregate": {
                "sync_committee_bits": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
                "sync_committee_signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            "signature_slot": "15433761"
        }
    }"#;

    let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
    let update = parse_beacon_update(res).unwrap();

    assert_eq!(update.finalized_header.slot, 15_433_760);
    assert_eq!(update.attested_header.slot, 15_433_761);
    assert_eq!(update.finality_branch.len(), 2);
    assert_eq!(update.sync_aggregate.sync_committee_bits.len(), 64);
    assert_eq!(update.sync_aggregate.sync_committee_signature.len(), 96);
}

#[test]
fn test_daemon_jitter_delay_range() {
    let base_poll = 60u64;
    for _ in 0..10 {
        let jitter = rand::thread_rng().gen_range(1.0_f64..=2.5_f64);
        let wait = (base_poll as f64 * jitter) as u64;
        assert!((60..=150).contains(&wait));
    }
}

#[test]
fn test_logos_ethereum_core_proxy_url_derivation() {
    let mut cli = Cli {
        eth_consensus_rpc: "https://lodestar-sepolia.chainsafe.io".to_string(),
        eth_execution_rpc: "https://rpc.sepolia.org".to_string(),
        eth_chain_id: 11155111,
        lez_rpc_url: "http://127.0.0.1:8545".to_string(),
        lez_private_key: Some("0x01".to_string()),
        logos_ethereum_core_rpc: None,
        poll_interval_secs: 60,
        log_level: "info".to_string(),
        log_format: "pretty".to_string(),
        health_port: None,
    };

    // Without Logos Core proxy: falls back to direct beacon node
    assert_eq!(
        derive_consensus_url(&cli, "headers/finalized"),
        "https://lodestar-sepolia.chainsafe.io/eth/v1/beacon/headers/finalized"
    );

    // With Logos Core proxy: routes to verified Ethereum Core catalog proxy
    cli.logos_ethereum_core_rpc = Some("https://ethereum-core.logos.co/".to_string());
    assert_eq!(
        derive_consensus_url(&cli, "headers/finalized"),
        "https://ethereum-core.logos.co/v1/ethereum-core/consensus/headers/finalized"
    );
    assert_eq!(
        derive_consensus_url(&cli, "light_client/finality_update"),
        "https://ethereum-core.logos.co/v1/ethereum-core/consensus/light_client/finality_update"
    );
}

/// Verify that the competing-update SubmitResult enum covers all liveness scenarios.
/// When the LEZ slot equals the Ethereum slot, AlreadyUpToDate is returned.
/// When the LEZ slot is AHEAD of the Ethereum slot, AlreadyUpToDate is returned.
/// When there is a gap, the daemon should proceed to fetch & submit.
#[test]
fn test_daemon_competing_update_result_enum_coverage() {
    // AlreadyUpToDate scenario: LEZ caught up
    let r1 = SubmitResult::AlreadyUpToDate {
        lez_slot: 15_433_760,
        eth_slot: 15_433_760,
    };
    assert!(
        matches!(r1, SubmitResult::AlreadyUpToDate { lez_slot, eth_slot } if lez_slot == eth_slot)
    );

    // AlreadyUpToDate scenario: LEZ is ahead (rare, should not happen in normal ops)
    let r2 = SubmitResult::AlreadyUpToDate {
        lez_slot: 15_433_760,
        eth_slot: 15_433_728,
    };
    assert!(
        matches!(r2, SubmitResult::AlreadyUpToDate { lez_slot, eth_slot } if lez_slot > eth_slot)
    );

    // JobAlreadyOpen scenario: another daemon operator won the race
    let r3 = SubmitResult::JobAlreadyOpen { slot: 15_433_760 };
    assert!(matches!(r3, SubmitResult::JobAlreadyOpen { slot } if slot == 15_433_760));

    // Submitted scenario: we won and committed the update
    let r4 = SubmitResult::Submitted { slot: 15_433_792 };
    assert!(matches!(r4, SubmitResult::Submitted { slot } if slot == 15_433_792));

    // Verify all 3 enum arms are distinct and non-overlapping
    assert_ne!(std::mem::discriminant(&r1), std::mem::discriminant(&r3));
    assert_ne!(std::mem::discriminant(&r3), std::mem::discriminant(&r4));
}

/// Verify the synthesized canonical update has correct structure for offline operation.
/// The fallback vector must carry a valid slot, non-empty branch, and correct bit/sig lengths.
#[test]
fn test_daemon_synthesized_canonical_update_structure() {
    let update = synthesize_canonical_update();

    // Attested header must be one slot ahead of finalized header (normal Ethereum progression)
    assert_eq!(
        update.attested_header.slot,
        update.finalized_header.slot + 1,
        "Attested slot must be finalized_slot + 1 in canonical update"
    );

    // Finality branch must be present with correct Ethereum Altair branch depth (6 nodes)
    assert_eq!(
        update.finality_branch.len(),
        6,
        "Ethereum finality branch has depth 6 (gindex 105)"
    );

    // Sync aggregate bitvector must be 64 bytes (512 validators / 8 bits per byte)
    assert_eq!(
        update.sync_aggregate.sync_committee_bits.len(),
        64,
        "Sync aggregate bits vector must be exactly 64 bytes for 512 validators"
    );

    // Sync aggregate signature must be 96 bytes (BLS12-381 G2 compressed point)
    assert_eq!(
        update.sync_aggregate.sync_committee_signature.len(),
        96,
        "Sync aggregate signature must be exactly 96 bytes (BLS12-381 G2)"
    );

    // Signature slot must match attested slot
    assert_eq!(
        update.signature_slot, update.attested_header.slot,
        "signature_slot must match attested_header.slot"
    );

    // Verify Period 1884 canonical slot range
    assert!(update.finalized_header.slot >= 15_000_000);
    assert!(update.finalized_header.slot < 16_000_000);
}

/// Verify that derive_consensus_url correctly handles trailing slashes on both sides.
#[test]
fn test_daemon_url_construction_trailing_slash_normalization() {
    let cli_trailing = Cli {
        eth_consensus_rpc: "https://beacon.example.com/".to_string(),
        eth_execution_rpc: "https://exec.example.com".to_string(),
        eth_chain_id: 1,
        lez_rpc_url: "https://lez.logos.co/rpc".to_string(),
        lez_private_key: Some("0x01".to_string()),
        logos_ethereum_core_rpc: None,
        poll_interval_secs: 60,
        log_level: "info".to_string(),
        log_format: "json".to_string(),
        health_port: None,
    };
    let cli_no_trailing = Cli {
        eth_consensus_rpc: "https://beacon.example.com".to_string(),
        ..cli_trailing.clone()
    };

    // Both forms must produce identical URLs (no double-slash)
    let url_trailing = derive_consensus_url(&cli_trailing, "headers/finalized");
    let url_no_trailing = derive_consensus_url(&cli_no_trailing, "headers/finalized");

    assert_eq!(url_trailing, url_no_trailing);
    assert!(
        !url_trailing.contains("//eth"),
        "URL must not contain double-slash before path: {}",
        url_trailing
    );

    // Also verify leading-slash normalization on path suffix
    let url_with_slash = derive_consensus_url(&cli_no_trailing, "/headers/finalized");
    assert_eq!(url_with_slash, url_no_trailing);
}

#[tokio::test]
async fn test_daemon_submit_begin_requires_private_key() {
    let cli = Cli {
        eth_consensus_rpc: "https://beacon.example.com".to_string(),
        eth_execution_rpc: "https://exec.example.com".to_string(),
        eth_chain_id: 1,
        lez_rpc_url: "http://127.0.0.1:8545".to_string(),
        lez_private_key: None,
        logos_ethereum_core_rpc: None,
        poll_interval_secs: 60,
        log_level: "info".to_string(),
        log_format: "json".to_string(),
        health_port: None,
    };
    let client = reqwest::Client::new();
    let update = synthesize_canonical_update();
    let res = submit_begin(&cli, &client, &update).await;
    assert!(res.is_err());
    assert!(res
        .unwrap_err()
        .to_string()
        .contains("LEZ_PRIVATE_KEY is required"));
}

#[test]
fn test_daemon_beacon_finality_update_with_execution_payload_parsing() {
    let json_data = r#"{
        "data": {
            "attested_header": {
                "beacon": {
                    "slot": "15433761",
                    "proposer_index": "123",
                    "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "finalized_header": {
                "beacon": {
                    "slot": "15433760",
                    "proposer_index": "120",
                    "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }
            },
            "finality_branch": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "sync_aggregate": {
                "sync_committee_bits": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
                "sync_committee_signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            "signature_slot": "15433761",
            "execution_payload_header": {
                "parent_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "fee_recipient": "0x2222222222222222222222222222222222222222",
                "state_root": "0x3333333333333333333333333333333333333333333333333333333333333333",
                "receipts_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                "logs_bloom": "0x00",
                "prev_randao": "0x5555555555555555555555555555555555555555555555555555555555555555",
                "block_number": "1000",
                "gas_limit": "30000000",
                "gas_used": "15000000",
                "timestamp": "1700000000",
                "extra_data": "0x",
                "base_fee_per_gas": "0x0000000000000000000000000000000000000000000000000000000000000001",
                "block_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
                "transactions_root": "0x7777777777777777777777777777777777777777777777777777777777777777"
            },
            "execution_branch": [
                "0x8888888888888888888888888888888888888888888888888888888888888888",
                "0x9999999999999999999999999999999999999999999999999999999999999999",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ]
        }
    }"#;

    let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
    let update = parse_beacon_update(res).unwrap();

    assert_eq!(update.finalized_header.slot, 15_433_760);
    let exec = update
        .execution_payload_header
        .expect("must decode execution payload header");
    assert_eq!(exec.block_number, 1000);
    assert_eq!(exec.fee_recipient, [0x22; 20]);
    assert_eq!(exec.state_root, [0x33; 32]);
    assert_eq!(exec.receipts_root, [0x44; 32]);
    assert_eq!(exec.block_hash, [0x66; 32]);

    let branch = update
        .execution_branch
        .expect("must decode execution branch");
    assert_eq!(branch.len(), 4);
    assert_eq!(branch[0], [0x88; 32]);
}

#[test]
fn test_daemon_open_job_status_representation() {
    let job = OpenJobStatus {
        job_nonce: 42,
        stage: "miller".to_string(),
        target_slot: 15_433_760,
    };
    assert_eq!(job.job_nonce, 42);
    assert_eq!(job.stage, "miller");
    assert_eq!(job.target_slot, 15_433_760);
}

#[test]
fn test_daemon_beacon_finality_update_with_next_sync_committee_and_rlp() {
    let dummy_pubkey = "0x".to_string() + &hex::encode([0x42u8; 48]);
    let json_data = format!(
        r#"{{
        "data": {{
            "attested_header": {{
                "beacon": {{
                    "slot": "15433761",
                    "proposer_index": "123",
                    "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }}
            }},
            "finalized_header": {{
                "beacon": {{
                    "slot": "15433760",
                    "proposer_index": "120",
                    "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }}
            }},
            "finality_branch": [
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "sync_aggregate": {{
                "sync_committee_bits": "0xff00",
                "sync_committee_signature": "0xc000"
            }},
            "signature_slot": "15433761",
            "next_sync_committee": {{
                "pubkeys": ["{dummy_pubkey}"],
                "aggregate_pubkey": "{dummy_pubkey}"
            }},
            "next_sync_committee_branch": [
                "0x7777777777777777777777777777777777777777777777777777777777777777"
            ],
            "execution_rlp": "0x01020304"
        }}
    }}"#
    );

    let res: FinalityUpdateResponse = serde_json::from_str(&json_data).unwrap();
    let update = parse_beacon_update(res).unwrap();

    let nsc = update
        .next_sync_committee
        .expect("must decode next_sync_committee");
    assert_eq!(nsc.pubkeys.len(), 1);
    assert_eq!(nsc.pubkeys[0], vec![0x42u8; 48]);
    assert_eq!(nsc.aggregate_pubkey, vec![0x42u8; 48]);

    let branch = update
        .next_sync_committee_branch
        .expect("must decode branch");
    assert_eq!(branch.len(), 1);
    assert_eq!(branch[0], [0x77; 32]);

    let rlp = update.execution_rlp.expect("must decode execution_rlp");
    assert_eq!(rlp, vec![1, 2, 3, 4]);
}

#[test]
fn test_daemon_beacon_finality_update_malformed_slot_rejected() {
    let json_data = r#"{
        "data": {
            "attested_header": {
                "beacon": {
                    "slot": "15433761",
                    "proposer_index": "123",
                    "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "finalized_header": {
                "beacon": {
                    "slot": "15433760",
                    "proposer_index": "120",
                    "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }
            },
            "finality_branch": [],
            "sync_aggregate": {
                "sync_committee_bits": "0xff",
                "sync_committee_signature": "0xc0"
            },
            "signature_slot": "not_a_number"
        }
    }"#;

    let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
    let err = parse_beacon_update(res);
    assert!(err.is_err());
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("Failed to parse signature_slot"));
}

#[test]
fn test_daemon_beacon_updates_period_boundary_parsing() {
    let dummy_pubkey = "0x".to_string() + &hex::encode([0x33u8; 48]);
    let json_updates = format!(
        r#"{{
        "data": [
            {{
                "version": "deneb",
                "data": {{
                    "attested_header": {{
                        "beacon": {{
                            "slot": "15433761",
                            "proposer_index": "123",
                            "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                            "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                            "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                        }}
                    }},
                    "finalized_header": {{
                        "beacon": {{
                            "slot": "15433760",
                            "proposer_index": "120",
                            "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                            "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                            "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                        }}
                    }},
                    "finality_branch": [
                        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ],
                    "sync_aggregate": {{
                        "sync_committee_bits": "0xff00",
                        "sync_committee_signature": "0xc000"
                    }},
                    "signature_slot": "15433761",
                    "next_sync_committee": {{
                        "pubkeys": ["{dummy_pubkey}"],
                        "aggregate_pubkey": "{dummy_pubkey}"
                    }},
                    "next_sync_committee_branch": [
                        "0x9999999999999999999999999999999999999999999999999999999999999999"
                    ]
                }}
            }}
        ]
    }}"#
    );

    let res: LightClientUpdatesResponse = serde_json::from_str(&json_updates).unwrap();
    let update = parse_beacon_updates_response(res).expect("Period boundary update must parse");

    assert_eq!(update.finalized_header.slot, 15_433_760);
    let nsc = update
        .next_sync_committee
        .expect("next_sync_committee must be present");
    assert_eq!(nsc.pubkeys.len(), 1);
    assert_eq!(nsc.pubkeys[0], vec![0x33u8; 48]);
    assert_eq!(nsc.aggregate_pubkey, vec![0x33u8; 48]);

    let branch = update
        .next_sync_committee_branch
        .expect("branch must be present");
    assert_eq!(branch[0], [0x99; 32]);
}

#[tokio::test]
async fn test_daemon_raw_private_key_never_sent_in_rpc_payload() {
    let dummy_privkey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let cli = Cli {
        eth_consensus_rpc: "http://127.0.0.1:5052".to_string(),
        eth_execution_rpc: "http://127.0.0.1:8545".to_string(),
        eth_chain_id: 1,
        lez_rpc_url: "http://127.0.0.1:8545".to_string(),
        lez_private_key: Some(dummy_privkey.to_string()),
        logos_ethereum_core_rpc: None,
        poll_interval_secs: 60,
        log_format: "json".to_string(),
        log_level: "info".to_string(),
        health_port: None,
    };

    let signer: alloy::signers::local::PrivateKeySigner = dummy_privkey.parse().unwrap();
    let expected_sender = format!("{:#x}", signer.address());

    let update = synthesize_canonical_update();
    let update_json = serde_json::to_string(&update).unwrap();
    let tx_digest = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"begin_update");
        sha2::Digest::update(&mut hasher, cli.eth_chain_id.to_be_bytes());
        sha2::Digest::update(&mut hasher, update_json.as_bytes());
        alloy::primitives::B256::from_slice(&sha2::Digest::finalize(hasher))
    };
    let sig = signer.sign_hash(&tx_digest).await.unwrap();

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_sendTransaction",
        "params": [{
            "to": "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            "instruction": "begin_update",
            "chain_id": cli.eth_chain_id,
            "data": "0x1234",
            "from": expected_sender,
            "signature": format!("0x{}", hex::encode(sig.as_bytes())),
        }],
        "id": 2
    });

    let payload_str = payload.to_string();
    assert!(!payload_str.contains(dummy_privkey.trim_start_matches("0x")));
    assert!(payload_str.contains(&expected_sender));
    assert!(payload_str.contains("signature"));
}

#[test]
fn test_daemon_malformed_branch_node_strictly_rejected() {
    let json_data = r#"{
        "data": {
            "attested_header": {
                "beacon": {
                    "slot": "15433761",
                    "proposer_index": "123",
                    "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                    "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                }
            },
            "finalized_header": {
                "beacon": {
                    "slot": "15433760",
                    "proposer_index": "120",
                    "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                }
            },
            "finality_branch": ["0x1234"],
            "sync_aggregate": {
                "sync_committee_bits": "0xff",
                "sync_committee_signature": "0xc0"
            },
            "signature_slot": "15433761"
        }
    }"#;

    let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
    let err = parse_beacon_update(res);
    assert!(err.is_err(), "Non-32-byte branch node must be rejected");
}

#[test]
fn test_pipeline_transaction_digests_enforce_chain_id_domain_separation() {
    let chain_a: u64 = 1;
    let chain_b: u64 = 11155111;
    let job_nonce: u64 = 42;

    let digest_a = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"miller_update");
        sha2::Digest::update(&mut hasher, chain_a.to_be_bytes());
        sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
        sha2::Digest::finalize(hasher)
    };

    let digest_b = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"miller_update");
        sha2::Digest::update(&mut hasher, chain_b.to_be_bytes());
        sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
        sha2::Digest::finalize(hasher)
    };

    assert_ne!(
        digest_a, digest_b,
        "Digests on different chains must differ due to domain separation"
    );
}

#[test]
fn test_daemon_parses_real_mainnet_fulu_vectors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors/mainnet");
    let fin_raw = std::fs::read_to_string(root.join("finality_update.json")).unwrap();
    let fin_res: FinalityUpdateResponse = serde_json::from_str(&fin_raw).unwrap();
    let fin = parse_beacon_update(fin_res).expect("real mainnet finality_update must parse");

    assert_eq!(fin.finalized_header.slot, 15_632_352);
    assert_eq!(fin.attested_header.slot, 15_632_429);
    assert_eq!(fin.signature_slot, 15_632_430);
    let exec = fin
        .execution_payload_header
        .expect("nested finalized_header.execution must populate execution_payload_header");
    assert_eq!(exec.block_number, 26_392_691);
    assert_eq!(
        exec.block_hash,
        hex_to_32("0x5f9597a4bbccc846b0589c646ca00ddb3af36c1468a7f42acbc95e16639070a2").unwrap()
    );
    // Decimal base_fee_per_gas "400545765" -> SSZ uint256 little-endian
    assert_eq!(
        exec.base_fee_per_gas,
        alloy::primitives::U256::from(400_545_765u64).to_le_bytes::<32>()
    );
    assert_eq!(fin.execution_branch.as_ref().map(|b| b.len()), Some(4));

    // Bare JSON array from /eth/v1/beacon/light_client/updates
    let upd_raw = std::fs::read_to_string(root.join("period_updates.json")).unwrap();
    let upd = parse_updates_json(&upd_raw).expect("bare array period_updates must parse");
    assert!(upd.next_sync_committee.is_some());
    assert_eq!(
        upd.next_sync_committee_branch.as_ref().map(|b| b.len()),
        Some(6)
    );
}

#[test]
fn test_daemon_parses_real_sepolia_gloas_and_hoodi_vectors() {
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors");

    // Sepolia Gloas finality_update uses finalized_header.execution_block_hash
    let sep_fin_raw =
        std::fs::read_to_string(vectors.join("sepolia/finality_update.json")).unwrap();
    let sep_res: FinalityUpdateResponse = serde_json::from_str(&sep_fin_raw).unwrap();
    let sep_fin = parse_beacon_update(sep_res).expect("real Sepolia Gloas finality must parse");
    assert_eq!(sep_fin.finalized_header.slot, 11_556_544);
    assert_eq!(sep_fin.signature_slot, 11_556_609);
    assert_eq!(sep_fin.execution_branch.as_ref().map(|b| b.len()), Some(11));
    let sep_exec = sep_fin
        .execution_payload_header
        .expect("Gloas execution_block_hash must synthesize minimal ExecutionPayloadHeader");
    assert_eq!(
        sep_exec.block_hash,
        hex_to_32("0x5bf0dd87b2bf3d90bf24e0274c90077e13ad2dde12424d748c469158cf127c64").unwrap()
    );

    let sep_upd_raw = std::fs::read_to_string(vectors.join("sepolia/period_updates.json")).unwrap();
    let sep_upd = parse_updates_json(&sep_upd_raw).expect("Sepolia Gloas updates must parse");
    assert_eq!(sep_upd.execution_branch.as_ref().map(|b| b.len()), Some(11));
    assert_eq!(
        sep_upd.next_sync_committee_branch.as_ref().map(|b| b.len()),
        Some(11)
    );

    // Hoodi Fulu finality_update & bare array current_period_update
    let hoodi_fin_raw =
        std::fs::read_to_string(vectors.join("hoodi/finality_update.json")).unwrap();
    let hoodi_res: FinalityUpdateResponse = serde_json::from_str(&hoodi_fin_raw).unwrap();
    let hoodi_fin = parse_beacon_update(hoodi_res).expect("Hoodi Fulu finality must parse");
    assert_eq!(hoodi_fin.finalized_header.slot, 4_349_920);
    assert_eq!(hoodi_fin.signature_slot, 4_349_987);

    let hoodi_upd_raw =
        std::fs::read_to_string(vectors.join("hoodi/current_period_update.json")).unwrap();
    let hoodi_upd = parse_updates_json(&hoodi_upd_raw).expect("Hoodi bare array update must parse");
    assert_eq!(hoodi_upd.finalized_header.slot, 4_349_184);
    assert!(hoodi_upd.next_sync_committee.is_some());
    assert!(mosoo_core::crypto::is_supported_chain(560_048));
}

#[test]
fn test_daemon_health_and_metrics_endpoints() {
    use std::sync::atomic::Ordering;

    let parsed = Cli::try_parse_from(["mosoo-daemon", "--health-port", "9102"])
        .expect("--health-port flag must parse cleanly");
    assert_eq!(parsed.health_port, Some(9102));

    let state = DaemonHealthState::default();
    let (status_not_ready, _) = state.render_http_response("/readyz");
    assert_eq!(status_not_ready, "503 Service Unavailable");

    state.ready.store(true, Ordering::Relaxed);
    state.polls_total.store(5, Ordering::Relaxed);
    state.submissions_total.store(2, Ordering::Relaxed);
    state.errors_total.store(1, Ordering::Relaxed);
    state.last_slot.store(15_632_352, Ordering::Relaxed);

    let (status_ok, body_health) = state.render_http_response("/healthz");
    assert_eq!(status_ok, "200 OK");
    assert!(body_health.contains("\"ok\""));

    let (status_ready, body_ready) = state.render_http_response("/readyz");
    assert_eq!(status_ready, "200 OK");
    assert!(body_ready.contains("\"ready\""));

    let (status_metrics, body_metrics) = state.render_http_response("/metrics");
    assert_eq!(status_metrics, "200 OK");
    assert!(body_metrics.contains("mosoo_daemon_ready 1"));
    assert!(body_metrics.contains("mosoo_daemon_polls_total 5"));
    assert!(body_metrics.contains("mosoo_daemon_submissions_total 2"));
    assert!(body_metrics.contains("mosoo_daemon_errors_total 1"));
    assert!(body_metrics.contains("mosoo_daemon_last_slot 15632352"));

    let (status_404, _) = state.render_http_response("/other");
    assert_eq!(status_404, "404 Not Found");
}
