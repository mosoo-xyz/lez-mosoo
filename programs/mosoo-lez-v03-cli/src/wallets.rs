use std::{
    fs,
    path::Path,
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use lee::{AccountId, PrivateKey, PublicKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

/// Loaded LEZ public account keypair whose `AccountId` is verified against metadata.
pub struct LoadedWallet {
    pub label: String,
    pub account_id: AccountId,
    private_key: PrivateKey,
}

impl LoadedWallet {
    pub fn from_ephemeral(label: &str, private_key: PrivateKey) -> Self {
        let account_id = account_id_of(&private_key);
        Self {
            label: label.to_owned(),
            account_id,
            private_key,
        }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

#[derive(Deserialize)]
struct RawWalletFile {
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    account: Option<String>,
    address: Option<String>,
    #[serde(rename = "privateKeyHex")]
    private_key_hex: Option<String>,
    privkey: Option<String>,
    private_key: Option<String>,
}

/// Generate a fresh valid secp256k1 `PrivateKey` from OS CSPRNG.
pub fn generate_fresh_key() -> Result<PrivateKey> {
    let mut buf = [0u8; 32];
    for _ in 0..64 {
        OsRng.fill_bytes(&mut buf);
        if let Ok(sk) = PrivateKey::try_new(buf) {
            return Ok(sk);
        }
    }
    bail!("failed to generate valid secp256k1 PrivateKey")
}

pub fn account_id_of(sk: &PrivateKey) -> AccountId {
    let pk = PublicKey::new_from_private_key(sk);
    AccountId::from(&pk)
}

pub fn parse_private_key_hex(s: &str) -> Result<PrivateKey> {
    let trimmed = s.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(hex_str).context("invalid private key hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("private key must be exactly 32 bytes"))?;
    PrivateKey::try_new(arr).map_err(|e| anyhow!("invalid secp256k1 private key: {e:?}"))
}

pub fn load_wallet(path: &Path, label: &str) -> Result<LoadedWallet> {
    let raw_text =
        fs::read_to_string(path).with_context(|| format!("failed to read wallet {}", path.display()))?;
    let parsed: RawWalletFile = serde_json::from_str(&raw_text)
        .with_context(|| format!("failed to parse wallet JSON {}", path.display()))?;

    let key_hex = parsed
        .private_key_hex
        .or(parsed.privkey)
        .or(parsed.private_key)
        .ok_or_else(|| anyhow!("wallet {} missing private key field", path.display()))?;
    let trimmed = key_hex.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let raw_bytes: [u8; 32] = hex::decode(hex_str)
        .context("invalid private key hex")?
        .try_into()
        .map_err(|_| anyhow!("private key must be exactly 32 bytes"))?;
    let sk_direct = PrivateKey::try_new(raw_bytes)
        .map_err(|e| anyhow!("invalid secp256k1 private key: {e:?}"))?;
    let derived_direct = account_id_of(&sk_direct);

    let (sk, derived_id) =
        if let Some(expected_str) = parsed.account_id.or(parsed.account).or(parsed.address) {
            let expected = AccountId::from_str(expected_str.trim())
                .map_err(|e| anyhow!("invalid Base58 AccountId in {}: {e:?}", path.display()))?;
            if derived_direct == expected {
                (sk_direct, derived_direct)
            } else if let Ok(sk_tweaked) = PrivateKey::tweak(&raw_bytes) {
                let derived_tweaked = account_id_of(&sk_tweaked);
                if derived_tweaked == expected {
                    (sk_tweaked, derived_tweaked)
                } else {
                    bail!(
                        "wallet {} derived AccountId {derived_direct} (or tweaked {derived_tweaked}) does not match expected {expected}",
                        path.display()
                    );
                }
            } else {
                bail!(
                    "wallet {} derived AccountId {derived_direct} does not match expected {expected}",
                    path.display()
                );
            }
        } else {
            (sk_direct, derived_direct)
        };

    Ok(LoadedWallet {
        label: label.to_owned(),
        account_id: derived_id,
        private_key: sk,
    })
}

/// Persists ephemeral deploy segment & header keys outside the git tree for resume/audit safety.
#[derive(Serialize, Deserialize)]
pub struct EphemeralDeployKeys {
    pub program_header_account: String,
    pub program_header_privkey_hex: String,
    pub segment_accounts: Vec<String>,
    pub segment_privkeys_hex: Vec<String>,
}

pub fn create_and_save_deploy_keys(
    segment_count: usize,
    secret_key_store: &Path,
) -> Result<(PrivateKey, AccountId, Vec<(PrivateKey, AccountId)>)> {
    if secret_key_store.exists() {
        let raw = fs::read_to_string(secret_key_store)?;
        let saved: EphemeralDeployKeys = serde_json::from_str(&raw)?;
        if saved.segment_privkeys_hex.len() == segment_count {
            let hdr_sk = parse_private_key_hex(&saved.program_header_privkey_hex)?;
            let hdr_id = account_id_of(&hdr_sk);
            let mut segs = Vec::with_capacity(segment_count);
            for h in &saved.segment_privkeys_hex {
                let s = parse_private_key_hex(h)?;
                let id = account_id_of(&s);
                segs.push((s, id));
            }
            return Ok((hdr_sk, hdr_id, segs));
        }
    }

    let hdr_sk = generate_fresh_key()?;
    let hdr_id = account_id_of(&hdr_sk);
    let mut segs = Vec::with_capacity(segment_count);
    let mut seg_addrs = Vec::with_capacity(segment_count);
    let mut seg_hex = Vec::with_capacity(segment_count);

    for _ in 0..segment_count {
        let s = generate_fresh_key()?;
        let id = account_id_of(&s);
        seg_addrs.push(id.to_string());
        seg_hex.push(hex::encode(s.value()));
        segs.push((s, id));
    }

    if let Some(parent) = secret_key_store.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = EphemeralDeployKeys {
        program_header_account: hdr_id.to_string(),
        program_header_privkey_hex: hex::encode(hdr_sk.value()),
        segment_accounts: seg_addrs,
        segment_privkeys_hex: seg_hex,
    };
    fs::write(secret_key_store, serde_json::to_string_pretty(&payload)?)?;
    Ok((hdr_sk, hdr_id, segs))
}
