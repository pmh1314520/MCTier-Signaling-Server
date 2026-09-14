//! Authentication, registration proof, and credential primitives.
use super::*;

pub(crate) const CHAT_TOKEN_BYTES: usize = 32;

pub(crate) fn generate_chat_token() -> String {
    let mut bytes = [0u8; CHAT_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 大厅密码盐长度：每个大厅创建时生成，随大厅生命周期存放于内存。
pub(crate) const LOBBY_PASSWORD_SALT_BYTES: usize = 16;

/// 大厅密码哈希混合每大厅随机盐，使弱口令无法命中现成的彩虹表。
pub(crate) fn hash_lobby_password(salt: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 常量时间比较，避免密码哈希校验的时间侧信道
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub(crate) fn random_session_generation() -> u64 {
    // Keep the value in JavaScript's safe-integer range while retaining at
    // least 16 decimal digits for desktop clients' generation validator.
    loop {
        let value = OsRng.next_u64() & ((1u64 << 53) - 1);
        if (1_000_000_000_000_000..=9_000_000_000_000_000).contains(&value) {
            return value;
        }
    }
}

pub(crate) fn registration_canonical(
    challenge: &str,
    lobby_name: &str,
    virtual_ip: &str,
) -> Vec<u8> {
    format!(
        "MCTIER-SIGNALING-V3\n{}\n{}\n{}\n{}",
        SIGNALING_PROTOCOL_VERSION, challenge, lobby_name, virtual_ip
    )
    .into_bytes()
}

/// Validate the v3 proof and derive the only client id accepted by the server.
pub(crate) fn verify_registration_identity(
    challenge: &str,
    lobby_name: &str,
    virtual_ip: &str,
    identity_public_key: &str,
    challenge_signature: &str,
) -> Option<(String, String, String)> {
    let encoded = identity_public_key.trim();
    if encoded.is_empty() || encoded.len() > MAX_IDENTITY_PUBLIC_KEY_LEN {
        return None;
    }
    let public_key_der = BASE64_STANDARD.decode(encoded).ok()?;
    if public_key_der.is_empty() || public_key_der.len() > 200 {
        return None;
    }
    let verifying_key = VerifyingKey::from_public_key_der(&public_key_der).ok()?;

    let encoded_signature = challenge_signature.trim();
    if encoded_signature.is_empty() || encoded_signature.len() > MAX_IDENTITY_SIGNATURE_LEN {
        return None;
    }
    let signature_der = BASE64_STANDARD.decode(encoded_signature).ok()?;
    let signature = Signature::from_der(&signature_der).ok()?;
    verifying_key
        .verify(
            &registration_canonical(challenge, lobby_name, virtual_ip),
            &signature,
        )
        .ok()?;

    let digest = Sha256::digest(&public_key_der);
    let client_id = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let virtual_domain = format!("{}.mct.net", &client_id[..32]);
    Some((client_id, encoded.to_string(), virtual_domain))
}
