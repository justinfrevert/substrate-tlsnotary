#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(enable_alloc_error_handler, feature(alloc_error_handler))]

use sp_runtime_interface::runtime_interface;

#[cfg(feature = "std")]
use tlsn_core::proof::TlsProof;
use p256::pkcs8::DecodePublicKey;
use codec::Decode;

#[runtime_interface]
pub trait TlsnVerifierPrimitive {
    fn do_verify(&self, escaped_encoded_proof_json: &[u8]) -> (bool, u8) {
        let onchain_proof: TlsProof = {
            let mut escaped_encoded_proof_json = escaped_encoded_proof_json.clone();
            let escaped_proof_json_str = String::decode(&mut escaped_encoded_proof_json).unwrap();
                serde_json::from_str(&escaped_proof_json_str).unwrap()
        };
        let TlsProof {
            session,
            substrings: _,
        } = onchain_proof;

        let verify_result = session.verify_with_default_cert_verifier(notary_pubkey()).is_ok();
        (verify_result, session.header.encoder_seed()[0])
    }
}

#[cfg(feature = "std")]
fn notary_pubkey() -> p256::PublicKey {
    let pem_file_path = "notary.pem";
    p256::PublicKey::read_public_key_pem_file(pem_file_path).unwrap()
}