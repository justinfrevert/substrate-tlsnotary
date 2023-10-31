#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(enable_alloc_error_handler, feature(alloc_error_handler))]

use sp_runtime_interface::{
	pass_by::{PassBy, PassByCodec},
	runtime_interface, Pointer,
};

#[cfg(feature = "std")]
use tlsn_core::proof::{SessionProof, TlsProof};

use p256::pkcs8::DecodePublicKey;

const PROOF_JSON: &str = include_str!("proof.json");

#[runtime_interface]
pub trait TlsnVerifierPrimitive {
    fn do_verify(&self, key: &[u8]) -> (bool, u8) {
        #[cfg(feature = "std")]
        {
            let proof: TlsProof = serde_json::from_str(PROOF_JSON).unwrap();
            let TlsProof {
                session,
                substrings,
            } = proof;

            let verify_result = session.verify_with_default_cert_verifier(notary_pubkey()).is_ok();
            (verify_result, session.header.encoder_seed()[0])
        }

        #[cfg(not(feature = "std"))]
        {
            (false, 0)
        }
    }
}

#[cfg(feature = "std")]
fn notary_pubkey() -> p256::PublicKey {
    let pem_file_path = "notary.pem";
    p256::PublicKey::read_public_key_pem_file(pem_file_path).unwrap()
}