#![warn(missing_docs)]
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
	/// Returns the data for `key` in the storage or `None` if the key can not be found.
	fn do_verify(&self, key: &[u8]) -> (bool, u8) {
		// false

		// #[cfg(feature = "std")]
		// let proof = std::fs::read_to_string("proof.json").unwrap();

		#[cfg(feature = "std")]
		let proof: TlsProof = serde_json::from_str(PROOF_JSON).unwrap();

		#[cfg(feature = "std")]
		let TlsProof {
			// The session proof establishes the identity of the server and the commitments
			// to the TLS transcript.
			session,
			// The substrings proof proves select portions of the transcript, while redacting
			// anything the Prover chose not to disclose.
			substrings,
		} = proof;

		// Verify the session proof against the Notary's public key
		//
		// This verifies the identity of the server using a default certificate verifier which
		// trusts the root certificates from the `webpki-roots` crate.

		// let notary_key = "-----BEGIN PUBLIC KEY-----
		// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBv36FI4ZFszJa0DQFJ3wWCXvVLFr
		// cRzMG5kaTeHGoSzDu6cFqx3uEWYpFGo6C0EOUgf+mEgbktLrXocv5yHzKg==
		// -----END PUBLIC KEY-----
		// "
		// .to_string();

		// #[cfg(feature = "std")]
		// println!("Notary key {:?}", notary_key);

		#[cfg(feature = "std")]
		let verify_result = session.verify_with_default_cert_verifier(notary_pubkey());

		#[cfg(feature = "std")]
		println!("VERIFy result {:?}", verify_result);

		#[cfg(feature = "std")]
		(verify_result, session.header.encoder_seed()[0]);

		#[cfg(not(std))]
		(false, 0)
	}
}

#[cfg(feature = "std")]
fn notary_pubkey() -> p256::PublicKey {
	#[cfg(feature = "std")]
	let pem_file_path = "notary.pem";
	#[cfg(feature = "std")]
	p256::PublicKey::read_public_key_pem_file(pem_file_path).unwrap()
}
