use tlsn_core;
const PROOF_JSON_MINIFIED: &str = include_str!("externalProofMinified.json");

use codec::Encode;

use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./node_metadata.scale")]
pub mod node {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let scale_encoded = PROOF_JSON_MINIFIED.encode();

    let api = OnlineClient::<PolkadotConfig>::new().await?;
    let verify_proof_tx = node::tx().template_module().verify_proof(
		scale_encoded
	);

    let from = dev::alice();
    let events = api
        .tx()
        .sign_and_submit_then_watch_default(&verify_proof_tx, &from)
        .await?
        .wait_for_finalized_success()
        .await?;

    let proof_submission_event = events.find_first::<node::template_module::events::ProofVerification>()?;
    if let Some(event) = proof_submission_event {
        println!("Proof Submission success: {event:?}");
    }

    Ok(())
}
