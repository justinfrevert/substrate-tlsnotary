use clap::{App, Arg};
use codec::Encode;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;
use std::fs;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "./node_metadata.scale")]
pub mod node {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("Your App Name")
        .arg(Arg::with_name("file")
            .help("Path to the JSON file containing the proof")
            .required(true)
            .index(1))
        .get_matches();
    let file_path = matches.value_of("file").unwrap();

    let proof_json_minified = fs::read_to_string(file_path)?;
    let scale_encoded = proof_json_minified.encode();

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
