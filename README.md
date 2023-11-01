# Substrate + TLS Notary 

A basic example of using TLS Notary verification from Substrate

## Installation
See [Substrate installation steps](https://docs.substrate.io/install/) for getting started.

## Run the chain 
cargo run -- --dev

## Prover
Run the prover from `./prover`

### Installation and prep
cargo install subxt-cli
subxt metadata -f bytes > metadata.scale

### Running
Pass the path of the proof file. NOTE: Currently only supports proofs generated using the configuration of the [TLS Notary simple example](https://github.com/tlsnotary/tlsn/blob/dev/tlsn/examples/simple/simple_prover.rs).

cargo run --  proof.json