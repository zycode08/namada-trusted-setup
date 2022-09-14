![Alt text](./namada-trusted-setup.jpeg?raw=true "Namada Trusted Setup")

<h1 align="center">Namada Trusted Setup</h1>

The Namada Trusted Setup Ceremony generates the public parameters for the Multi-Asset Shielded Pool (MASP) circuit and guarantees its security. Under the hood, a trusted setup ceremony is a multi-party computation (MPC) that lets many participants contribute randomness to the public parameters in a trustless manner. The setup is secure, as long as one participant is honest.

# About Namada

[Namada](https://namada.net/) is a sovereign proof-of-stake blockchain, using Tendermint BFT consensus, that enables multi-asset private transfers for any native or non-native asset using a multi-asset shielded pool derived from the Sapling circuit. 

To learn more about the protocol, we recommend the following resources:

- [Introducing Namada: Shielded Transfers with Any Assets](https://medium.com/anomanetwork/introducing-namada-shielded-transfers-with-any-assets-dce2e579384c)
- [Namada's specifications](https://specs.namada.net)

# Participate in Namada Trusted Setup
If you are interested in participating in the ceremony head over to the [Namada website](https://namada.net/trusted-setup.html) and [sign up to the newsletter](https://dev.us7.list-manage.com/subscribe?u=69adafe0399f0f2a434d8924b&id=9e747afc55) to be notified about the launch.

## Contributing from prebuilt binaries
We provide prebuilt binaries for Ubuntu and MacOS. For this, go to the [Releases page](https://github.com/anoma/namada-trusted-setup/releases) and download the latest version of the client.

After download, you might need to give execution permissions with `chmod +x phase1-{distrib}-{version}`.

Finally start the client with:
```
./phase1-{distrib}-{version} https://contribute.namada.net
```
### Troubleshooting
In MacOS, you might see appearing the warning "cannot be opened because the developer cannot be verified". To solve this, open the "Security & Privacy" control panel from System Preferences. In `general` tab, next to the info that the binary was prevented from running, click `Allow Anyway`. Run the binary again. This time a different prompt is shown. Click `Open` - the binary should run as you expect.

## Building and contributing from source

First, [install Rust](https://www.rust-lang.org/tools/install) by entering the following command:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you already have Rust installed, make sure it is the most up-to-date version:
```
rustup update
```

Once Rust is installed, clone the Namada Trusted Setup Ceremony GitHub repository and change directories into `namada-trusted-setup`:
```
git clone https://github.com/anoma/namada-trusted-setup.git
cd namada-trusted-setup
```

Build the binaries and start your contribution with:
```
cargo run --release --bin phase1 --features cli contribute default https://contribute.namada.net
```

## Advanced features
Advanced features are available to encourage creativity during your contribution.

### Computation on another machine
You can generate the parameters on a machine that is offline or never connected to internet. Some examples are an air-gapped machine, a brand-new computer or a Raspberry PI.

To use this feature, add the `--another-machine` flag to your command.

### Custom random seed
You can provide your own random seed (32 bytes) to initialize the ChaCha RNG. This is useful if you are using an external source of randomness or don't want to use the OS randomness. Some examples are atmospheric noise, radioactive elements or lava lite.

To use this feature, add the `--custom-seed` flag to your command.

## Understanding the ceremony

1. The client will ask you if you want to take part in the incentivized program. If you answer 'yes', it will generate a secret mnemonic that derives your key pair.  Back up your mnemonic and keep it in a safe place! This is the only way to prove your contribution and claim your rewards later.

2. Then, you will need to provide the unique token for your cohort you received by email. If the token is valid, you will join the queue of the ceremony. You will need to wait a bit until it is your turn. Each round lasts between 4 min and 20 min. During the whole ceremony, please neither close your terminal, nor your internet connection. If you stay offline for more than 2 min, the coordinator will kick you out from the queue.

3. When it is your turn, the client will download the challenge from the coordinator and save it to the root folder. You have at most 20 minutes to compute your contribution and send it back to the coordinator. Be creative and good luck!

## Client Contribution Flow 
![Alt text](./ceremony-contribution-diagram.png?raw=true "Ceremony Contribution Flow")

# Overview of previous trusted setup ceremonies

Pairing based zk-SNARKs require the generation of certain parameters in order to achieve high efficiency (small proof sizes, fast proving and verifying time). These parameters are generated by another set of parameters which MUST remain secret. We call these secret parameters the "toxic waste". If a prover knows these secrets, [then they can generate valid proofs for invalid statements](https://medium.com/qed-it/how-toxic-is-the-waste-in-a-zksnark-trusted-setup-9b250d59bdb4), breaking soundness. This is undesired!

In order to guarantee that no prover will ever know these secrets, we can generate them in a distributed manner. Each participant in this so-called "ceremony" will contribute to the generation of the parameters with their own secret. If at least 1 participant is honest and destroys their secret, then there should be no way for a malicious prover to create fake proofs.

This repository contains implementations for the [BGM17](https://eprint.iacr.org/2017/1050) multi party computation. The ceremony is split 
in two phases, one which generates the _Powers of Tau_, and one which "specializes" them to the provided arithmetic circuit for the Groth16 zk-SNARK and this is where we will construct our MASP zk-SNARK. 

Note that the generated Powers of Tau can be re-used for any other Phase 2 setup, or for instantiating other mechanisms, such as the [KZG10](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf) polynomial commitment scheme.

For instructions on how to ensure that the ceremony is executed properly, refer to [`RECOMMENDATIONS.md`](RECOMMENDATIONS.md).


# Directory Structure

This repository contains several Rust crates that implement the different building blocks of the MPC. The high-level structure of the repository is as follows:
- [`phase1-cli`](phase1-cli): Rust crate that provides a HTTP client that communicates with the REST API endpoints of the coordinator and uses the necessary cryptographic functions to contribute to the trusted setup.
- [`phase1-coordinator`](phase1-coordinator): Rust crate that provides a coordinator library and a HTTP REST API that allow contributors to interact with the coordinator. The coordinator handles the operational steps of the ceremony like: adding a new contributor to the queue, authentificating a contributor, sending and receiving challenge files, removing inactive contributors, reattributing challenge file to a new contributor after a contributor dropped, verifying contributions, creating new files, etc.
- [`phase1`](phase1) and [`setup-utils`](setup-utils): contain utils used in both the client and the coordinator.
- The remaining files contain configs for CI and deployment to AWS EC2 and S3 bucket.

# Audits

The original implementation of the coordinator for the [Aleo Trusted Setup](https://github.com/AleoHQ/aleo-setup) was audited by: 

- [Least Authority](https://leastauthority.com/blog/audit-of-aleo-trusted-setup-phase-1/)

# License

All code in this workspace is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

# Community support

- [Discord](https://discord.com/invite/anoma) (Questions and discussions on Namada)
- [Twitter](https://twitter.com/namadanetwork)
