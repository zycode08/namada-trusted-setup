![Alt text](./namada-trusted-setup.jpeg?raw=true "Namada Trusted Setup")

<h1 align="center">Namada Trusted Setup</h1>

The Namada Trusted Setup Ceremony generates the public parameters for the Multi-Asset Shielded Pool (MASP) circuit and guarantees its security. For more context, see the article [Announcing the Namada Trusted Setup](https://blog.namada.net/announcing-the-namada-trusted-setup-ceremony/). This repository contains the coordinator code and CLI for the Ceremony.

### Signing up for the Ceremony

- Participants signed through a public mailing list.
- The registrations [closed at 00:00 UTC on the 15th of November 2022](https://twitter.com/namadanetwork/status/1592306386779742208?s=20&t=vbUGK9sZVB_eBJbDCSrhmg).

### Ceremony dashboard

During the ceremony, valid contributions will appear on the [Namada Ceremony Dashboard](http://ceremony.namada.net/)

### About Namada

[Namada](https://namada.net/) is a Proof-of-Stake layer 1 protocol for asset-agnostic, interchain privacy. Namada is Anoma's first fractal instance.

To learn more about the protocol, we recommend the following resources:

- [Introducing Namada: Interchain Asset-agnostic Privacy](https://blog.namada.net/introducing-namada-interchain-asset-agnostic-privacy/)
- [What is Namada?](https://blog.namada.net/what-is-namada/)
- [Namada protocol specifications](https://specs.namada.net)

# Participating

The Namada Trusted Setup CLI exposes two ways to contribute:

- **default**, performs the entire contribution on the current machine `default` 
- **offline**, computes the contribution on a separate (possibly offline) machine (more details [here](#computation-on-another-machine))

This documentation provides instructions to contribute:

1. By building the CLI from source
2. From prebuilt binaries (manual setup)
3. From prebuilt binaries (automated setup)

Participants are also encouraged to participate via their custom clients. For more suggestions on best practices, refer to [`RECOMMENDATIONS.md`](RECOMMENDATIONS.md).

## Contribution tokens

- Each participant needs a unique token (`$TOKEN`) in order to participate in the ceremony. If your slot was confirmed, you should've received it by email before the start of the ceremony (09:00 UTC on the 19th of November 2022).
- If you didn't receive a token but wish to participate, you can use the _first come, first served_ list of tokens during the free-for-all cohorts in the ceremony. Follow [@namadanetwork](https://twitter.com/namadanetwork) on Twitter for updates.

## 1. Building and contributing from source

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
cd namada-trusted-setup && git checkout v1.0.0-10
```

Build the binary:
```
cargo build --release --bin namada-ts --features cli
```

Move binary on `$PATH` (might require sudo):
```
mv target/release/namada-ts /usr/local/bin 
```

Start your contribution:
```
namada-ts contribute default https://ceremony.namada.net $TOKEN
```

## 2. Contributing from prebuilt binaries (manual setup)

We provide prebuilt `x86_64` binaries for Linux, MacOS and Windows. For this, go to the [Releases page](https://github.com/anoma/namada-trusted-setup/releases) and download the latest version of the client.

After download, you might need to give execution permissions with:
```chmod +x namada-ts-{distrib}-{version}```

Finally start the client with:
```
./namada-ts-{distrib}-{version} contribute default https://ceremony.namada.net $TOKEN
```

## 3. Contributing from prebuilt binaries (automated setup)

If you are on Linux or MacOS, we also provide an install script to automate binary setup. You can run the following command:

```
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/anoma/namada-trusted-setup/main/install.sh | sh
```

and you are ready to contribute:
```
namada-ts contribute default https://ceremony.namada.net $TOKEN
```

### Troubleshooting

In MacOS, you might see appearing the warning "cannot be opened because the developer cannot be verified". To solve this, open the "Security & Privacy" control panel from System Preferences. In `general` tab, next to the info that the binary was prevented from running, click `Allow Anyway`. Run the binary again. This time a different prompt is shown. Click `Open` - the binary should run as you expect.

## Advanced features
Advanced features are available to encourage creativity during your contribution.

### Computation on another machine
You can generate the parameters on a machine that is offline or never connected to internet. Some examples are an air-gapped machine, a brand-new computer or a Raspberry PI. You will still need a second machine connected to the internet to carry out the necessary communication with the coordinator.

On the online machine give the following command:

```
cargo run --release --bin namada-ts --features cli contribute another-machine https://ceremony.namada.net $TOKEN
```

This will start the communication process to join the ceremony and download/upload the necessary files. On the offline machine use the following command:

```
cargo run --release --bin namada-ts --features cli contribute offline
```

which will compute the contribution itself. This second command expects the file `challenge.params` got from the online machine to be available in the cwd and it will produce a `contribution.params` to be passed back to the online machine for shipment to the coordinator. The user will be responsible for moving these files around.

### Verify your contribution

If you want to verify your contribution you can do it via CLI. After you have successfully contributed, a file called `namada_contributor_info_round_${round_height}.json` will be generated and saved in the same folder of the `namada-ts` binary. The file contains a json structure. You should copy the value following fields:

- `public_key`
- `contribution_hash`
- `contribution_hash_signature`

and input them to:

```
namada-ts verify-contribution $public_key $contribution_hash $contribution_hash_signature
```

## Client Contribution Flow

1. The client will ask you if you want to contribute anonymously:
    - If yes, your contribution will show as "anonymous" on the dashboard.
    - If no, you'll be asked to provide a name and an email address.

2. Generation of a mnemonic: every participant will be asked to generate a mnemonic. These are compatible with accounts on Namada and you will need it if you end up being rewarded for your contribution! 
    - The CLI will request you to verify 3 phrases of your mnemonic.
    - If you fail the verification, the CLI will crash and you'll have to start anew.

3. You will need to wait a bit until it is your turn. Each round lasts between 4 min and 20 min. During the whole ceremony, please neither close your terminal, nor your internet connection. If you stay offline for more than 2 min, the coordinator will kick you out from the queue.

4. When it is your turn, the client will download the challenge from the coordinator and save it to the root folder. The client will request you to enter:
    - A frenetically typed string
    - Or a string representation of your alternative source of randomness
    
5. You have at most **20 minutes** to compute your contribution and send it back to the coordinator.

6. After successfully contributing, you can optionally submit a public attestation url (e.g. link to a tweet, article documenting your setup, video, etc). Note that the url must be `http` or `https`.

7. If your contribution was valid, it'll show up on the dashboard!

# Directory Structure

This repository contains several Rust crates that implement the different building blocks of the MPC. The high-level structure of the repository is as follows:
- [`phase2-cli`](phase2-cli): Rust crate that provides a HTTP client that communicates with the REST API endpoints of the coordinator and uses the necessary cryptographic functions to contribute to the trusted setup.
- [`phase2-coordinator`](phase2-coordinator): Rust crate that provides a coordinator library and a HTTP REST API that allow contributors to interact with the coordinator. The coordinator handles the operational steps of the ceremony like: adding a new contributor to the queue, authentificating a contributor, sending and receiving challenge files, removing inactive contributors, reattributing challenge file to a new contributor after a contributor dropped, verifying contributions, creating new files, etc.
- [`phase2`](phase2) and [`setup-utils`](setup-utils): contain utils used in both the client and the coordinator.
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

- [Reddit](https://www.reddit.com/r/Namada/)
