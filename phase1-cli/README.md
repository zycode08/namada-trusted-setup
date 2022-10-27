# Phase 1 CLI

## Coordinator

The coordinator can be started by simply giving:

```shell
cargo run --features=parallel --bin phase1-coordinator
```

## Contributor

To contribute to the ceremony simply give:

```shell
cargo run --bin namada-ts --features=cli contribute default $(coordinator-ip:port)
```

You can also test a contribution against a local coordinator (running at `127.0.0.1:8000`) with:

```shell
make contribution
```

## License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license (LICENSE-MIT or <http://opensource.org/licenses/MIT>)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
