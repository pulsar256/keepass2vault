# keepass2vault

Hacked together motivated by personal needs.

## Build

```shell
cargo build
```

## Usage

`cargo run` or built binary from `./target/[release/debug]/keepass2vault`

```
 ᐅ keepass2vault
imports all secrets from a keepass file into Hashicorp-vault

Usage: keepass2vault [OPTIONS]

Options:
      --vault-addr <VAULT_ADDR>
          [env: VAULT_ADDR=] [default: http://127.0.0.1:8200]
      --vault-token <VAULT_TOKEN>
          [env: VAULT_TOKEN=]
      --keepass-file <KEEPASS_FILE>
          [env: KEEPASS_FILE=]
      --keepass-password <KEEPASS_PASSWORD>
          [env: KEEPASS_PASSWORD=]
      --path-prefix <PATH_PREFIX>
          vault path prefix [env: VAULT_PATH_PREFIX=] [default: ]
      --mount <MOUNT>
          vault mountpoint of the kv2 [env: VAULT_MOUNT=] [default: secret]
  -v
          verbose output if not specified otherwise by the RUST_LOG environment variable. [env: DEBUG=]
  -h, --help
          Print help information
  -V, --version
          Print version information
```
