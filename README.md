<div align="center">
  <h1>EDK</h1>

  <p>
    <span>Elements Dev Kit</span>
    <strong>A modern, lightweight, descriptor-based wallet library for Elements / Liquid written in Rust!</strong>
  </p>

  <p>
    <a href="https://github.com/lvaccaro/edk-lite/actions?query=workflow%3Aci"><img alt="CI Status" src="https://github.com/lvaccaro/edk-lite/workflows/ci/badge.svg"></a>
  </p>

</div>

## About

It uses Elements Miniscript to support descriptors with generalized conditions.

Based on:
- [rust-elements](https://github.com/ElementsProject/rust-elements/): Library with support for de/serialization, parsing and executing on data structures and network messages related to Elements
- [rust-miniscript-elements](https://github.com/sanket1729/rust-miniscript-elements): Library for handling Miniscript, which is a subset of Elements Script designed to support simple and general tooling.


## Examples

### Sync the balance of a descriptor

```rust,no_run
    let database = MemoryDatabase::new();
    let client = Client::new("ssl://blockstream.info:995").unwrap();
    let wallet = Wallet::new(descriptor, master_blinding_key, database, client).unwrap();
    let balance = wallet.balance().unwrap();
    println!("AssetId: Value");
    for b in balance {
        println!("{}: {}", b.0, b.1);
    }
```

### Generate a few addresses

```rust,no_run
    let database = MemoryDatabase::new();
    let client = Client::new("ssl://blockstream.info:995").unwrap();
    let wallet = Wallet::new(descriptor, master_blinding_key, database, client).unwrap();
    println!("Address #0: {}", wallet.get_new_address()?);
    println!("Address #1: {}", wallet.get_new_address()?);
    println!("Address #2: {}", wallet.get_new_address()?);
```

## Testing

### Unit testing

```
cargo test
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
