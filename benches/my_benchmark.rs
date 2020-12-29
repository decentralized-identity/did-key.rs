use criterion::{black_box, criterion_group, criterion_main, Criterion};
use did_key::*;

fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 1,
        1 => 1,
        n => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("edwards new", |b| b.iter(|| DIDKey::new(DIDKeyType::Ed25519)));

    c.bench_function("montgomery new", |b| b.iter(|| DIDKey::new(DIDKeyType::X25519)));

    c.bench_function("p256 new", |b| b.iter(|| DIDKey::new(DIDKeyType::P256)));

    c.bench_function("bls new", |b| b.iter(|| DIDKey::new(DIDKeyType::Bls12381G1G2)));

    // key exchange using montgomery
    let a1 = DIDKey::new(DIDKeyType::X25519);
    let b1 = DIDKey::new(DIDKeyType::X25519);

    c.bench_function("montgomery exchange", |b| b.iter(|| a1.key_exchange(&b1)));

    // key exchange using Secp256k1
    let a2 = DIDKey::new(DIDKeyType::Secp256k1);
    let b2 = DIDKey::new(DIDKeyType::Secp256k1);

    c.bench_function("secp256k1 exchange", |b| b.iter(|| a2.key_exchange(&b2)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
