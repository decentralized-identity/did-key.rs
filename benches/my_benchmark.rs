use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use did_key::*;
use std::fmt::Debug;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group_key = c.benchmark_group("key generation");

    group_key.bench_function("edwards new", |b| b.iter(|| generate::<Ed25519KeyPair>(None)));
    group_key.bench_function("montgomery new", |b| b.iter(|| generate::<X25519KeyPair>(None)));
    group_key.bench_function("p256 new", |b| b.iter(|| generate::<P256KeyPair>(None)));
    group_key.bench_function("bls new", |b| b.iter(|| generate::<Bls12381KeyPairs>(None)));

    group_key.finish();

    let mut group_exch = c.benchmark_group("key exchange");

    // key exchange using montgomery
    let a1 = X25519KeyPair::new();
    let b1 = X25519KeyPair::new();

    group_exch.bench_function("montgomery exchange", |b| b.iter(|| a1.key_exchange(&b1)));

    // key exchange using Secp256k1
    let a2 = Secp256k1KeyPair::new();
    let b2 = Secp256k1KeyPair::new();

    group_exch.bench_function("secp256k1 exchange", |b| b.iter(|| a2.key_exchange(&b2)));

    group_exch.finish();

    // signature benchmarks
    let payloads: Vec<Buffer> = vec![
        Buffer { data: &[0; 256] },
        Buffer { data: &[0; 1024] },
        Buffer { data: &[0; 1024 * 1024] },
        Buffer { data: &[0; 1024 * 1024 * 5] },
    ];

    let ed_key = generate::<Ed25519KeyPair>(None);
    let bls_key = generate::<Bls12381KeyPairs>(None);
    let p256_key = generate::<P256KeyPair>(None);

    let mut group_sign = c.benchmark_group("signatures");

    for payload in payloads {
        group_sign.bench_with_input(BenchmarkId::new("ed sign", payload.data.len()), &payload, |b, &payload| {
            b.iter(|| ed_key.sign(payload.data))
        });

        group_sign.bench_with_input(BenchmarkId::new("p256 sign", payload.data.len()), &payload, |b, &payload| {
            b.iter(|| p256_key.sign(payload.data))
        });

        group_sign.bench_with_input(BenchmarkId::new("bls sign", payload.data.len()), &payload, |b, &payload| {
            b.iter(|| bls_key.sign(payload.data))
        });
    }

    group_sign.finish();
}

#[derive(Copy, Clone)]
struct Buffer<'a> {
    data: &'a [u8],
}

// Pretty print human readable byte sizes
fn convert(num: f64) -> String {
    let negative = if num.is_sign_positive() { "" } else { "-" };
    let num = num.abs();
    let units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    if num < 1_f64 {
        return format!("{}{} {}", negative, num, "B");
    }
    let delimiter = 1024_f64;
    let exponent = std::cmp::min((num.ln() / delimiter.ln()).floor() as i32, (units.len() - 1) as i32);
    let pretty_bytes = format!("{:.2}", num / delimiter.powi(exponent)).parse::<f64>().unwrap() * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
}

impl Debug for Buffer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //f.write_fmt(format_args!("{:?} bytes", self.data.len()))
        f.write_str(&convert(self.data.len() as f64).to_string())
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
