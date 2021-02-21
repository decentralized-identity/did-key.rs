use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use did_key::*;
use std::fmt::Debug;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("edwards new", |b| b.iter(|| generate::<Ed25519KeyPair>()));

    c.bench_function("montgomery new", |b| b.iter(|| generate::<X25519KeyPair>()));

    c.bench_function("p256 new", |b| b.iter(|| generate::<P256KeyPair>()));

    c.bench_function("bls new", |b| b.iter(|| generate::<Bls12381KeyPair>()));

    // key exchange using montgomery
    let a1 = generate::<X25519KeyPair>();
    let b1 = generate::<X25519KeyPair>();

    c.bench_function("montgomery exchange", |b| b.iter(|| a1.key_exchange(&b1)));

    // key exchange using Secp256k1
    let a2 = generate::<Secp256k1KeyPair>();
    let b2 = generate::<Secp256k1KeyPair>();

    c.bench_function("secp256k1 exchange", |b| b.iter(|| a2.key_exchange(&b2)));

    // signature benchmarks
    let payloads: Vec<Buffer> = vec![
        Buffer { data: &[0; 256] },
        Buffer { data: &[0; 1024] },
        Buffer {
            data: &[0; 1024 * 1024],
        },
        Buffer {
            data: &[0; 1024 * 1024 * 5],
        },
    ];

    let ed_key = generate::<Ed25519KeyPair>();
    let bls_key = generate::<Bls12381KeyPair>();
    let p256_key = generate::<P256KeyPair>();

    c.bench_function_over_inputs(
        "ed sign",
        move |b: &mut Bencher, payload: &Buffer| {
            b.iter(|| ed_key.sign(Payload::Buffer(payload.data.to_vec())));
        },
        payloads.clone(),
    );

    c.bench_function_over_inputs(
        "p256 sign",
        move |b: &mut Bencher, payload: &Buffer| {
            b.iter(|| p256_key.sign(Payload::Buffer(payload.data.to_vec())));
        },
        payloads.clone(),
    );

    c.bench_function_over_inputs(
        "bls sign",
        move |b: &mut Bencher, payload: &Buffer| {
            b.iter(|| bls_key.sign(Payload::BufferArray(vec![payload.data.to_vec()])));
        },
        payloads,
    );
}

#[derive(Clone)]
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
