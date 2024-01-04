use criterion::{criterion_group, criterion_main, Criterion};

use fips203::traits::{Decaps, Encaps, KeyGen};
use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};

pub fn criterion_benchmark(c: &mut Criterion) {
    let (ek_512, dk_512) = ml_kem_512::KG::try_keygen_vt().unwrap();
    let (_, ct_512) = ek_512.try_encaps_vt().unwrap();
    let (ek_768, dk_768) = ml_kem_768::KG::try_keygen_vt().unwrap();
    let (_, ct_768) = ek_768.try_encaps_vt().unwrap();
    let (ek_1024, dk_1024) = ml_kem_1024::KG::try_keygen_vt().unwrap();
    let (_, ct_1024) = ek_1024.try_encaps_vt().unwrap();

    c.bench_function("ml_kem_512 KeyGen", |b| b.iter(|| ml_kem_512::KG::try_keygen_vt()));
    c.bench_function("ml_kem_512 Encaps", |b| b.iter(|| ek_512.try_encaps_vt()));
    c.bench_function("ml_kem_512 Decaps", |b| b.iter(|| dk_512.try_decaps_vt(&ct_512)));

    c.bench_function("ml_kem_768 KeyGen", |b| b.iter(|| ml_kem_768::KG::try_keygen_vt()));
    c.bench_function("ml_kem_768 Encaps", |b| b.iter(|| ek_768.try_encaps_vt()));
    c.bench_function("ml_kem_768 Decaps", |b| b.iter(|| dk_768.try_decaps_vt(&ct_768)));

    c.bench_function("ml_kem_1024 KeyGen", |b| b.iter(|| ml_kem_1024::KG::try_keygen_vt()));
    c.bench_function("ml_kem_1024 Encaps", |b| b.iter(|| ek_1024.try_encaps_vt()));
    c.bench_function("ml_kem_1024 Decaps", |b| b.iter(|| dk_1024.try_decaps_vt(&ct_1024)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

/*

cargo bench # As of 1-1-24
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

ml_kem_512 KeyGen       time:   [63.821 µs 63.830 µs 63.839 µs]
ml_kem_768 KeyGen       time:   [100.88 µs 100.89 µs 100.90 µs]
ml_kem_1024 KeyGen      time:   [146.53 µs 146.61 µs 146.70 µs]

ml_kem_512 Encaps       time:   [76.934 µs 76.948 µs 76.961 µs]
ml_kem_768 Encaps       time:   [117.93 µs 118.01 µs 118.08 µs]
ml_kem_1024 Encaps      time:   [168.68 µs 168.76 µs 168.85 µs]

ml_kem_512 Decaps       time:   [76.749 µs 76.887 µs 77.071 µs]
ml_kem_768 Decaps       time:   [117.05 µs 117.34 µs 117.84 µs]
ml_kem_1024 Decaps      time:   [167.51 µs 167.53 µs 167.57 µs]

 */
