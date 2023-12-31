use criterion::{Criterion, criterion_group, criterion_main};

use fips203::{ml_kem_1024, ml_kem_512, ml_kem_768};
use fips203::traits::{Decaps, Encaps, KeyGen};

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

Initial conditions

cargo bench
Intel® Core™ i7-7700K CPU @ 4.20GHz × 8

ml_kem_512 KeyGen       time:   [64.996 µs 65.084 µs 65.246 µs]
ml_kem_768 KeyGen       time:   [102.50 µs 102.54 µs 102.62 µs]
ml_kem_1024 KeyGen      time:   [148.28 µs 148.33 µs 148.38 µs]

ml_kem_512 Encaps       time:   [77.391 µs 77.424 µs 77.489 µs]
ml_kem_768 Encaps       time:   [117.76 µs 117.83 µs 117.90 µs]
ml_kem_1024 Encaps      time:   [167.77 µs 167.79 µs 167.82 µs]

ml_kem_512 Decaps       time:   [75.627 µs 75.671 µs 75.745 µs]
ml_kem_768 Decaps       time:   [115.20 µs 115.24 µs 115.27 µs]
ml_kem_1024 Decaps      time:   [164.48 µs 164.56 µs 164.67 µs]

 */
