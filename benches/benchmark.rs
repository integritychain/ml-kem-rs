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

ml_kem_512 KeyGen       time:   [81.377 µs 81.607 µs 82.058 µs]
ml_kem_768 KeyGen       time:   [141.22 µs 141.24 µs 141.26 µs]
ml_kem_1024 KeyGen      time:   [196.07 µs 196.11 µs 196.16 µs]

ml_kem_512 Encaps       time:   [103.26 µs 103.40 µs 103.60 µs]
ml_kem_768 Encaps       time:   [175.28 µs 175.30 µs 175.32 µs]
ml_kem_1024 Encaps      time:   [241.54 µs 241.58 µs 241.64 µs]

ml_kem_512 Decaps       time:   [110.86 µs 110.88 µs 110.90 µs]
ml_kem_768 Decaps       time:   [188.13 µs 188.19 µs 188.28 µs]
ml_kem_1024 Decaps      time:   [262.80 µs 263.47 µs 264.59 µs]

 */
