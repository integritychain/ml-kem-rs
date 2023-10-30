use criterion::{black_box, Criterion, criterion_group, criterion_main};
use ml_kem_rs::{ml_kem_1024, ml_kem_512, ml_kem_768};

pub fn criterion_benchmark(c: &mut Criterion) {
    let (ek_512, dk_512) = ml_kem_512::key_gen();
    let (_, ct_512) = ek_512.encaps();
    let (ek_768, dk_768) = ml_kem_768::key_gen();
    let (_, ct_768) = ek_768.encaps();
    let (ek_1024, dk_1024) = ml_kem_1024::key_gen();
    let (_, ct_1024) = ek_1024.encaps();

    c.bench_function("ml_kem_512 KeyGen", |b| b.iter(|| ml_kem_512::key_gen()));
    c.bench_function("ml_kem_512 Encaps", |b| b.iter(|| ek_512.encaps()));
    c.bench_function("ml_kem_512 Decaps", |b| b.iter(|| dk_512.decaps(&ct_512)));

    c.bench_function("ml_kem_768 KeyGen", |b| b.iter(|| ml_kem_768::key_gen()));
    c.bench_function("ml_kem_768 Encaps", |b| b.iter(|| ek_768.encaps()));
    c.bench_function("ml_kem_768 Decaps", |b| b.iter(|| dk_768.decaps(&ct_768)));

    c.bench_function("ml_kem_1024 KeyGen", |b| b.iter(|| ml_kem_1024::key_gen()));
    c.bench_function("ml_kem_1024 Encaps", |b| b.iter(|| ek_1024.encaps()));
    c.bench_function("ml_kem_1024 Decaps", |b| b.iter(|| dk_1024.decaps(&ct_1024)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
