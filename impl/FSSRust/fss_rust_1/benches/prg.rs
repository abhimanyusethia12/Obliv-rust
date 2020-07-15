// NOTE : For running benchmarks of prg make prg, utils, Aeskey and S public
// in src/lib.rs and then run this bench.
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use fss_rust_1::{
    prg,
    utils::{gen_key, get_random_block},
    Aeskey, ArrayLength, GenericArray, S,
};

use fss_rust_1::seed_size::{U1, U16, U2, U4, U8};

pub fn prg_benchmark<N: ArrayLength<Aeskey>>(c: &mut Criterion) {
    let aes_keys: [Aeskey; 3] = [gen_key(), gen_key(), gen_key()];
    let mut s: S<N> = GenericArray::default();

    let sec_param = 128 * s.len();

    get_random_block(&mut s, sec_param);

    c.bench_function(
        &format!("prg security parameter: {}", sec_param)[..],
        move |b| {
            b.iter(|| prg::prg(&aes_keys, &s, sec_param));
        },
    );
}

criterion_group!(
    benches,
    prg_benchmark::<U1>,
    prg_benchmark::<U2>,
    prg_benchmark::<U4>,
    prg_benchmark::<U8>,
    prg_benchmark::<U16>
);
criterion_main!(benches);
