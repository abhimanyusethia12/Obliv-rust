use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use rand::Rng;

use fss_rust_1::{
    dpf::{eval, gen},
    ArrayLength, FssKey, GenericArray,
};

use fss_rust_1::seed_size::{U1, U16, U2, U4, U8};
type Block = GenericArray<u8, U16>;

pub fn dpf_benchmark<N: 'static + ArrayLength<Block>>(c: &mut Criterion) {
    let rnd_num = |num| {
        let mut rng = rand::thread_rng();
        let x: u64 = rng.gen();
        let y: u64 = rng.gen();
        (((x as u128) << 64) + y as u128) & ((1u128 << (num - 1)) - 1u128 + (1u128 << (num - 1)))
    };
    let num_bits: Vec<u8> = vec![1, 2, 4, 8, 16, 32, 64, 128];

    for num_bit in num_bits.into_iter() {
        let mut key1 = FssKey::<N>::new();
        let mut key2 = FssKey::<N>::new();

        let sec_param = 128 * key1.s.len();

        let mut grp = c.benchmark_group(format!(
            "group size: {}, security parameter: {}",
            num_bit, sec_param
        ));

        let a = rnd_num(num_bit);
        let b = rnd_num(num_bit);
        let x = rnd_num(num_bit);

        let gen_obj: gen::Gen = gen::Gen::new(num_bit, a, b);
        let eval_obj = eval::Eval::new(num_bit, &gen_obj.aes_keys());

        let key1_ref = &mut key1;
        let key2_ref = &mut key2;

        grp.bench_function("gen algorithm", move |b| {
            b.iter(|| gen_obj.dpf(sec_param, key1_ref, key2_ref));
        });

        let key1_ref = &mut key1;
        let eval_ref = &eval_obj;

        grp.bench_function("eval algorithm for party 1", move |b| {
            b.iter(|| eval_ref.eval(0, key1_ref, x, sec_param));
        });

        let key2_ref = &mut key2;
        let eval_ref = &eval_obj;

        grp.bench_function("eval algorithm for party 2", move |b| {
            b.iter(|| eval_ref.eval(0, key2_ref, x, sec_param));
        });
    }
}

criterion_group!(
    benches,
    dpf_benchmark::<U1>,
    dpf_benchmark::<U2>,
    dpf_benchmark::<U4>,
    dpf_benchmark::<U8>
);
criterion_main!(benches);
