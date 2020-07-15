extern crate rand;

use fss_rust::{
    dpf::{eval, gen},
    seed_size::U1,
    FssKey,
};

fn main() {
    let sec_param = 128;
    let num_bit = 20;

    let a = 49834;
    let b = 44581;
    let x = 49832;

    // Initialising the Gen object.
    let obj: gen::Gen = gen::Gen::new(num_bit, a, b);
    let mut key1 = FssKey::<U1>::new();
    let mut key2 = FssKey::<U1>::new();
    // Invoking the dpf function on the Gen object.
    gen::Gen::dpf(&obj, sec_param, &mut key1, &mut key2);

    println!("FSS KEY 1\n{:?}\nFSS KEY 2\n{:?}", key1, key2);

    let key1 = &key1;
    let key2 = &key2;

    let eval_obj = eval::Eval::new(num_bit, &obj.aes_keys());

    let share1 = eval_obj.eval(0, key1, x, sec_param);
    println!("\n\n\nshare 1: {}", share1);
    let share2 = eval_obj.eval(1, key2, x, sec_param);
    println!("\n\n\nshare 2: {}", share2);

    println!("\n ans: {}", (share1 + share2) % (1 << num_bit));
}
