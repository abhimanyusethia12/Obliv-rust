use fss_rust::dif::{eval::Eval, gen::Gen, FssKey};

use fss_rust::seed_size::U1;

fn main() {
    let a = 2;
    let g = 1;
    let numbit = 2;
    let sec_param = 128;
    let x = 3;

    let gen_obj = Gen::new(numbit, a, g);
    let (mut key0, mut key1) = (FssKey::<U1>::new(), FssKey::<U1>::new());
    println!(
        "\n\nkey0 before gen:\n\n{:?}\n\nkey1 before gen:\n\n{:?}",
        key0, key1
    );

    gen_obj.gen(sec_param, &mut key0, &mut key1);

    println!(
        "\n\nkey0 after gen:\n\n{:?}\n\nkey1 after gen:\n\n{:?}",
        key0, key1
    );

    let eval_obj = Eval::new(numbit, gen_obj.aes_keys());
    let share1 = eval_obj.eval(0, &key0, x, sec_param);
    let share2 = eval_obj.eval(1, &key0, x, sec_param);

    println!("\n\nshare 1: {}\nshare 2: {}", share1, share2);
}
