use rand::Rng;

use fss_rust_1::{gen, eval, FssKey};
use fss_rust_1::seed_size::U1;

#[test]
fn dpf_test() {
    let rnd_128 = ||{
        let mut rng = rand::thread_rng();
        let x = rng.gen::<u8>() as u128;
        let y = rng.gen::<u8>() as u128;
        (x<<8) + y
    };
    let sec_param = 128;
    let num_bit = 20;

    for _i in 0..1000 {
        let a = rnd_128();
        let b = rnd_128();
        
        
        // Initialising the Gen object.
        let obj: gen::Gen = gen::Gen::new(num_bit, a, b);
        let mut key1 = FssKey::<U1>::new();
        let mut key2 = FssKey::<U1>::new();
        // Invoking the dpf function on the Gen object.
        gen::Gen::dpf(&obj, sec_param, &mut key1, &mut key2);

        let key1 = &key1;
        let key2 = &key2;

        let eval_obj = eval::Eval::new(num_bit, &obj.aes_keys());

        //test- eval at a is equal to b
        let mut x = a;
        let mut share1 = eval_obj.eval(0, key1, x, sec_param);
        let mut share2 = eval_obj.eval(1, key2, x, sec_param);
        let mut ans = (share1+share2)%(1<<num_bit);
        assert_eq!(b,ans);

        //test- eval at 99 random values is equal to 0
        for _j in 0..99 {
            x = rnd_128();
            if x != a {
                share1 = eval_obj.eval(0, key1, x, sec_param);
                share2 = eval_obj.eval(1, key2, x, sec_param);
                ans = (share1+share2)%(1<<num_bit);
                assert_eq!(0,ans);
            }
        }
    }
}
