use crate::prg;
use crate::utils::{gen_key, get_bit, get_random_block, grp_add, grp_sub, seed_xor};
use crate::FssKey;
use crate::{ArrayLength, GenericArray};

use crate::{Aeskey, Block, S};

use std::{mem, thread};

// Struct used for creating the generator object.
#[derive(Debug)]
pub struct Gen {
    aes_keys: [Aeskey; 3],
    num_bits: u8,
    pub a: u128,
    pub b: u128,
}

// Implementing the functions for the struct(class) Gen.
impl Gen {
    // Constructor function that takes in num_bits, a and b such that dpf(a) = b.
    pub fn new(num_bits: u8, input: u128, output: u128) -> Gen {
        let aes_keys: [Aeskey; 3] = [gen_key(), gen_key(), gen_key()];
        Gen {
            aes_keys: aes_keys,
            num_bits: num_bits,
            a: input,
            b: output,
        }
    }
    // Main function that implements the dpf for input a and output b.
    pub fn dpf<N: ArrayLength<Block> + 'static>(
        &self,
        sec_param: usize,
        key1: &mut FssKey<N>,
        key2: &mut FssKey<N>,
    ) {
        let n = self.num_bits;
        let lambda = sec_param;
        let a = self.a;
        let b = self.b;
        let aes_keys = self.aes_keys;

        let mut s_0: S<N> = GenericArray::default();
        let mut s_1: S<N> = GenericArray::default();
        get_random_block(&mut s_0, lambda);
        get_random_block(&mut s_1, lambda);
        key1.s = s_0.clone();
        key2.s = s_1.clone();
        let mut t_0: bool = false;
        let mut t_1: bool = true;

        let mut s0: Vec<S<N>> = vec![GenericArray::default(), GenericArray::default()];
        let mut s1: Vec<S<N>> = vec![GenericArray::default(), GenericArray::default()];
        let mut t0: Vec<bool> = vec![false, false];
        let mut t1: Vec<bool> = vec![false, false];

        let mut cw: (GenericArray<Block, N>, bool, bool);

        for i in 1..=n {
            let _s0 = mem::take(&mut s_0);
            let handle = thread::spawn(move || prg::prg(&aes_keys, &_s0, lambda));
            let (x1, x2, x3, x4) = prg::prg(&aes_keys, &s_1, lambda);
            s1[0] = x1;
            s1[1] = x3;
            t1[0] = x2;
            t1[1] = x4;
            let (p1, p2, p3, p4) = handle.join().unwrap();
            s0[0] = p1;
            s0[1] = p3;
            t0[0] = p2;
            t0[1] = p4;

            let alpha = get_bit(a, (i - 1).into());
            let keep: usize;
            let lose: usize;
            if alpha == false {
                keep = 0;
                lose = 1;
            } else {
                keep = 1;
                lose = 0;
            }

            let mut s_cw: S<N> = GenericArray::default();
            let mut t_cw: Vec<bool> = vec![false, false];
            seed_xor(&mut s_cw, &s0[lose], &s1[lose]);
            t_cw[0] = t0[0] ^ t1[0] ^ alpha ^ true;
            t_cw[1] = t0[1] ^ t1[1] ^ alpha;

            if t_0 {
                seed_xor(&mut s_0, &s0[keep], &s_cw);
                t_0 = t0[keep] ^ t_cw[keep];
            } else {
                s_0 = mem::take(&mut s0[keep]);
                t_0 = t0[keep];
            }
            if t_1 {
                seed_xor(&mut s_1, &s1[keep], &s_cw);
                t_1 = t1[keep] ^ t_cw[keep];
            } else {
                s_1 = mem::take(&mut s1[keep]);
                t_1 = t1[keep];
            }

            cw = (s_cw, t_cw[0], t_cw[1]);
            key1.cw.push(cw.clone());
            key2.cw.push(cw);
        }

        let x0 = prg::convert::<N>(&mut s_0, n);
        let x1 = prg::convert::<N>(&mut s_1, n);
        let mut tmp;
        if t_1 {
            tmp = grp_sub(x0, x1, n);
            tmp = grp_sub(tmp, b, n);
        } else {
            tmp = grp_sub(b, x0, n);
            tmp = grp_add(tmp, x1, n);
        }
        key1.w = tmp;
        key2.w = tmp;
    }

    pub fn aes_keys(&self) -> [Aeskey; 3] {
        self.aes_keys
    }
}
