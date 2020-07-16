use super::{prg, FssKey};

use crate::utils::{get_bit, grp_add, grp_sub, seed_xor};
use crate::ArrayLength;

use crate::{Aeskey, Block, S};

#[derive(Debug)]
pub struct Eval {
    aes_keys: [Aeskey; 3],
    num_bits: u8,
}

impl Eval {
    pub fn new(num_bits: u8, aes_keys: &[Aeskey; 3]) -> Eval {
        Eval {
            aes_keys: *aes_keys,
            num_bits: num_bits,
        }
    }
    pub fn eval<N: ArrayLength<Block>>(
        &self,
        party: u8,
        key: &FssKey<N>,
        x: u128,
        sec_param: usize,
    ) -> u128 {
        let mut t = match party {
            0 => false,
            1 => true,
            _ => panic!("It is two party scheme. Party number can only be 1 or 2"),
        };

        let n = self.num_bits;
        let lambda = sec_param;

        let mut s: S<N> = key.s.clone();

        for i in 0..n as usize {
            let (s0, t0, s1, t1) = prg::prg(&self.aes_keys, &s, lambda);

            let x_i = get_bit(x, (i as u8).into());

            if x_i {
                if t {
                    s = seed_xor(&s1, &key.cw[i].0);
                    t = t1 ^ key.cw[i].2;
                } else {
                    s = s1;
                    t = t1;
                }
            } else {
                if t {
                    s = seed_xor(&s0, &key.cw[i].0);
                    t = t0 ^ key.cw[i].1;
                } else {
                    s = s0;
                    t = t0;
                }
            };
        }

        let share = grp_add(prg::convert::<N>(&mut s, n), (t as u128) * key.w, n);
        if party != 0 {
            grp_sub(0u128, share, n)
        } else {
            share
        }
    }
}
