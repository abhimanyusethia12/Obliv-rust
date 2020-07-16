use super::{
    prg::{prg, PrgOutput},
    FssKey,
};

use crate::utils::{get_bit, grp_add, grp_sub, seed_xor};
use crate::ArrayLength;

use crate::{Aeskey, Block, S};

#[derive(Debug)]
pub struct Eval<'a> {
    aes_keys: &'a [Aeskey; 5],
    num_bits: u8,
}

impl Eval<'_> {
    pub fn new(num_bits: u8, aes_keys: &[Aeskey; 5]) -> Eval {
        Eval { aes_keys, num_bits }
    }

    pub fn eval<N: ArrayLength<Block>>(
        &self,
        party: u8,
        key: &FssKey<N>,
        x: u128,
        sec_param: usize,
    ) -> u128 {
        let party = match party {
            0 => false,
            1 => true,
            _ => panic!("It is two party scheme. Party number can only be 0 or 1"),
        };

        let n = self.num_bits;
        let lambda = sec_param;

        let x_1 = get_bit(x, 0);

        let (mut s, mut t, mut v) = match x_1 {
            false => (&key.init.0, key.init.2, key.init.4),
            true => (&key.init.1, key.init.3, key.init.5),
        };
        let mut _s: S<N>;

        for (i, cw) in key
            .cw
            .iter()
            .step_by(2)
            .zip(key.cw.iter().skip(1).step_by(2))
            .enumerate()
        {
            let PrgOutput(_s0, _s1, _t0, _t1, _v0, _v1) = prg(self.aes_keys, &s, lambda, n);
            let x_i = get_bit(x, i as u8 + 1);

            match t {
                false => match x_i {
                    false => {
                        _s = seed_xor(&_s0, &(cw.0).0);
                        s = &s;
                        t = _t0 ^ (cw.0).2;
                    }
                    true => {
                        _s = seed_xor(&_s1, &(cw.0).1);
                        s = &s;
                        t = _t1 ^ (cw.0).3;
                    }
                },
                true => match x_i {
                    false => {
                        _s = seed_xor(&_s0, &(cw.1).0);
                        s = &s;
                        t = _t0 ^ (cw.1).2;
                    }
                    true => {
                        _s = seed_xor(&_s1, &(cw.1).1);
                        s = &s;
                        t = _t1 ^ (cw.1).3;
                    }
                },
            }

            v = grp_add(
                v,
                match x_i {
                    false => {
                        _v0 + match party {
                            false => (cw.0).4,
                            true => (cw.1).4,
                        }
                    }
                    true => {
                        _v1 + match party {
                            false => (cw.0).5,
                            true => (cw.1).5,
                        }
                    }
                },
                n,
            );
        }

        match party {
            false => v,
            true => grp_sub(0, v, n),
        }
    }
}
