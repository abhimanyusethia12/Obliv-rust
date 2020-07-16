use super::{prg::prg, FssKey, PrgOutput};
use crate::utils::{
    gen_key, get_bit, get_random_block, get_random_bool, get_random_num, grp_add, grp_sub, seed_xor,
};
use crate::{ArrayLength, GenericArray};

use std::mem;

use crate::{Aeskey, Block, S};

#[derive(Debug)]
pub struct Gen {
    aes_keys: [Aeskey; 5],
    numbit: u8,
    a: u128,
    g: u128,
}

impl Gen {
    fn initialise<N: ArrayLength<Block>>(
        a_i: usize,
        g: u128,
        numbit: u8,
        lambda: usize,
        key0: &mut FssKey<N>,
        key1: &mut FssKey<N>,
    ) -> (Vec<Vec<GenericArray<Block, N>>>, [[bool; 2]; 2]) {
        let _a_i = 1 - a_i;

        let mut s: Vec<Vec<S<N>>> = vec![
            vec![GenericArray::default(), GenericArray::default()],
            vec![GenericArray::default(), GenericArray::default()],
        ];
        get_random_block(&mut s[0][a_i], lambda);
        get_random_block(&mut s[1][a_i], lambda);
        get_random_block(&mut s[0][_a_i], lambda);
        s[1][_a_i] = s[0][_a_i].clone();

        key0.init.0 = s[0][0].clone();
        key0.init.1 = s[0][1].clone();
        key1.init.0 = s[1][0].clone();
        key1.init.1 = s[1][1].clone();

        let mut t = [[false; 2]; 2];
        t[0][a_i] = get_random_bool();
        t[1][a_i] = !t[0][a_i];
        t[0][_a_i] = get_random_bool();
        t[1][_a_i] = t[0][_a_i];

        key0.init.2 = t[0][0];
        key0.init.3 = t[0][1];
        key1.init.2 = t[1][0];
        key1.init.3 = t[1][1];

        let mut v = [[0u128; 2]; 2];
        v[0][a_i] = get_random_num(numbit);
        v[1][a_i] = grp_sub(0, v[0][a_i], numbit);
        v[0][_a_i] = get_random_num(numbit);
        v[1][_a_i] = grp_add(v[0][_a_i], g * a_i as u128, numbit);

        key0.init.4 = v[0][0];
        key0.init.5 = v[0][1];
        key1.init.4 = v[1][0];
        key1.init.5 = v[1][1];

        (s, t)
    }
    pub fn new(numbit: u8, a: u128, output: u128) -> Gen {
        let aes_keys: [Aeskey; 5] = [gen_key(), gen_key(), gen_key(), gen_key(), gen_key()];
        Gen {
            aes_keys,
            numbit,
            a,
            g: output,
        }
    }

    pub fn aes_keys(&self) -> &[Aeskey; 5] {
        &self.aes_keys
    }

    pub fn gen<N: ArrayLength<Block>>(
        &self,
        sec_param: usize,
        key0: &mut FssKey<N>,
        key1: &mut FssKey<N>,
    ) {
        let n = self.numbit;
        let lambda = sec_param;
        let a = self.a;

        let mut a_i_1 = get_bit(a, 0) as usize;
        let mut _a_i_1 = 1 - a_i_1;
        let mut a_i;
        let mut _a_i;

        let (mut s, mut t) = Self::initialise(a_i_1, self.g, n, lambda, key0, key1);

        let mut _s = vec![
            vec![GenericArray::default(), GenericArray::default()],
            vec![GenericArray::default(), GenericArray::default()],
        ];
        let mut _t = [[false; 2]; 2];
        let mut _v = [[0u128; 2]; 2];

        let mut _cs = vec![
            vec![GenericArray::default(), GenericArray::default()],
            vec![GenericArray::default(), GenericArray::default()],
        ];
        let mut _ct = [[false; 2]; 2];
        let mut _cv = [[0u128; 2]; 2];

        for _i in 1..n {
            a_i = a_i_1;
            _a_i = _a_i_1;
            a_i_1 = get_bit(a, 0) as usize;
            _a_i_1 = 1 - a_i_1;

            for party in 0..2 {
                let prg_out = prg(&self.aes_keys, &s[party][a_i], lambda, n);
                _s[party][0] = prg_out.0;
                _s[party][1] = prg_out.1;
                _t[party][0] = prg_out.2;
                _t[party][1] = prg_out.3;
                _v[party][0] = prg_out.4;
                _v[party][1] = prg_out.5;
            }

            get_random_block(&mut _cs[0][a_i_1], lambda);
            get_random_block(&mut _cs[1][a_i_1], lambda);
            get_random_block(&mut _cs[0][_a_i_1], lambda);
            _cs[1][_a_i_1] = seed_xor(
                &mut _cs[0][_a_i_1],
                &seed_xor(&_s[0][_a_i_1], &_s[0][_a_i_1]),
            );

            _ct[0][a_i_1] = get_random_bool();
            _ct[1][a_i_1] = true ^ _ct[0][a_i_1] ^ t[0][a_i_1] ^ t[1][a_i_1];
            _ct[0][_a_i_1] = get_random_bool();
            _ct[1][_a_i_1] = _ct[0][_a_i_1] ^ t[0][_a_i_1] ^ t[1][_a_i_1];

            _cv[0][a_i_1] = get_random_num(n);
            _cv[1][a_i_1] = grp_sub(grp_add(_cv[0][a_i_1], _v[0][a_i_1], n), _v[1][a_i_1], n);
            _cv[0][_a_i_1] = get_random_num(n);
            _cv[1][_a_i_1] = grp_sub(
                grp_sub(grp_add(_cv[0][a_i_1], _v[0][a_i_1], n), _v[1][a_i_1], n),
                self.g * a_i_1 as u128,
                n,
            );

            let tau = [t[0][a_i] as usize, t[1][a_i] as usize];
            for party in 0..2 {
                for j in 0..2 {
                    s[party][j] = seed_xor(&_s[party][j], &_cs[tau[party]][j]);
                    t[party][j] = _t[party][j] ^ _ct[tau[party]][j];
                }
            }

            key0.cw.push(PrgOutput(
                mem::take(&mut _cs[0][0]),
                mem::take(&mut _cs[0][1]),
                _ct[0][0],
                _ct[0][1],
                _cv[0][0],
                _cv[0][1],
            ));
            key1.cw.push(PrgOutput(
                mem::take(&mut _cs[1][0]),
                mem::take(&mut _cs[1][1]),
                _ct[1][0],
                _ct[1][1],
                _cv[1][0],
                _cv[1][1],
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checking_gen_new() {
        println!("{:?}", Gen::new(128, 48, 1234));
    }
}
