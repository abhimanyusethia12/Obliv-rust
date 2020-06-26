use aesni::block_cipher::generic_array::{GenericArray, ArrayLength};
use aesni::block_cipher::generic_array::typenum::{U16,U2};

extern crate rand;    
use rand::os::{OsRng};
use crate::rand::RngCore;

use std::mem;

mod gen;
mod prg;

type Aeskey = GenericArray<u8,U16>;
type Block = GenericArray<u8, U16>;
type S<N> = GenericArray<Block, N>;

pub struct FssKey<N : ArrayLength<Block>> {
    s : S<N>,
    cw : Vec<(GenericArray<Block, N>, bool, bool)>,
    w : u128
}

fn gen_key() -> Aeskey {
    let mut key: Aeskey = GenericArray::default();
    // OsRng is a type of `Rng` that wraps /dev/urandom, getrandom(), etc
    let mut r = OsRng::new().unwrap();

    // Random bytes.
    r.fill_bytes(&mut key);
        
    return key;
}

pub fn get_bit(n : u128, pos : u8) -> bool {
    n & ( 1 << pos) > 0
}


#[derive(Debug)]
pub struct Eval{
    aes_keys : [Aeskey; 3],
    num_bits : u8,
}

impl Eval{
    pub fn new(num_bits: u8, aes_keys: &[Aeskey; 3]) -> Eval {
        Eval {
            aes_keys: *aes_keys,
            num_bits : num_bits,
        }
    }
    pub fn eval<N: ArrayLength<Block>>(self,b: u8, key:&mut FssKey<N>, x: u128 , sec_param : usize) -> u128{
    
        let mut t = match b{
            0 => false,
            1 => true,
            _ => panic!("It is two party scheme. Party number can only be 1 or 2")
        };

        let n = self.num_bits;
        let lambda = sec_param;
        
        let mut s: S<N> = mem::take(&mut key.s);
        
        for i in 1..=n as usize {
            let (s0, t0, s1, t1) = prg::prg(&self.aes_keys, &s, lambda);
        
            let mut s_l: S<N> = GenericArray::default();
            let mut s_r: S<N> = GenericArray::default();
            let t_l: bool;
            let t_r: bool;

            if !t {
                s_l = s0;
                s_r = s1;
                t_l = t0;
                t_r = t1;
            } else {
                for j in 0..s_l.len() as usize{
                    for k in 0..16{
                        s_l[j][k] = s0[j][k] ^ key.cw[i].0[j][k];
                        s_r[j][k] = s1[j][k] ^ key.cw[i].0[j][k];
                    }
                }
                t_l = t0 ^ key.cw[i].1;
                t_r = t1 ^ key.cw[i].2;
            }

            let x_i = get_bit(x, (i as u8-1).into());

            if x_i {
                s = s_r; t = t_r;
            }else {
                s = s_l; t = t_l;
            }
        }

        let share = prg::convert::<N>(&mut s, n) + (t as u128)*key.w;
        if b != 0 {
            (!share)&((1<<n) - 1)
        }else{
            share
        }
        
    }

}