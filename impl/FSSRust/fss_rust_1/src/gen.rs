use aesni::block_cipher::generic_array::{GenericArray, ArrayLength};
extern crate rand;    
use std::thread;
use std::mem;
use crate::prg;
use crate::utils;

// Struct used for creating the generator object.
#[derive(Debug)]
pub struct Gen {
    aes_keys : [utils::Aeskey; 3],
    num_bits : u8,
    pub a : u128,
    pub b : u128,
}

// Implementing the functions for the struct(class) Gen.
impl Gen {
    // Constructor function that takes in num_bits, a and b such that dpf(a) = b.
    pub fn new(num_bits: u8, input: u128, output: u128) -> Gen {
        let key1 = utils::gen_key();
        let key2 = utils::gen_key();
        let key3 = utils::gen_key();
        let aes_keys:[utils::Aeskey; 3] = [key1, key2, key3];
        Gen {
            aes_keys: aes_keys,
            num_bits: num_bits,
            a : input,
            b : output,
        }
    }
    // Main function that implements the dpf for input a and output b.
    pub fn dpf <N : ArrayLength<utils::Block> + 'static> (&self, sec_param : u64, key1 : &mut utils::FssKey<N>, key2 : &mut utils::FssKey<N>) {
        let n = self.num_bits;
        let lambda = sec_param;
        let a = self.a;
        let b = self.b;
        let aes_keys = self.aes_keys;
        let mut s_0: utils::S<N> = GenericArray::default();
        let mut s_1: utils::S<N> = GenericArray::default();
        let mut s0: Vec<utils::S<N>> = vec![GenericArray::default(), GenericArray::default()]; 
        let mut s1: Vec<utils::S<N>> = vec![GenericArray::default(), GenericArray::default()]; 
        utils::get_random_block(&mut s_0, lambda);
        utils::get_random_block(&mut s_1, lambda);
        key1.s = s_0.clone();
        key2.s = s_1.clone();
        let mut t_0: bool = false;
        let mut t_1: bool = true;
        let mut t0: Vec<bool> = vec![false, false];
        let mut t1: Vec<bool> = vec![false, false];
        let mut cw : (GenericArray<utils::Block, N>, bool, bool);
        for i in 1..=n {
            let _s0 = mem::take(&mut s_0);
            let handle = thread::spawn(move || {
                let (p1, p2, p3, p4) = prg::prg(&aes_keys, &_s0, lambda as usize);
                return (p1, p2, p3, p4, _s0);
            });
            let (x1, x2, x3, x4) = prg::prg(&aes_keys, &s_1, lambda as usize);
            s1[0] = x1; s1[1] = x3; t1[0] = x2; t1[1] = x4;
            println!("x1 : {:?} \n x2 : {:?} \n x3 : {:?} \n x4 : {:?}", s1[0], t1[0], s1[1], t1[1]);
            let (p1, p2, p3, p4, mut s_0) = handle.join().unwrap();
            s0[0] = p1; s0[1] = p3; t0[0] = p2; t0[1] = p4;
            println!("p1 : {:?} \n p2 : {:?} \n p3 : {:?} \n p4 : {:?}", s0[0], t0[0], s0[1], t0[1]);
            let alpha =  utils::get_bit(a, (i-1).into());
            println!("alpha : {}", alpha);
            let keep: u8;
            let lose: u8;
            let mut s_cw : utils::S<N> = GenericArray::default();
            let mut t_cw : Vec<bool> = vec![false, false];
            if alpha == false {
                    keep = 0; lose = 1;
            }
            else {
                keep = 1; lose = 0;
            }
            for j in 0..s_0.len() {
                for k in 0..16 {
                    s_cw[j as usize][k] = s0[lose as usize][j as usize][k] ^ s1[lose as usize][j as usize][k];
                }
            }
            println!("s_cw : {:?}", s_cw);
            t_cw[0] = t0[0]^t1[0]^alpha^true;
            t_cw[1] = t0[1]^t1[1]^alpha;
            cw = (s_cw.clone(), t_cw[0].clone(), t_cw[1].clone());
            println! ("cw : {:?}", cw);
            key1.cw.push(cw.clone());
            key2.cw.push(cw.clone());
            println!("key1- > cw : {:?} \n key2 -> cw : {:?}", key1.cw, key2.cw);
            if t_0 == false {
                for j in 0..s_0.len() {
                    for k in 0..16 {
                        s_0[j as usize][k] = s0[keep as usize][j as usize][k];
                    }
                }
                for j in 0..s_1.len() {
                    for k in 0..16 {
                        s_1[j as usize][k] = s1[keep as usize][j as usize][k];
                    }
                }
                t_0 = t0[keep as usize];
                t_1 = t1[keep as usize];
                println!("s_0 : {:?}\n s_1 : {:?}\n t_0 : {:?}\n t_1: {:?}\n", s_0, s_1, t_0, t_1);
            }
            else {  
                for j in 0..s_0.len() {
                    for k in 0..16 {
                        s_0[j as usize][k] = s0[keep as usize][j as usize][k] ^ s_cw[j as usize][k];
                    }
                }
                for j in 0..s_1.len() {
                    for k in 0..16 {
                        s_1[j as usize][k] = s1[keep as usize][j as usize][k] ^ s_cw[j as usize][k];
                    }
                }
                t_0 = t0[keep as usize]^t_cw[keep as usize];
                t_1 = t1[keep as usize]^t_cw[keep as usize];
                println!("s_0 : {:?}\n s_1 : {:?}\n t_0 : {:?}\n t_1: {:?}\n", s_0, s_1, t_0, t_1);
            }
        }
        if t_1 == false {
            let temp = b - prg::convert::<N>(&mut s_0, n) + prg::convert::<N>(&mut s_1, n); 
            key1.w = temp;
            key2.w = temp; 
        }
        else {
            let temp = b - prg::convert::<N>(&mut s_0, n) + prg::convert::<N>(&mut s_1, n);
            if temp > (n as u128) {
                panic!("Not possible");
            }
            else {
                key1.w = (n as u128 - temp)%(n as u128);
                key2.w = (n as u128 - temp)%(n as u128);
            } 
        }
    }
}
