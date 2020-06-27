use aesni::block_cipher::generic_array::{GenericArray, ArrayLength};
use aesni::block_cipher::generic_array::typenum::{U16};
extern crate rand;    
use rand::os::{OsRng};
use crate::rand::RngCore;

pub type Aeskey = GenericArray<u8,U16>;
pub type Block = GenericArray<u8, U16>;
pub type S<N> = GenericArray<Block, N>;

// Declaring struct for Fss keys containing s, correction word and W(for evaluation).
pub struct FssKey<N : ArrayLength<Block>> {
    pub s : S<N>,
    pub cw : Vec<(GenericArray<Block, N>, bool, bool)>,
    pub w : u128
}

// Generation of AES Keys for use in prg.
pub fn gen_key() -> Aeskey {
    let mut key: Aeskey = GenericArray::default();
    // OsRng is a type of `Rng` that wraps /dev/urandom, getrandom(), etc
    let mut r = OsRng::new().unwrap();

    // Random bytes.
    r.fill_bytes(&mut key);
        
    return key;
}

// Function for getting random bytes for initialising s0 and s1.
pub fn set_random_bytes (lambda: u64) -> Vec<u8> {
    let x = lambda as usize;
    let mut rand_bytes = vec![0u8; x];
    let mut r = OsRng::new().unwrap();

    r.fill_bytes(&mut rand_bytes);
    return rand_bytes;
}

// Utility function to get the bit at a certain position of input.
pub fn get_bit(n : u128, pos : u8) -> bool {
    return n & ( 1 << pos) > 0 
}

// Function that uses set_random_bytes to set random bytes in form of blocks in s0 and s1.
pub fn get_random_block <N : ArrayLength<Block>> (s : &mut S<N>, lambda : u64) {
    let rand_bytes = set_random_bytes(lambda); 
    let max_block_len = lambda/128;
    let extra_bits = lambda%128;
    if extra_bits > 0 {
        for j in 0..max_block_len {
            let ind = j as usize;
            s[ind] = *GenericArray::from_slice(&rand_bytes[ind*16..(ind+1)*16]);
        }
        let last = max_block_len as usize;
        let x = extra_bits/8;
        let y = extra_bits%8;
        for i in 0..x {
            let ind = i as usize;
            s[last][ind] = rand_bytes[last*8 + ind];
        }
        if y > 0 {
            let mask = 0xffu8 >> y;
            let ind = x as usize;
            s[last][ind] = mask;
        }
    }
    else {
        for j in 0..max_block_len {
            let ind = j as usize;
            s[ind] = *GenericArray::from_slice(&rand_bytes[ind*16..(ind+1)*16]);
        }
    }
}