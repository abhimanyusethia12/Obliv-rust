use crate::{Aeskey, Block, S};
use crate::{ArrayLength, GenericArray};

extern crate rand;
use rand::os::OsRng;
use rand::RngCore;

//group addition and subtraction of size 1<<n
pub fn grp_add(x: u128, y: u128, n: u8) -> u128 {
    if n < 128 {
        return (x + y) % (1 << n);
    };
    let max = u128::MAX;
    let z = max - x;
    if y > z {
        y - z - 1
    } else {
        x + y
    }
}

pub fn grp_sub(x: u128, y: u128, n: u8) -> u128 {
    if n < 128 {
        return (x + (1 << n) - y) % (1 << n);
    }
    let max = u128::MAX;
    if y <= x {
        x - y
    } else {
        max - y + x
    }
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

// Utility function to get the bit at a certain position of input.
pub fn get_bit(n: u128, pos: u8) -> bool {
    return n & (1 << pos) > 0;
}

// Function for getting random bytes for initialising s0 and s1.
fn set_random_bytes(lambda: usize) -> Vec<u8> {
    let extra_bits = lambda % 8;
    let x = lambda / 8 + if extra_bits > 0 { 1 } else { 0 };
    let mut rand_bytes = vec![0u8; x];
    let mut r = OsRng::new().unwrap();

    r.fill_bytes(&mut rand_bytes);

    if extra_bits > 0 {
        let mask: u8 = ((1 << (extra_bits - 1)) - 1) + 1 << (extra_bits - 1);
        rand_bytes[x - 1] &= mask;
    }
    return rand_bytes;
}

// Function that uses set_random_bytes to set random bytes in form of blocks in s0 and s1.
pub fn get_random_block<N: ArrayLength<Block>>(s: &mut S<N>, lambda: usize) {
    let mut rand_bytes = set_random_bytes(lambda);
    while (rand_bytes.len() % 16) > 0 {
        rand_bytes.push(0u8);
    }

    let max_block_len = rand_bytes.len() / 16;
    for i in 0..max_block_len {
        s[i] = *GenericArray::from_slice(&rand_bytes[(i * 16)..(i * 16 + 16)]);
    }
}

pub fn seed_xor<N: ArrayLength<Block>>(operand1: &S<N>, operand2: &S<N>) -> S<N> {
    operand1
        .iter()
        .zip(operand2.iter())
        .map(|(x, y)| x.iter().zip(y.iter()).map(|(a, b)| a ^ b).collect())
        .collect()
}
