use crate::{ArrayLength, GenericArray};
use aesni::block_cipher::{BlockCipher, NewBlockCipher};
use aesni::Aes128;

use std::thread;

use crate::{Aeskey, Block, S};

#[derive(Debug)]
pub struct PrgOutput<N: ArrayLength<Block>>(
    pub S<N>,
    pub S<N>,
    pub bool,
    pub bool,
    pub u128,
    pub u128,
);

impl<N: ArrayLength<Block>> PrgOutput<N> {
    pub fn new() -> PrgOutput<N> {
        PrgOutput(
            GenericArray::default(),
            GenericArray::default(),
            false,
            false,
            0,
            0,
        )
    }
}

pub fn prg<N: ArrayLength<Block>>(
    aes_keys: &[Aeskey; 5],
    seed: &S<N>,
    seed_len: usize,
    numbit: u8,
) -> PrgOutput<N> {
    let rnd_bool = |rnd_int: u8| match rnd_int & 1u8 {
        0u8 => false,
        1u8 => true,
        _ => panic!("Not possible"),
    };

    let to_grp = |block: Block| -> u128 {
        let extra = numbit % 8;
        let mut max_blk_len = numbit / 8;
        let mut y = if extra > 0 {
            max_blk_len += 1;
            block[0] as u128 & ((1 << extra) - 1)
        } else {
            block[0] as u128
        };

        for i in 1..max_blk_len as usize {
            y <<= 8;
            y += block[i] as u128;
        }
        y
    };

    let mut ciphers = Vec::new();
    for aes_key in aes_keys.iter() {
        ciphers.push(Aes128::new(aes_key));
    }

    let blocks_arr = vec![seed.clone(), seed.clone()];

    // Encrypting in parallel.

    // Using iterator functions.
    let handles: Vec<Vec<thread::JoinHandle<Block>>> = blocks_arr
        .into_iter()
        .enumerate()
        .map(|(i, blocks)| {
            blocks
                .into_iter()
                .map(|mut block| {
                    let cipher = ciphers[i];
                    thread::spawn(move || {
                        cipher.encrypt_block(&mut block);
                        block
                    })
                })
                .collect()
        })
        .collect();
    /*
        // Without using iterator functions
        for (j, blocks) in blocks_arr.into_iter().enumerate() {
            for mut block in blocks.into_iter() {
                let cipher = ciphers[j];
                let handle = thread::spawn(move || {
                    cipher.encrypt_block(&mut block);
                    block
                });
                handles[j].push(handle);
            }
        }
    */

    let mut seed_for_bool = seed[0].clone();
    ciphers[2].encrypt_block(&mut seed_for_bool);

    let t1 = rnd_bool(seed_for_bool[0]);
    let t2 = rnd_bool(seed_for_bool[1]);

    let (mut v1, mut v2) = (seed[0].clone(), seed[0].clone());
    ciphers[3].encrypt_block(&mut v1);
    ciphers[4].encrypt_block(&mut v2);

    let (v1, v2) = (to_grp(v1), to_grp(v2));

    let mut blocks_arr: Vec<S<N>>;

    blocks_arr = handles
        .into_iter()
        .map(|handle| {
            handle
                .into_iter()
                .map(|enc_block| enc_block.join().unwrap())
                .collect()
        })
        .collect();

    // trims extra bits to zeros.
    for seed_count in 0..blocks_arr.len() {
        let mut max_blk_len = seed_len / 128;
        let extra_bits = seed_len % 128;
        if extra_bits > 0 {
            let mut x = extra_bits / 8;
            let y = extra_bits % 8;
            if y > 0 {
                let mask = 0xffu8 >> (8 - y);
                blocks_arr[seed_count][max_blk_len][x] &= mask;
                x += 1;
            };
            while x < 16 {
                blocks_arr[seed_count][max_blk_len][x] &= 0x00;
                x += 1;
            }
        }
        max_blk_len += 1;
        while max_blk_len < blocks_arr[0].len() {
            for i in 0..16 {
                blocks_arr[seed_count][max_blk_len][i] &= 0x00;
            }
            max_blk_len += 1;
        }
    }

    let mut blocks_arr_iter = blocks_arr.into_iter();

    let s1 = blocks_arr_iter.next().unwrap();
    let s2 = blocks_arr_iter.next().unwrap();

    PrgOutput(s1, s2, t1, t2, v1, v2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_key_and_zero_buffer() {
        let aes_key: &GenericArray<u8, crate::seed_size::U16> =
            GenericArray::from_slice(&[0u8; 16]);
        let aes_keys = [*aes_key; 5];

        let block = *aes_key;
        let blocks: GenericArray<Block, crate::seed_size::U8> =
            GenericArray::clone_from_slice(&[block; 8]);

        prg(&aes_keys, &blocks, 8 * 128, 128);
    }
}
