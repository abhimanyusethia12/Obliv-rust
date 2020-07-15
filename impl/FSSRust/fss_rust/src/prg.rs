use crate::{ArrayLength, GenericArray};
use aesni::block_cipher::{BlockCipher, NewBlockCipher};
use aesni::Aes128;

use std::thread;

use crate::Block;

// a PRG generating seed_len*2 + 2 bits random value from seed of length seed_len using AES128.
pub fn prg<N: ArrayLength<Block>>(
    aes_keys: &[Block; 3],
    seed: &GenericArray<Block, N>,
    seed_len: usize,
) -> (GenericArray<Block, N>, bool, GenericArray<Block, N>, bool) {
    // This closure extracts first bit as bool from integer.
    let rnd_bool = |rnd_int: u8| match rnd_int & 1u8 {
        0u8 => false,
        1u8 => true,
        _ => panic!("Not possible"),
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

    let mut seed_first_block = seed[0].clone();
    ciphers[2].encrypt_block(&mut seed_first_block);

    let t1 = rnd_bool(seed_first_block[0]);
    let t2 = rnd_bool(seed_first_block[1]);

    let mut blocks_arr: Vec<GenericArray<Block, N>>;

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

    (s1, t1, s2, t2)
}

pub fn convert<N: ArrayLength<Block>>(s: &mut GenericArray<Block, N>, n: u8) -> u128 {
    let mut rnd_num = 0u128;
    let mut x = 0u128;
    let mut count = 0u8;
    let max: u128 = ((1 << (n - 1)) - 1) + (1 << (n - 1));
    let mask = u128::MAX - max;
    let shift = if n == 128 { 0 } else { n };

    for block in s {
        for y in block {
            x = x << 8;
            x += *y as u128;
            count += 8;
            while count >= n {
                rnd_num ^= x & max;
                x = (x & mask) >> shift;
                count -= n;
            }
        }
    }

    rnd_num ^ x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_key_and_zero_buffer() {
        let aes_key: &GenericArray<u8, crate::seed_size::U16> =
            GenericArray::from_slice(&[0u8; 16]);
        let aes_keys = [*aes_key; 3];

        let block = *aes_key;
        let blocks: GenericArray<Block, crate::seed_size::U8> =
            GenericArray::clone_from_slice(&[block; 8]);

        prg(&aes_keys, &blocks, 8 * 128);
    }
}
