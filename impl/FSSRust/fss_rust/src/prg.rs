use crate::{GenericArray, ArrayLength};
use aesni::block_cipher::{BlockCipher, NewBlockCipher};
use aesni::Aes128;

use std::mem;
use std::thread;

use crate::Block;

// a PRG generating seed_len*2 + 2 bits random value from seed of length seed_len using AES128.
pub fn prg<N: ArrayLength<Block>>(aes_keys: &[Block; 3],seed: &GenericArray<Block,N>,seed_len: usize) -> (GenericArray<Block,N>, bool, GenericArray<Block,N>, bool)
{
    // This closure extracts first bit as bool from integer.
    let rnd_bool = |rnd_int: u8|{
        match rnd_int&1u8 {
            0u8 => false,
            1u8 => true,
            _ => panic!("Not possible")
        }
    };

    let ciphers: [Aes128; 3] = [Aes128::new(&aes_keys[0]), Aes128::new(&aes_keys[1]), Aes128::new(&aes_keys[2])];
    let mut blocks_arr = [seed.clone(), seed.clone()];

    let mut handles = vec![vec![], vec![]];

    // encrypts blocks_arr parallely.
    for j in 0..blocks_arr.len() {
        for i in 0..seed.len() {
            let mut block = mem::take(&mut blocks_arr[j][i]);
            let cipher = ciphers[j];
            let handle = thread::spawn(move ||{
                cipher.encrypt_block(&mut block);
                block
            });
            handles[j].push(handle);
        }
    }

    let mut seed = seed[0].clone();
    ciphers[2].encrypt_block(&mut seed);

    let t1 = rnd_bool(seed[0]);
    let t2 = rnd_bool(seed[1]);

    let mut index = 0usize;
    for enc_blocks in handles {
        let mut counter = 0usize;
        for enc_block in enc_blocks {
            blocks_arr[index][counter] = enc_block.join().unwrap();
            counter+=1;
        }
        index+=1 ;
    }

    // trims extra bits with zeros.
    for seed_count in 0..2 {
        let mut max_blk_len = seed_len/128 ;
        let extra_bits = seed_len%128;
        if extra_bits > 0 {
            let mut x = extra_bits/8;
            let y = extra_bits%8;
            if y > 0 {
                let mask = 0xffu8 >> (8 - y);
                blocks_arr[seed_count][max_blk_len][x] &= mask;
                x += 1;
            };
            while x < 16 {
                blocks_arr[seed_count][max_blk_len][x] &= 0x00;
                x+=1;
            };
        }
        max_blk_len += 1;
        while max_blk_len < blocks_arr[0].len() {
            for i in 0..16 {
                blocks_arr[seed_count][max_blk_len][i] &= 0x00;
            }
            max_blk_len += 1;
        }
    }   

    (mem::take(&mut blocks_arr[0]),t1,mem::take(&mut blocks_arr[1]),t2)
}

pub fn convert <N : ArrayLength<Block>> (s: &mut GenericArray<Block,N>, n: u8) -> u128 {
    let mut rnd_num = 0u128;
    let mut x=0u128;
    let mut count = 0u8;
    let max:u128 = ((1<<(n-1))-1)+(1<<(n-1));
    let mask = u128::MAX - max;
    let shift = if n == 128 {0} else {n};

    for block in s {
        for y in block {
            x=x<<8;
            x+=*y as u128;
            count+=8;
            while count >= n {
                rnd_num ^= x&max;
                x = (x&mask)>>shift;
                count-=n;
            }
        }
    }

    rnd_num^x
}
