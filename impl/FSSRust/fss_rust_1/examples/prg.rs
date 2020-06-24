#[path="../src/prg.rs"]

mod prg;

use aesni::block_cipher::consts::{U10, U16};
use aesni::block_cipher::generic_array::GenericArray;

type Block = GenericArray<u8,U16>;

fn main() {
    let key: Block = *GenericArray::from_slice(&[0u8; 16]);
    let keys = [key; 3];
    let block = GenericArray::clone_from_slice(&[0u8; 16]);
    let seed: GenericArray<Block,U10> = GenericArray::clone_from_slice(&[block; 10]);

    let (mut s1,t1,s2,t2) = prg::prg(&keys, &seed, 1021usize);

    println!("{:?}\n{}\n{:?}\n{}\n",s1,t1,s2,t2);
    let ans = prg::convert(&mut s1, 1021u64, 23u128);
    println!("{}",ans);
}
