use crate::{ArrayLength, GenericArray};

use crate::{Aeskey, Block};

pub mod eval;
pub mod gen;

#[derive(Debug)]
pub struct PrgOutput<N: ArrayLength<Block>>(
    GenericArray<Block, N>,
    GenericArray<Block, N>,
    bool,
    bool,
    u128,
    u128,
);

fn prg<N: ArrayLength<Block>>(
    aes_keys: &[Aeskey; 5],
    seed: &GenericArray<Block, N>,
    seed_len: usize,
    numbit: u8,
) -> PrgOutput<N> {
    PrgOutput(
        seed.clone(),
        seed.clone(),
        seed[0][0] != 0,
        seed[0][1] != 0,
        23123,
        21342,
    )
}

#[derive(Debug)]
pub struct FssKey<N: ArrayLength<Block>> {
    pub init: PrgOutput<N>,
    pub cw: Vec<PrgOutput<N>>,
}
