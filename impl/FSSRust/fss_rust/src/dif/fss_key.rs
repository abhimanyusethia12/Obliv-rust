use super::PrgOutput;
use crate::ArrayLength;

use crate::Block;

#[derive(Debug)]
pub struct FssKey<N: ArrayLength<Block>> {
    pub init: PrgOutput<N>,
    pub cw: Vec<PrgOutput<N>>,
}

impl<N: ArrayLength<Block>> FssKey<N> {
    pub fn new() -> FssKey<N> {
        FssKey::<N> {
            init: PrgOutput::<N>::new(),
            cw: vec![],
        }
    }
}
