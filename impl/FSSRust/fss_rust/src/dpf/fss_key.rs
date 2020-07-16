use crate::{ArrayLength, GenericArray};

use crate::{Block, S};

// Declaring struct for Fss keys containing s, correction word and W(for evaluation).
#[derive(Debug)]
pub struct FssKey<N: ArrayLength<Block>> {
    pub s: S<N>,
    pub cw: Vec<(S<N>, bool, bool)>,
    pub w: u128,
}

impl<N: ArrayLength<Block>> FssKey<N> {
    pub fn new() -> FssKey<N> {
        FssKey::<N> {
            s: GenericArray::default(),
            cw: vec![],
            w: 0,
        }
    }
}
