pub use aesni::block_cipher::generic_array;
pub use aesni::block_cipher::generic_array::typenum as seed_size;
pub use generic_array::{ArrayLength, GenericArray};
use seed_size::U16;

pub mod dpf;
mod prg;
mod utils;

type Aeskey = GenericArray<u8, U16>;
type Block = GenericArray<u8, U16>;
type S<N> = GenericArray<Block, N>;

// Declaring struct for Fss keys containing s, correction word and W(for evaluation).
#[derive(Debug)]
pub struct FssKey<N: ArrayLength<Block>> {
    pub s: S<N>,
    pub cw: Vec<(GenericArray<Block, N>, bool, bool)>,
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
