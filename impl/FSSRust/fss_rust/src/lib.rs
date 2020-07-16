pub use aesni::block_cipher::generic_array;
pub use aesni::block_cipher::generic_array::typenum as seed_size;
pub use generic_array::{ArrayLength, GenericArray};
use seed_size::U16;

pub mod dif;
pub mod dpf;
mod utils;

type Aeskey = GenericArray<u8, U16>;
type Block = GenericArray<u8, U16>;
type S<N> = GenericArray<Block, N>;
