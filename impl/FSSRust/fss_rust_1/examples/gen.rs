use aesni::block_cipher::generic_array::GenericArray;
use aesni::block_cipher::generic_array::typenum::U2;
extern crate rand;    

#[path = "../src/prg.rs"]
mod prg;
#[path = "../src/gen.rs"]
mod gen;
#[path = "../src/utils.rs"]
mod utils;

fn main() {
    // Initialising the Gen object.
    let obj: gen::Gen = gen::Gen::new(2, 3, 2);
    println!("{:?}", obj);
    let mut key1 = utils::FssKey::<U2>{ s : GenericArray::default(), cw: vec![], w : 0};
    let mut key2 = utils::FssKey::<U2>{ s : GenericArray::default(), cw: vec![], w : 0};
    // Invoking the dpf function on the Gen object.
    gen::Gen::dpf(&obj, 256, &mut key1, &mut key2);    
}
