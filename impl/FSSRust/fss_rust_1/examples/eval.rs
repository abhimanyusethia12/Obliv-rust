#[path = "../src/eval.rs"]
mod eval;
#[path = "../src/util.rs"]
mod util;

fn main() {
    let e = eval::Eval::new(2,&[gen_key(),gen_key(),gen_key()]);
    println!("{:?}",e);
    let party: u8 = 0;
    let x: u128 = 90801;
    let sec_param: usize = 260373;
    let mut key1 = util::FssKey::<U2>{s : GenericArray::default(), cw: vec![], w : 0};
    let test: u128 = eval::Eval::eval(e, party, &mut key1, x, sec_param);    
    println!("The test works! Value of test :{}",test);
}
