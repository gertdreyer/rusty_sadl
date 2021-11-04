use rusty_sadl;
fn main() {
    let vect = base64::decode("Base 64 encoded barcode data here").unwrap();
    println!("{:?}",rusty_sadl::decrypt_and_decode(&vect).unwrap());
}