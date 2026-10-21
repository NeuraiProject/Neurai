// Reads "dk_hex j_decimal" lines and prints d = FF1-AES256(dk, I2LEBSP_88(j)) as
// hex, exactly as orchard::keys::DiversifierKey::get does.
use aes::Aes256;
use fpe::ff1::{BinaryNumeralString, FF1};
use std::io::{self, BufRead};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let mut parts = line.split_whitespace();
        let dk = hex::decode(parts.next().unwrap()).unwrap();
        let j: u128 = parts.next().unwrap().parse().unwrap();
        let index = &j.to_le_bytes()[..11];
        let ff = FF1::<Aes256>::new(&dk, 2).unwrap();
        let enc = ff.encrypt(&[], &BinaryNumeralString::from_bytes_le(index)).unwrap();
        let dec = ff.decrypt(&[], &enc).unwrap();
        assert_eq!(dec.to_bytes_le(), index);
        println!("{}", hex::encode(enc.to_bytes_le()));
    }
}
