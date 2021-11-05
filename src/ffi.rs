use ::safer_ffi::prelude::*;

use crate::{decrypt_barcode, parse_decrypted};

#[ffi_export]
fn free_buf(vec: repr_c::Vec<u8>) {
    drop(vec); // And that's it!
}

#[ffi_export]
fn c_decrypt_and_parse(barcode_data: repr_c::Vec<u8>) -> repr_c::Vec<u8> {
    let returnval;
    match decrypt_barcode(barcode_data.to_vec()) {
        Ok(decrypted) => match parse_decrypted(decrypted) {
            Ok(data) => returnval = serde_json::to_string(&data).unwrap(),
            Err(_) => returnval = "{error: true}".to_string(),
        },
        Err(_) => returnval = "{error: true}".to_string(),
    };
    returnval.as_bytes().to_vec().into()
}
#[::safer_ffi::cfg_headers]
#[test]
fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("librusty_sadl.h")?
        .generate()
}
