use rsa::{pkcs8::FromPublicKey, RsaPublicKey};
pub struct SizedKeys {
    pub b128: RsaPublicKey,
    pub b74: RsaPublicKey,
}
pub struct Keys {
    pub v1: SizedKeys,
    pub v2: SizedKeys,
}


impl Keys {
    pub fn init() -> Keys {
        Keys {
            v1: SizedKeys {
                b128: RsaPublicKey::from_public_key_pem(
                    "-----BEGIN PUBLIC KEY-----
MIGtMA0GCSqGSIb3DQEBAQUAA4GbADCBlwKBgQD+0uHCfjNjMW53MXp6UsVJgTlR
hr5JdHYMclGNY+BUSkjQiLMyxbDDcMdl1l2YPB+d4KQrMQzMB653C9K2HWpNzOrH
V2ib3L9ghHj68xL2CHzElsN2LPXEZRyuzaNJn65+2360Dj4Y6zBBcOke1bFWqs5v
Qy1uymzDWFHejGePZwIRALt5f/3sf55Cydb3mxNwWds=
-----END PUBLIC KEY-----",
                )
                .expect("Internal Error"),
                b74: RsaPublicKey::from_public_key_pem(
                    "-----BEGIN PUBLIC KEY-----
MHQwDQYJKoZIhvcNAQEBBQADYwAwYAJLAP887GtfQOPDZhRRufz67zrrBtwjKcDm
9NzMknlyZxbOFbvgXu0sVxG8+PW2yPcnbbXEO/qjBA3AGrFLnE0W9xwM5eqVPwx1
TGsXAhEA2wW6gi2azDP6t9j0J/nOZQ==
-----END PUBLIC KEY-----",
                )
                .expect("Internal Error"),
            },
            v2: SizedKeys {
                b128: RsaPublicKey::from_public_key_pem(
                    "-----BEGIN PUBLIC KEY-----
MIGsMA0GCSqGSIb3DQEBAQUAA4GaADCBlgKBgQDKnxjvbD8/pMWkYf6lSrGUBrpe
zXRtYKJ0ktyj1047XB0xX3sQODJBgJsCnrvV3k0RYDDMV/fVpsmhbzc7sUpQhSP3
6ApMdE2QhWY6ShRy168sVq5BtQZffvoCk70yeK1pNUb58WIZt5/0caNjaCTP/Ntj
qO2AWea5pPDbiVOBywIQGHCS2mRUzrGFPmkV+EZqBQ==
-----END PUBLIC KEY-----",
                )
                .expect("Internal Error"),
                b74: RsaPublicKey::from_public_key_pem(
                    "-----BEGIN PUBLIC KEY-----
MHMwDQYJKoZIhvcNAQEBBQADYgAwXwJLALQEoN8R0crP8aGgSNTVc/lTpixYPXSS
WSdWGm16HisUBCUmr3C1UFRzkOpux0jTD9uBrbSQ4MNqGYa0BLL19p712htmPllQ
kTDnAhAwnP7ZcZ/ipeIMm7RHZTgr
-----END PUBLIC KEY-----",
                )
                .expect("Internal Error"),
            },
        }
    }
}
