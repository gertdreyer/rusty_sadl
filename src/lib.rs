use chrono::{Date, DateTime, NaiveDate, Utc};
use rsa::{PaddingScheme, PublicKey};
use std::{convert::TryInto, error::Error, mem};
use serde::Serialize;
mod base64whenjson;



use crate::{keys::Keys };
mod keys;
mod ffi;
use num::{self, ToPrimitive};
#[macro_use]
extern crate num_derive;


#[derive(Debug, Copy, Clone)]
#[repr(packed)]
struct HeaderLayout {
    //0 1 2 3 4
    _identification: [u8; 5],
    //5 6 7 8 9
    _pad1: [u8; 5],
    //10
    data1len: u8,
    //11
    _pad2: u8,
    //12
    data2len: u8,
    //13 14
    data3len: u16,
}

#[repr(C)]
enum BarcodeVersion {
    V1,
    V2,
}
#[derive(Debug, Serialize)]
pub struct LicenceData {
    pub surname: String,
    pub initials: String,
    pub codes: Vec<(String, DateTime<Utc>)>,
    pub prdp: Option<(String, DateTime<Utc>)>,
    pub id_country_of_issue: String,
    pub licence_country_of_issue: String,
    pub vehicle_restrictions: Vec<VehicleRestrictions>,
    pub driver_restrictions: Vec<DriverRestrictions>,
    pub licence_number: String,
    pub id_number: String,
    pub id_type: IDType,
    pub gender: Gender,
    pub licence_issue_number: u8,
    pub birth_date: Option<DateTime<Utc>>,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    #[serde(with = "base64whenjson")]
    pub wi_image: Vec<u8>,
}

#[derive(Debug)]
#[repr(C)]
pub struct BarcodeLayout {
    pub identification: [u8; 6],
    pub block1: [u8; 128],
    pub block2: [u8; 128],
    pub block3: [u8; 128],
    pub block4: [u8; 128],
    pub block5: [u8; 128],
    pub block6: [u8; 74],
}

#[derive(FromPrimitive, Debug, Clone, Serialize)]
#[repr(C)]

pub enum IDType {
    RegNoCert = 1,
    RSA = 2,
    Foreign = 3,
}
#[derive(FromPrimitive, Debug, Clone, Serialize)]
#[repr(C)]
pub enum DriverRestrictions {
    None,
    Glasses,
    ArtificialLimb,
}
#[derive(FromPrimitive, Debug, Clone, Serialize)]
#[repr(C)]

pub enum VehicleRestrictions {
    None,
    AutomaticTransmission,
    ElectricallyPowered,
    PhysicallyDisabled,
    BusGt16tons,
}
#[derive(FromPrimitive, Debug, Clone, Serialize)]
#[repr(C)]
pub enum Gender {
    Male,
    Female,
}

fn decrypt_barcode(barcode_data: Vec<u8>) -> Result<Vec<u8>, String> {
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    if barcode_data.len() != 720 {
        return Err("Barcode is malformed =! 720 bytes long".to_string());
    }
    let arr: [u8; 720] = barcode_data.try_into().expect("Malformed barcode");
    let barcode: BarcodeLayout;

    unsafe {
        barcode = mem::transmute::<[u8; 720], BarcodeLayout>(arr);
    }

    let version;
    if barcode.identification == [0x01, 0x9b, 0x09, 0x45, 0x00, 0x00] {
        version = BarcodeVersion::V2;
    } else if barcode.identification == [0x01, 0xe1, 0x02, 0x45, 0x00, 0x00] {
        version = BarcodeVersion::V1
    } else {
        return Err("Unknown Barcode Version".to_string());
    }
    let keys = Keys::init();
    let keyset;
    match version {
        BarcodeVersion::V1 => {
            keyset = keys.v1;
        }
        BarcodeVersion::V2 => {
            keyset = keys.v2;
        }
    }

    let mut dec = keyset
        .b128
        .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block1)
        .unwrap();
    dec.append(
        &mut keyset
            .b128
            .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block2)
            .unwrap()[5..]
            .to_vec(),
    );
    dec.append(
        &mut keyset
            .b128
            .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block3)
            .unwrap()[5..]
            .to_vec(),
    );
    dec.append(
        &mut keyset
            .b128
            .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block4)
            .unwrap()[5..]
            .to_vec(),
    );
    dec.append(
        &mut keyset
            .b128
            .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block5)
            .unwrap()[5..]
            .to_vec(),
    );
    dec.append(
        &mut keyset
            .b74
            .encrypt(&mut rng, PaddingScheme::new_no_padding(), &barcode.block6)
            .unwrap()[5..]
            .to_vec(),
    );
    Ok(dec)
}

pub fn parse_decrypted(decrypted_data: Vec<u8>) -> Result<LicenceData, Box<dyn Error>> {
    let mut header: HeaderLayout;
    let mut headerbytes: [u8; 15] = decrypted_data[0..15].try_into()?;
    headerbytes[13] &= 0x0F;
    unsafe {
        header = mem::transmute::<[u8; 15], HeaderLayout>(headerbytes);
    }
    header.data3len = header.data3len.to_be();

    let mut index = 15;
    let mut datablock1 = &decrypted_data[index..header.data1len as usize + index];
    index += header.data1len as usize;
    let datablock2nibbs = &decrypted_data[index..header.data2len as usize + index];
    index += header.data2len as usize;
    let datablock3 = &decrypted_data[index..header.data3len as usize + index];

    let mut datablock1_fields: Vec<Vec<u8>> = Vec::new();
    let mut datablock2_fields: Vec<Vec<u8>> = Vec::new();
    //Split nibbles into bytes for sane calculations
    let mut datablock2: Vec<u8> = Vec::new();
    for i in datablock2nibbs {
        datablock2.push((i & 0xF0) >> 4);
        datablock2.push(i & 0x0F);
    }

    loop {
        match datablock1.iter().position(|&r| r == 0xe0 || r == 0xe1) {
            Some(x) => {
                datablock1_fields.push(datablock1[0..x].to_vec());
                if datablock1[x] == 0xe1 && (datablock1.len() == x + 1 || datablock1[x + 1] != 0xe1)
                {
                    datablock1_fields.push(vec![]);
                }
                datablock1 = &datablock1[x + 1..];
            }
            None => {
                datablock1_fields.push(datablock1.to_vec());
                break;
            }
        }
    }
    let idtype: IDType = num::FromPrimitive::from_u8((datablock2[0] << 4) + datablock2[1]).unwrap();
    datablock2 = (&datablock2[2..]).to_vec();
    let mut found = 0;
    while found < 4 {
        if datablock2[0] == 0xa {
            datablock2_fields.push([].to_vec());
            datablock2 = (&datablock2[0x1..]).to_vec();
        } else {
            datablock2_fields.push(datablock2[0..8].to_vec());
            datablock2 = (&datablock2[0x8..]).to_vec();
        }
        found += 1;
    }
    let driverrestriction = vec![
        num::FromPrimitive::from_u8(datablock2[0]).ok_or(std::fmt::Error)?,
        num::FromPrimitive::from_u8(datablock2[1]).ok_or(std::fmt::Error)?,
    ];
    datablock2 = datablock2[2..].to_vec();

    if datablock2[0] == 0xa {
        datablock2_fields.push([].to_vec());
        datablock2 = (&datablock2[0x1..]).to_vec();
    } else {
        datablock2_fields.push(datablock2[0..8].to_vec());
        datablock2 = (&datablock2[0x8..]).to_vec();
    }

    let licissue = (datablock2[0] << 4) + datablock2[1];
    datablock2 = (&datablock2[2..]).to_vec();

    found = 0;
    while found < 3 {
        if datablock2[0] == 0xa {
            datablock2_fields.push([].to_vec());
            datablock2 = (&datablock2[0x1..]).to_vec();
        } else {
            datablock2_fields.push(datablock2[0..8].to_vec());
            datablock2 = (&datablock2[0x8..]).to_vec();
        }
        found += 1;
    }
    let gender: Gender = num::FromPrimitive::from_u8(datablock2[0]).ok_or(std::fmt::Error)?;

    let data = LicenceData {
        //datablock1
        surname: String::from_utf8(datablock1_fields[4].to_vec())?,
        initials: String::from_utf8(datablock1_fields[5].to_vec())?,
        codes: datablock1_fields[0..4]
            .iter()
            .enumerate()
            .filter_map(|(i, x)| match String::from_utf8(x.to_vec()) {
                Ok(res) => {
                    if !res.is_empty() {
                        Some((res, parse_date_from_slice(&datablock2_fields[i])?))
                    } else {
                        None
                    }
                }
                Err(_) => None,
            })
            .collect(),
        prdp: if datablock1_fields[6].is_empty() {
            None
        } else {
            Some((
                String::from_utf8(datablock1_fields[6].to_vec())?,
                parse_date_from_slice(&datablock2_fields[4]).ok_or(std::fmt::Error)?,
            ))
        },
        id_country_of_issue: String::from_utf8(datablock1_fields[7].to_vec())?,
        licence_country_of_issue: String::from_utf8(datablock1_fields[8].to_vec())?,
        vehicle_restrictions: datablock1_fields[9..13]
            .iter()
            .filter_map(|x| match String::from_utf8(x.to_vec()) {
                Ok(res) => {
                    if !res.is_empty() {
                        num::FromPrimitive::from_usize(res.parse::<usize>().unwrap())
                    } else {
                        None
                    }
                }
                Err(_) => None,
            })
            .collect(),
        driver_restrictions: driverrestriction,
        licence_number: String::from_utf8(datablock1_fields[13].to_vec())?,
        id_number: String::from_utf8(datablock1_fields[14].to_vec())?,
        //datablock2
        id_type: idtype,
        gender,
        licence_issue_number: licissue,
        birth_date: parse_date_from_slice(&datablock2_fields[5]),
        valid_from: parse_date_from_slice(&datablock2_fields[6]),
        valid_to: parse_date_from_slice(&datablock2_fields[7]),
        wi_image: datablock3.to_vec(),
    };

    Ok(data)
}

fn parse_date_from_slice(slice: &[u8]) -> Option<DateTime<Utc>> {
    if slice.len() == 8 {
        Some(Date::<Utc>::from_utc(
            NaiveDate::from_ymd(
                slice[0].to_i32()? * 1000
                    + slice[1].to_i32()? * 100
                    + slice[2].to_i32()? * 10
                    + slice[3].to_i32()?,
                (slice[4] * 10 + slice[5]).into(),
                (slice[6] * 10 + slice[7]).into(),
            ),
            Utc,
        ).and_hms(0, 0, 0))
    } else {
        None
    }
}

pub fn decrypt_and_parse(barcode_data: &[u8; 720]) -> Result<LicenceData, Box<dyn Error>> {
    let decrypted = decrypt_barcode(barcode_data.to_vec())?;
    return match parse_decrypted(decrypted) {
        Ok(data) => Ok(data),
        Err(err) => Err(err),
    };
}
