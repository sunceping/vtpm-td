// Copyright (c) 2022 - 2023 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec;
use core::convert::{TryFrom, TryInto};
use der::asn1::{
    Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString, PrintableString, SetOfVec,
    UIntBytes, UtcTime, Utf8String,
};
use der::{
    Choice, Decodable, Decoder, DerOrd, Encodable, Header, Sequence, Tag, TagNumber, Tagged,
};

#[derive(Debug)]
pub enum X509Error {
    DerEncoding(der::Error),
}

impl From<der::Error> for X509Error {
    fn from(e: der::Error) -> Self {
        X509Error::DerEncoding(e)
    }
}

pub struct CertificateBuilder<'a>(Certificate<'a>);

impl<'a> CertificateBuilder<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
    ) -> Result<Self, X509Error> {
        Ok(Self(Certificate::new(signature, algorithm, public_key)?))
    }

    pub fn set_not_before(mut self, time: core::time::Duration) -> Result<Self, X509Error> {
        self.0.tbs_certificate.validity.not_before =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(self)
    }

    pub fn set_not_after(mut self, time: core::time::Duration) -> Result<Self, X509Error> {
        self.0.tbs_certificate.validity.not_after =
            Time::Generalized(GeneralizedTime::from_unix_duration(time)?);
        Ok(self)
    }

    pub fn set_public_key(
        mut self,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
    ) -> Result<Self, X509Error> {
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::new(0, public_key)?,
        };
        self.0.tbs_certificate.subject_public_key_info = subject_public_key_info;
        Ok(self)
    }

    pub fn add_extension(mut self, extension: Extension<'a>) -> Result<Self, X509Error> {
        if let Some(extn) = self.0.tbs_certificate.extensions.as_mut() {
            extn.0.push(extension);
        } else {
            let extensions = vec![extension];
            self.0.tbs_certificate.extensions = Some(Extensions(extensions));
        }
        Ok(self)
    }

    pub fn sign(
        mut self,
        signature: &'a mut alloc::vec::Vec<u8>,
        mut signer: impl FnMut(&[u8], &mut alloc::vec::Vec<u8>),
    ) -> Result<Self, X509Error> {
        let tbs = self.0.tbs_certificate.to_vec().unwrap();
        signer(tbs.as_slice(), signature);
        self.0.signature_value = BitString::new(0, signature)?;
        Ok(self)
    }

    pub fn build(self) -> Certificate<'a> {
        self.0
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-3.1
// Certificate  ::=  SEQUENCE  {
//    tbsCertificate       TBSCertificate,
//    signatureAlgorithm   AlgorithmIdentifier,
//    signatureValue       BIT STRING  }
#[derive(Clone)]
pub struct Certificate<'a> {
    pub tbs_certificate: TBSCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitString<'a>,
}

impl<'a> Certificate<'a> {
    pub fn new(
        signature: AlgorithmIdentifier<'a>,
        algorithm: AlgorithmIdentifier<'a>,
        public_key: &'a [u8],
    ) -> Result<Self, X509Error> {
        let version = Version(UIntBytes::new(&[2])?);
        let serial_number = UIntBytes::new(&[1])?;

        let mut country_name = SetOfVec::new();
        country_name.add(DistinguishedName {
            attribute_type: ObjectIdentifier::new("2.5.4.6"),
            value: PrintableString::new("US")?.try_into().unwrap(),
        })?;
        let mut locality_name = SetOfVec::new();
        locality_name.add(DistinguishedName {
            attribute_type: ObjectIdentifier::new("2.5.4.7"),
            value: Utf8String::new("OR")?.try_into().unwrap(),
        })?;
        let mut organization_name = SetOfVec::new();
        organization_name.add(DistinguishedName {
            attribute_type: ObjectIdentifier::new("2.5.4.10"),
            value: Utf8String::new("Intel")?.try_into().unwrap(),
        })?;

        let issuer = vec![country_name, locality_name, organization_name];

        let validity = Validity {
            not_before: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
            not_after: Time::Generalized(GeneralizedTime::from_unix_duration(
                core::time::Duration::new(0, 0),
            )?),
        };

        let subject = issuer.clone();

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::new(0, public_key)?,
        };

        let tbs_certificate = TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        let signature_value = BitString::new(0, &[])?;

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm: signature,
            signature_value,
        })
    }

    pub fn tbs_certificate(&self) -> &TBSCertificate {
        &self.tbs_certificate
    }

    pub fn set_signature(&mut self, signature: &'a [u8]) -> Result<(), X509Error> {
        self.signature_value = BitString::new(0, signature)?;
        Ok(())
    }
}

impl<'a> Decodable<'a> for Certificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let tbs_certificate = decoder.decode()?;
            let signature_algorithm = decoder.decode()?;
            let signature_value = decoder.decode()?;

            Ok(Self {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            })
        })
    }
}

impl<'a> Sequence<'a> for Certificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.tbs_certificate,
            &self.signature_algorithm,
            &self.signature_value,
        ])
    }
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
// TBSCertificate  ::=  SEQUENCE  {
//     version         [0]  EXPLICIT Version DEFAULT v1,
//     serialNumber         CertificateSerialNumber,
//     signature            AlgorithmIdentifier,
//     issuer               Name,
//     validity             Validity,
//     subject              Name,
//     subjectPublicKeyInfo SubjectPublicKeyInfo,
//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                          -- If present, version MUST be v2 or v3
//     extensions      [3]  EXPLICIT Extensions OPTIONAL
//                          -- If present, version MUST be v3
// }
#[derive(Clone)]
pub struct TBSCertificate<'a> {
    pub version: Version<'a>,
    pub serial_number: UIntBytes<'a>, // ASN.1 INTEGER
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub validity: Validity,
    pub subject: alloc::vec::Vec<SetOfVec<DistinguishedName<'a>>>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,
    pub issuer_unique_id: Option<UniqueIdentifier<'a, 1>>,
    pub subject_unique_id: Option<UniqueIdentifier<'a, 2>>,
    pub extensions: Option<Extensions<'a>>,
}

impl<'a> Decodable<'a> for TBSCertificate<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let version = decoder.decode()?;
            let serial_number = decoder.decode()?;
            let signature = decoder.decode()?;
            let issuer = decoder.decode()?;
            let validity = decoder.decode()?;
            let subject = decoder.decode()?;
            let subject_public_key_info = decoder.decode()?;
            let issuer_unique_id = decoder.decode()?;
            let subject_unique_id = decoder.decode()?;
            let extensions = decoder.decode()?;

            Ok(Self {
                version,
                serial_number,
                signature,
                issuer,
                validity,
                subject,
                subject_public_key_info,
                extensions,
                issuer_unique_id,
                subject_unique_id,
            })
        })
    }
}

impl<'a> Sequence<'a> for TBSCertificate<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[
            &self.version,
            &self.serial_number,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.subject_public_key_info,
            &self.extensions,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version<'a>(UIntBytes<'a>);

impl<'a> Decodable<'a> for Version<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        Ok(Self(UIntBytes::from_der(res.value())?))
    }
}

impl<'a> Encodable for Version<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            der::Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(0),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a> Tagged for Version<'a> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

impl<'a> Choice<'a> for Version<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(0),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Any<'a>>,
}

impl<'a> Decodable<'a> for AlgorithmIdentifier<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let algorithm = decoder.decode()?;
            let parameters = decoder.decode()?;

            Ok(Self {
                algorithm,
                parameters,
            })
        })
    }
}

impl<'a> Sequence<'a> for AlgorithmIdentifier<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.algorithm, &self.parameters])
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DistinguishedName<'a> {
    pub(crate) attribute_type: ObjectIdentifier,
    pub(crate) value: Any<'a>,
}

impl<'a> DerOrd for DistinguishedName<'a> {
    fn der_cmp(&self, other: &Self) -> der::Result<core::cmp::Ordering> {
        Ok(self.attribute_type.cmp(&other.attribute_type))
    }
}

impl<'a> Decodable<'a> for DistinguishedName<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let attribute_type = decoder.decode()?;
            let value = decoder.decode()?;

            Ok(Self {
                attribute_type,
                value,
            })
        })
    }
}

impl<'a> Sequence<'a> for DistinguishedName<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.attribute_type, &self.value])
    }
}

#[derive(Choice, Copy, Clone, Debug, Eq, PartialEq)]
pub enum Time {
    #[asn1(type = "UTCTime")]
    Utc(UtcTime),
    #[asn1(type = "GeneralizedTime")]
    Generalized(GeneralizedTime),
}

impl From<UtcTime> for Time {
    fn from(time: UtcTime) -> Time {
        Time::Utc(time)
    }
}

impl From<GeneralizedTime> for Time {
    fn from(time: GeneralizedTime) -> Time {
        Time::Generalized(time)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Validity {
    not_before: Time,
    not_after: Time,
}

impl Decodable<'_> for Validity {
    fn decode(decoder: &mut Decoder) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let not_before = decoder.decode()?;
            let not_after = decoder.decode()?;

            Ok(Self {
                not_before,
                not_after,
            })
        })
    }
}

impl Sequence<'_> for Validity {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.not_before, &self.not_after])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitString<'a>,
}

#[allow(non_snake_case)]
impl<'a> Decodable<'a> for SubjectPublicKeyInfo<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let algorithm = decoder.decode()?;
            let subject_public_key = decoder.decode()?;

            Ok(Self {
                algorithm,
                subject_public_key,
            })
        })
    }
}

impl<'a> Sequence<'a> for SubjectPublicKeyInfo<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.algorithm, &self.subject_public_key])
    }
}

#[derive(Clone)]
pub struct UniqueIdentifier<'a, const N: u8>(BitString<'a>);

impl<'a, const N: u8> Decodable<'a> for UniqueIdentifier<'a, N> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        let uid = BitString::from_der(res.value())?;
        Ok(Self(uid))
    }
}

impl<'a, const N: u8> Encodable for UniqueIdentifier<'a, N> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(N),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a, const N: u8> Tagged for UniqueIdentifier<'a, N> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

impl<'a, const N: u8> Choice<'a> for UniqueIdentifier<'a, N> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(N),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extensions<'a>(alloc::vec::Vec<Extension<'a>>);

impl<'a> Extensions<'a> {
    pub fn get(&self) -> &alloc::vec::Vec<Extension<'a>> {
        &self.0
    }
}

impl<'a> Decodable<'a> for Extensions<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        let res = decoder.any()?;
        Ok(Self(alloc::vec::Vec::from_der(res.value())?))
    }
}

impl<'a> Encodable for Extensions<'a> {
    fn encoded_len(&self) -> der::Result<der::Length> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encoded_len() + len
    }

    fn encode(&self, encoder: &mut der::Encoder<'_>) -> der::Result<()> {
        let len = self.0.encoded_len()?;
        let explicit = Header::new(
            Tag::ContextSpecific {
                constructed: true,
                number: TagNumber::new(3),
            },
            len,
        )?;
        explicit.encode(encoder)?;
        self.0.encode(encoder)
    }
}

impl<'a> Tagged for Extensions<'a> {
    fn tag(&self) -> Tag {
        Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

impl<'a> Choice<'a> for Extensions<'a> {
    fn can_decode(tag: Tag) -> bool {
        tag == Tag::ContextSpecific {
            constructed: true,
            number: TagNumber::new(3),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extension<'a> {
    pub extn_id: ObjectIdentifier,
    pub critical: Option<bool>, // ASN.1 BOOLEAN.
    pub extn_value: Option<OctetString<'a>>,
}

impl<'a> Extension<'a> {
    pub fn new(
        extn_id: ObjectIdentifier,
        critical: Option<bool>,
        extn_value: Option<&'a [u8]>,
    ) -> Result<Self, X509Error> {
        let extn_value = if let Some(extn_value) = extn_value {
            Some(OctetString::new(extn_value)?)
        } else {
            None
        };

        Ok(Self {
            extn_id,
            critical,
            extn_value,
        })
    }
}

impl<'a> Decodable<'a> for Extension<'a> {
    fn decode(decoder: &mut Decoder<'a>) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            let extn_id = decoder.decode()?;
            let critical = decoder.decode()?;
            let extn_value = decoder.decode()?;

            Ok(Self {
                extn_id,
                critical,
                extn_value,
            })
        })
    }
}

impl<'a> Sequence<'a> for Extension<'a> {
    fn fields<F, T>(&self, field_encoder: F) -> der::Result<T>
    where
        F: FnOnce(&[&dyn Encodable]) -> der::Result<T>,
    {
        field_encoder(&[&self.extn_id, &self.critical, &self.extn_value])
    }
}

pub type ExtendedKeyUsage = alloc::vec::Vec<ObjectIdentifier>;


#[cfg(test)]
mod test {
    use super::*;
    // use ring::pkcs8::Document;
    use ring::rand::SystemRandom;
    use ring::signature::{self, EcdsaKeyPair, KeyPair};
    use zerocopy::AsBytes;
    const ID_EC_PUBKEY_OID: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");
    const SECP384R1_OID: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

    #[test]
    fn test_new_cert() {
        let algorithm = AlgorithmIdentifier {
            algorithm: ID_EC_PUBKEY_OID,
            parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
        };

        let rand = SystemRandom::new();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rand)
                .map_err(|_| 0);
        let pkc8 = pkcs8_bytes.unwrap();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
            pkc8.as_ref(),
        );
        let key = key_pair.unwrap();
        print!("public key is {:?}\n",key.public_key());

        let mut certificatebuilder =
            CertificateBuilder::new(algorithm, algorithm, key.public_key().as_ref());
        print!("cert new is {}\n", certificatebuilder.is_err());
        assert_eq!(certificatebuilder.is_err(), false);

        // 1970-01-01T00:00:00Z
        certificatebuilder = certificatebuilder
            .unwrap()
            .set_not_before(core::time::Duration::new(0, 0));       
 
        print!("cert set_not_before is {}\n", certificatebuilder.is_err());
        assert_eq!(certificatebuilder.is_err(), false);
       // 9999-12-31T23:59:59Z
        certificatebuilder = certificatebuilder
            .unwrap()
            .set_not_after(core::time::Duration::new(253402300799, 0));
        print!("cert set_not_after is {}\n", certificatebuilder.is_err());
        assert_eq!(certificatebuilder.is_err(), false);

        certificatebuilder = certificatebuilder
            .unwrap()
            .set_public_key(algorithm, key.public_key().as_ref());
        print!("cert set_public_key is {}\n", certificatebuilder.is_err());
        assert_eq!(certificatebuilder.is_err(), false);

        let extn_id: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
        let value :[u8;0x100] = [0xff;0x100];
        let extension = Extension::new(extn_id, Some(false), Some(&value));
        certificatebuilder = certificatebuilder.unwrap().add_extension(extension.unwrap());

        let mut sig_buf : alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let signer = |data: &[u8], sig_buf: &mut alloc::vec::Vec<u8>| {
            let rand = SystemRandom::new();
            let signature = key.sign(&rand, data).unwrap();
            sig_buf.extend_from_slice(signature.as_ref());
        };
        certificatebuilder = certificatebuilder.unwrap().sign(&mut sig_buf, signer);
        print!("cert sign is {}\n", certificatebuilder.is_err());
        assert_eq!(certificatebuilder.is_err(), false);

        let mut cert = certificatebuilder.unwrap().build();

        let tb_cert = cert.tbs_certificate();
        print!("tb_cert signature is {:?}\n",tb_cert.signature);
        assert_eq!(tb_cert.signature, algorithm);

        print!("cert {:?}\n", cert.tbs_certificate().validity.not_before);
        print!("cert {:?}\n", cert.tbs_certificate().validity.not_after);
        print!("Public key algorithm is {:?}\n",  cert.tbs_certificate.subject_public_key_info.algorithm);
        // print!("Public key info is {:?}\n",  cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes());
        assert_eq!(cert.tbs_certificate.subject_public_key_info.algorithm,algorithm);

        let data = [0u8;100];
        let res = cert.set_signature(&data);
        assert!(res.is_ok());

    }

    #[test]
    fn test_extension_new_none(){
        let extn_id: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
        let extension = Extension::new(extn_id, Some(false), None);
        print!("extension is {}\n",extension.is_err());
        print!("extension critical is {:?}\n",extension.unwrap().critical);
    }

    #[test]
    fn test_version(){
        let bytes:[u8;1] = [1;1];
        print!("len {}\n",bytes.as_bytes().len());
        let uinbytes = UIntBytes::new(&bytes).unwrap();
        let uinbytes_len = uinbytes.encoded_len().unwrap();
        print!("uinbytes_len {}\n",uinbytes_len);
        let uinbytes_len = uinbytes.len();
        print!("uinbytes_len {}\n",uinbytes_len);
        let version = Version(uinbytes);
        let tag = version.tag();
        print!("tag number is {}\n",tag.number());
        print!("tag number is {}\n", tag.is_context_specific());
        assert_eq!(tag.number(), TagNumber::N0);
        assert_eq!(tag.is_context_specific(), true);
        let mut can_decode = Version::can_decode(tag);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,true);
        let tag_false = Tag::ContextSpecific { constructed: false, number: TagNumber::new(0) };
        can_decode = Version::can_decode(tag_false);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,false);
        let tag_n30 = Tag::ContextSpecific { constructed: true, number: TagNumber::new(30) };
        can_decode = Version::can_decode(tag_n30);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,false);


        let der_len = version.encoded_len();
        assert_eq!(der_len.is_err(),false);
        // assert_eq!(der_len.unwrap(), uinbytes_len + 3);
        print!("der_len is {}\n",der_len.unwrap());

        let bytes:[u8;1] = [0;1];
        print!("len {}\n",bytes.as_bytes().len());
        let uinbytes = UIntBytes::new(&bytes).unwrap();
        let version = Version(uinbytes);
        let mut bytes = [0u8;10];
        let mut encode_data = der::Encoder::new(&mut bytes);
        print!("encode_data is {:?}\n",encode_data);
        let der_encode = version.encode(&mut encode_data);
        print!("der_encode is {}\n",der_encode.is_err());

        let buffer:[u8;10] = [0;10];
        let decoder_res = der::Decoder::new(&buffer);
        print!("decoder_res is {}\n ",decoder_res.is_err());
        let mut decoder = decoder_res.unwrap();
        print!("none {}\n",decoder.is_failed());
        let res = decoder.any();
        print!("res is {}\n",res.is_err());
        let der = Version::decode(&mut decoder);
        print!("der res is {}\n", der.is_err());

    }

    #[test]
    fn test_algorithm_identifier(){
        let algorithm = AlgorithmIdentifier {
            algorithm: ID_EC_PUBKEY_OID,
            parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
        };
        let binding = algorithm.to_vec().unwrap();
        let buffer= binding.as_slice();
        let mut decoder = der::Decoder::new(&buffer).unwrap();
        let res = AlgorithmIdentifier::decode(&mut decoder);
        print!("res is {}\n", res.is_err());
    }

    #[test]
    fn test_extension(){
        let mut extn_id: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
        let value :[u8;0x100] = [0xff;0x100];
        let extension = Extension::new(extn_id, Some(false), Some(&value));
        assert_ne!(extension.is_err(),true);
        assert_eq!(extension.as_ref().unwrap().extn_id,extn_id);
        assert_eq!(extension.as_ref().unwrap().critical,Some(false));
        // assert_eq!(extension.unwrap().extn_value,Some(&value));
        extn_id = ObjectIdentifier::new("2.5.29.30");
        let extension =  Extension::new(extn_id, Some(true), Some(&[]));
        print!("extension is {}\n",extension.is_err());
        let buffer:[u8;1024] = [0xff;1024];
        let mut decoder = der::Decoder::new(&buffer).unwrap();
        let decode_extn = Extension::decode(&mut decoder);
        print!("decode_extn is {}\n",decode_extn.is_err());
    }

    #[test]
    fn test_strcut_extensions(){
        let extn_id: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");
        let value :[u8;0x100] = [0xff;0x100];
        let extension = Extension::new(extn_id, Some(false), Some(&value)).unwrap();
        let extensios = Extensions(vec![extension]);

        let tag = extensios.tag();
        assert_eq!(tag.number(),TagNumber::N3);
        assert!(tag.is_context_specific());
        let mut can_decode = Extensions::can_decode(tag);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,true);
        let tag_false = Tag::ContextSpecific { constructed: false, number: TagNumber::new(0) };
        can_decode = Extensions::can_decode(tag_false);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,false);
        let tag_n30 = Tag::ContextSpecific { constructed: true, number: TagNumber::new(30) };
        can_decode = Extensions::can_decode(tag_n30);
        print!("can_decode is {}\n",can_decode);
        assert_eq!(can_decode,false);
        let get_res = extensios.get();
        assert_eq!(get_res.get(0).unwrap().extn_id,extn_id);
        assert_eq!(get_res.get(0).unwrap().critical,Some(false));

        let encode_len_res = extensios.encoded_len();
        assert_ne!(encode_len_res.is_err(),true);
        print!("encode_len_res is {}\n", encode_len_res.unwrap());

        let mut bytes1 = [0u8;279];
        let mut encode_data = der::Encoder::new(&mut bytes1);
        let mut encode_res = extensios.encode(&mut encode_data);
        print!("encode_res {}\n",encode_res.is_err());
        assert!(encode_res.is_err());
        let mut  bytes2 = [0u8;280];
          encode_data = der::Encoder::new(&mut bytes2);
         encode_res = extensios.encode(&mut encode_data);
        assert_ne!(encode_res.is_err(), true);
    }

    #[test]
    fn test_subject_publickeyinfo(){
        let algorithm = AlgorithmIdentifier {
            algorithm: ID_EC_PUBKEY_OID,
            parameters: Some(Any::new(Tag::ObjectIdentifier, SECP384R1_OID.as_bytes()).unwrap()),
        };
        let public_key =[0u8;96];
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::new(0, &public_key).unwrap(),
        };
        print!("subject_public_key_info is {:?}\n",subject_public_key_info.encoded_len());
        // const EXAMPLE_MSG: &[u8] = hex::encode("0022FF");
        let buffer = [0u8;120];
        let mut decoder = der::Decoder::new(&buffer).unwrap();
        let res = SubjectPublicKeyInfo::decode(&mut decoder);
        print!("res is {}\n",res.is_err());
    }

}