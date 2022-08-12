use std::{
    error,
    ffi::{CString, NulError},
    fmt, mem, ptr,
};

use log::{debug, error};
use windows::{
    core::PSTR,
    Win32::{Foundation::GetLastError, Security::Cryptography::*},
};

use crate::cert::*;

fn get_last_error() -> u32 {
    unsafe { GetLastError().0 }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CmsError {
    NoSigner,
    NoRecipient,
    NoPrivateKey,
    NameError,
    ProcessingError(u32),
    CertError(CertError),
}

impl error::Error for CmsError {}

impl fmt::Display for CmsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CmsError::NoSigner => write!(f, "No signer certificate"),
            CmsError::NoRecipient => write!(f, "No recipient certificate"),
            CmsError::NoPrivateKey => write!(f, "No private key for signer certificate"),
            CmsError::NameError => write!(f, "Name error"),
            CmsError::ProcessingError(e) => write!(f, "Processing error: {:08x}", e),
            CmsError::CertError(e) => write!(f, "Certificate error: {}", e),
        }
    }
}

impl From<widestring::error::NulError<u16>> for CmsError {
    fn from(_: widestring::error::NulError<u16>) -> Self {
        CmsError::NameError
    }
}

impl From<NulError> for CmsError {
    fn from(_: NulError) -> Self {
        CmsError::NameError
    }
}

impl From<CertError> for CmsError {
    fn from(e: CertError) -> Self {
        CmsError::CertError(e)
    }
}

pub struct CmsContentBuilder {
    signer: Option<CertContext>,
    recipients: Vec<CertContext>,
    hash_algorithm: String,
    encrypt_algorithm: String,
}

impl CmsContentBuilder {
    pub fn signer(mut self, signer: CertContext) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn recipients<I>(mut self, recipients: I) -> Self
    where
        I: IntoIterator<Item = CertContext>,
    {
        self.recipients = recipients.into_iter().collect();
        self
    }

    pub fn hash_algorithm<S>(mut self, algorithm: S) -> Self
    where
        S: AsRef<str>,
    {
        self.hash_algorithm = algorithm.as_ref().to_owned();
        self
    }

    pub fn encrypt_algorithm<S>(mut self, algorithm: S) -> Self
    where
        S: AsRef<str>,
    {
        self.encrypt_algorithm = algorithm.as_ref().to_owned();
        self
    }

    pub fn build(self) -> CmsContent {
        CmsContent(self)
    }
}

pub struct CmsContent(CmsContentBuilder);

impl CmsContent {
    pub fn builder() -> CmsContentBuilder {
        CmsContentBuilder {
            signer: None,
            recipients: Vec::new(),
            hash_algorithm: szOID_RSA_SHA256RSA.to_owned(),
            encrypt_algorithm: szOID_NIST_AES256_CBC.to_owned(),
        }
    }

    /// Produces PKCS#7 CMS message which is signed with signer key and encrypted with recipient certificates
    pub fn sign_and_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CmsError> {
        let signer = self.0.signer.as_ref().ok_or(CmsError::NoSigner)?;

        if self.0.recipients.is_empty() {
            return Err(CmsError::NoRecipient);
        }

        let mut hash_alg = CRYPT_ALGORITHM_IDENTIFIER::default();
        let alg_str = CString::new(self.0.hash_algorithm.as_bytes())?;
        hash_alg.pszObjId = PSTR(alg_str.as_ptr() as _);

        debug!("Using hash algorithm: {}", self.0.hash_algorithm);

        let mut signers = [signer.as_ptr()];

        let sign_param = CRYPT_SIGN_MESSAGE_PARA {
            cbSize: mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32,
            dwMsgEncodingType: MY_ENCODING_TYPE.0,
            pSigningCert: signer.as_ptr() as _,
            HashAlgorithm: hash_alg,
            cMsgCert: 1,
            rgpMsgCert: signers.as_mut_ptr() as _,
            ..Default::default()
        };

        let mut crypt_alg = CRYPT_ALGORITHM_IDENTIFIER::default();
        let alg_str = CString::new(self.0.encrypt_algorithm.as_bytes())?;
        crypt_alg.pszObjId = PSTR(alg_str.as_ptr() as _);

        debug!("Using encryption algorithm: {}", self.0.encrypt_algorithm);

        let encrypt_param = CRYPT_ENCRYPT_MESSAGE_PARA {
            cbSize: mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as u32,
            dwMsgEncodingType: MY_ENCODING_TYPE.0,
            ContentEncryptionAlgorithm: crypt_alg,
            ..Default::default()
        };

        let recipients = self
            .0
            .recipients
            .iter()
            .map(|r| r.as_ptr())
            .collect::<Vec<_>>();

        let mut encoded_blob_size: u32 = 0;
        let result = unsafe {
            CryptSignAndEncryptMessage(
                &sign_param,
                &encrypt_param,
                &recipients,
                data.as_ptr(),
                data.len() as u32,
                ptr::null_mut(),
                &mut encoded_blob_size,
            )
        }
        .as_bool();

        if !result {
            error!(
                "Cannot calculate blob size, error: {:08x}",
                get_last_error()
            );
            return Err(CmsError::ProcessingError(get_last_error()));
        }

        debug!(
            "Data size: {}, encrypted blob size: {}",
            data.len(),
            encoded_blob_size
        );

        let mut encoded_blob = vec![0u8; encoded_blob_size as usize];

        let result = unsafe {
            CryptSignAndEncryptMessage(
                &sign_param,
                &encrypt_param,
                &recipients,
                data.as_ptr(),
                data.len() as u32,
                encoded_blob.as_mut_ptr(),
                &mut encoded_blob_size,
            )
            .as_bool()
        };

        if !result {
            error!("Sign and encode failed, error: {:08x}", get_last_error());
            Err(CmsError::ProcessingError(get_last_error()))
        } else {
            debug!("Sign and encrypt succeeded");
            encoded_blob.truncate(encoded_blob_size as _);
            Ok(encoded_blob)
        }
    }

    pub fn decrypt_and_verify(store: &CertStore, data: &[u8]) -> Result<Vec<u8>, CmsError> {
        unsafe {
            let mut stores = [store.handle()];

            let decrypt_param = CRYPT_DECRYPT_MESSAGE_PARA {
                cbSize: mem::size_of::<CRYPT_DECRYPT_MESSAGE_PARA>() as u32,
                dwMsgAndCertEncodingType: MY_ENCODING_TYPE.0,
                cCertStore: 1,
                rghCertStore: stores.as_mut_ptr() as _,
            };

            let verify_param = CRYPT_VERIFY_MESSAGE_PARA {
                cbSize: mem::size_of::<CRYPT_VERIFY_MESSAGE_PARA>() as u32,
                dwMsgAndCertEncodingType: MY_ENCODING_TYPE.0,
                ..Default::default()
            };

            let mut message_size = 0u32;

            let rc = CryptDecryptAndVerifyMessageSignature(
                &decrypt_param,
                &verify_param,
                0,
                data.as_ptr(),
                data.len() as u32,
                ptr::null_mut(),
                &mut message_size,
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .as_bool();

            if !rc {
                error!(
                    "Cannot calculate message size, error: {:08x}",
                    GetLastError().0
                );
                return Err(CmsError::ProcessingError(GetLastError().0));
            }

            let mut message = vec![0u8; message_size as usize];

            let rc = CryptDecryptAndVerifyMessageSignature(
                &decrypt_param,
                &verify_param,
                0,
                data.as_ptr(),
                data.len() as u32,
                message.as_mut_ptr(),
                &mut message_size,
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .as_bool();

            if !rc {
                error!(
                    "Cannot decrypt and verify message, error: {:08x}",
                    GetLastError().0
                );
                return Err(CmsError::ProcessingError(GetLastError().0));
            }

            debug!(
                "Decrypt and verify succeeded, output size: {}",
                message_size
            );
            message.truncate(message_size as _);

            Ok(message)
        }
    }
}
