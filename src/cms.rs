use std::{
    error,
    ffi::{CString, NulError},
    fmt, mem, ptr,
};

use log::{debug, error};
use winapi::um::{errhandlingapi::GetLastError, wincrypt};

use crate::cng::*;

#[derive(Debug, Clone, PartialEq)]
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

impl From<widestring::NulError<u16>> for CmsError {
    fn from(_: widestring::NulError<u16>) -> Self {
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

    pub fn build(self) -> Result<CmsContent, CmsError> {
        if let Some(signer) = self.signer {
            if self.recipients.is_empty() {
                return Err(CmsError::NoRecipient);
            }

            Ok(CmsContent {
                signer,
                recipients: self.recipients,
            })
        } else {
            Err(CmsError::NoSigner)
        }
    }
}

pub struct CmsContent {
    signer: CertContext,
    recipients: Vec<CertContext>,
}

impl CmsContent {
    pub fn builder() -> CmsContentBuilder {
        CmsContentBuilder {
            signer: None,
            recipients: Vec::new(),
        }
    }

    /// Produces PKCS#7 CMS message which is signed with signer key and encrypted with recipient certificates
    pub fn sign_and_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CmsError> {
        unsafe {
            let mut hash_alg = mem::zeroed::<wincrypt::CRYPT_ALGORITHM_IDENTIFIER>();
            let alg_str = CString::new(wincrypt::szOID_RSA_SHA256RSA)?;
            hash_alg.pszObjId = alg_str.as_ptr() as *mut _;

            debug!("Using hash algorithm: {}", wincrypt::szOID_RSA_SHA256RSA);

            let mut signers = [self.signer.as_ptr()];

            let mut sign_param = mem::zeroed::<wincrypt::CRYPT_SIGN_MESSAGE_PARA>();
            sign_param.cbSize = mem::size_of::<wincrypt::CRYPT_SIGN_MESSAGE_PARA>() as u32;
            sign_param.dwMsgEncodingType = MY_ENCODING_TYPE;
            sign_param.pSigningCert = self.signer.as_ptr();
            sign_param.cMsgCert = 1;
            sign_param.rgpMsgCert = signers.as_mut_ptr();
            sign_param.HashAlgorithm = hash_alg;

            let mut crypt_alg = mem::zeroed::<wincrypt::CRYPT_ALGORITHM_IDENTIFIER>();
            let alg_str = CString::new(wincrypt::szOID_NIST_AES256_CBC)?;
            crypt_alg.pszObjId = alg_str.as_ptr() as *mut _;

            debug!(
                "Using encryption algorithm: {}",
                wincrypt::szOID_NIST_AES256_CBC
            );

            let mut encrypt_param = mem::zeroed::<wincrypt::CRYPT_ENCRYPT_MESSAGE_PARA>();
            encrypt_param.cbSize = mem::size_of::<wincrypt::CRYPT_ENCRYPT_MESSAGE_PARA>() as u32;
            encrypt_param.dwMsgEncodingType = MY_ENCODING_TYPE;
            encrypt_param.ContentEncryptionAlgorithm = crypt_alg;

            let mut recipients = self
                .recipients
                .iter()
                .map(|r| r.as_ptr())
                .collect::<Vec<_>>();

            let mut encoded_blob_size: u32 = 0;
            let result = wincrypt::CryptSignAndEncryptMessage(
                &mut sign_param,
                &mut encrypt_param as *mut _ as *mut _,
                self.recipients.len() as u32,
                recipients.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
                ptr::null_mut(),
                &mut encoded_blob_size,
            ) != 0;

            if !result {
                error!("Cannot calculate blob size, error: {:08x}", GetLastError());
                return Err(CmsError::ProcessingError(GetLastError()));
            }

            debug!(
                "Data size: {}, encrypted blob size: {}",
                data.len(),
                encoded_blob_size
            );

            let mut encoded_blob = vec![0u8; encoded_blob_size as usize];

            let result = wincrypt::CryptSignAndEncryptMessage(
                &mut sign_param,
                &mut encrypt_param as *mut _ as *mut _,
                self.recipients.len() as u32,
                recipients.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
                encoded_blob.as_mut_ptr(),
                &mut encoded_blob_size,
            ) != 0;

            if !result {
                error!("Sign and encode failed, error: {:08x}", GetLastError());
                Err(CmsError::ProcessingError(GetLastError()))
            } else {
                debug!("Sign and encrypt succeeded");
                Ok(encoded_blob)
            }
        }
    }
}
