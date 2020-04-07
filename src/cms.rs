#![allow(dead_code)]

use std::{
    error,
    ffi::{CString, NulError},
    fmt, mem, ptr,
};

use log::error;
use widestring::U16CString;
use winapi::{
    shared::winerror::ERROR_SUCCESS,
    um::{
        errhandlingapi::GetLastError,
        ncrypt::NCryptSetProperty,
        wincrypt::{
            szOID_NIST_AES256_CBC, szOID_RSA_SHA256RSA, CryptSignAndEncryptMessage,
            CRYPT_ALGORITHM_IDENTIFIER, CRYPT_DECRYPT_MESSAGE_PARA, CRYPT_ENCRYPT_MESSAGE_PARA,
            CRYPT_MESSAGE_SILENT_KEYSET_FLAG, CRYPT_SIGN_MESSAGE_PARA,
        },
    },
};

use crate::cng::*;

#[derive(Debug, Clone, PartialEq)]
pub enum CmsError {
    NoSigner,
    NoRecipient,
    NoPrivateKey,
    PinError,
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
            CmsError::PinError => write!(f, "PIN error"),
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
    signer: String,
    recipients: Vec<String>,
    password: Option<String>,
    silent: bool,
    cert_store_type: CertStoreType,
}

impl CmsContentBuilder {
    pub fn signer<S>(mut self, signer: S) -> Self
    where
        S: AsRef<str>,
    {
        self.signer = signer.as_ref().to_owned();
        self
    }

    pub fn recipients<I, S>(mut self, recipients: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.recipients = recipients
            .into_iter()
            .map(|s| s.as_ref().to_owned())
            .collect();
        self
    }

    pub fn password<S>(mut self, password: S) -> Self
    where
        S: AsRef<str>,
    {
        self.password = Some(password.as_ref().to_owned());
        self
    }

    pub fn silent(mut self, silent: bool) -> Self {
        self.silent = silent;
        self
    }

    pub fn cert_store_type(mut self, store_type: CertStoreType) -> Self {
        self.cert_store_type = store_type;
        self
    }

    pub fn build(self) -> Result<CmsContent, CmsError> {
        if self.signer.is_empty() {
            return Err(CmsError::NoSigner);
        }

        if self.recipients.is_empty() {
            return Err(CmsError::NoRecipient);
        }

        let store = CertStore::open(self.cert_store_type, "my")?;

        let mut signer = store.find_cert_by_subject_str(self.signer)?;

        let mut recipients = Vec::new();
        for rcpt in self.recipients {
            recipients.push(store.find_cert_by_subject_str(rcpt)?);
        }

        let key = signer.acquire_key()?;

        // TESTTEST
        // let raw_cert = signer.get_data();
        // let prov = key.get_provider()?;
        // let name = key.get_name()?;
        // let raw_key = NCryptKey::open(&prov, &name)?;
        // CertStore::open(CertStoreType::LocalMachine, "my")?.add_cert(&raw_cert, Some(raw_key))?;

        if let Some(password) = self.password {
            let pin_prop = U16CString::from_str(NCRYPT_PIN_PROPERTY)?;
            let pin = U16CString::from_str(&password)?;

            let result = unsafe {
                NCryptSetProperty(
                    key.as_ptr(),
                    pin_prop.as_ptr(),
                    pin.as_ptr() as *mut u8,
                    password.len() as u32,
                    0,
                ) as u32
            };
            if result != ERROR_SUCCESS {
                error!("Cannot set pin code");
                return Err(CmsError::PinError);
            }
        }

        Ok(CmsContent {
            signer,
            recipients,
            silent: self.silent,
        })
    }
}

pub struct CmsContent {
    signer: CertContext,
    recipients: Vec<CertContext>,
    silent: bool,
}

impl CmsContent {
    pub fn builder() -> CmsContentBuilder {
        CmsContentBuilder {
            signer: String::new(),
            recipients: Vec::new(),
            password: None,
            silent: false,
            cert_store_type: CertStoreType::CurrentUser,
        }
    }

    /// Produces PKCS#7 CMS message which is signed with signer key and encrypted with recipient certificates
    pub fn sign_and_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CmsError> {
        let mut hash_alg = unsafe { mem::zeroed::<CRYPT_ALGORITHM_IDENTIFIER>() };
        let alg_str = CString::new(szOID_RSA_SHA256RSA)?;
        hash_alg.pszObjId = alg_str.as_ptr() as *mut i8;

        let mut signers = [self.signer.as_ptr()];

        let mut sign_param = unsafe { mem::zeroed::<CRYPT_SIGN_MESSAGE_PARA>() };
        sign_param.cbSize = mem::size_of::<CRYPT_SIGN_MESSAGE_PARA>() as u32;
        sign_param.dwMsgEncodingType = MY_ENCODING_TYPE;
        sign_param.pSigningCert = self.signer.as_ptr();
        sign_param.cMsgCert = 1;
        sign_param.rgpMsgCert = signers.as_mut_ptr();
        sign_param.HashAlgorithm = hash_alg;
        sign_param.dwFlags = if self.silent {
            CRYPT_MESSAGE_SILENT_KEYSET_FLAG
        } else {
            0
        };

        let mut crypt_alg = unsafe { mem::zeroed::<CRYPT_ALGORITHM_IDENTIFIER>() };
        let alg_str = CString::new(szOID_NIST_AES256_CBC)?;
        crypt_alg.pszObjId = alg_str.as_ptr() as *mut i8;

        let mut encrypt_param = unsafe { mem::zeroed::<CRYPT_ENCRYPT_MESSAGE_PARA>() };
        encrypt_param.cbSize = mem::size_of::<CRYPT_ENCRYPT_MESSAGE_PARA>() as u32;
        encrypt_param.dwMsgEncodingType = MY_ENCODING_TYPE;
        encrypt_param.ContentEncryptionAlgorithm = crypt_alg;

        let mut recipients = self
            .recipients
            .iter()
            .map(|r| r.as_ptr())
            .collect::<Vec<_>>();

        let mut encoded_blob_size: u32 = 0;
        let result = unsafe {
            CryptSignAndEncryptMessage(
                &mut sign_param,
                &mut encrypt_param as *mut CRYPT_ENCRYPT_MESSAGE_PARA
                    as *mut CRYPT_DECRYPT_MESSAGE_PARA,
                self.recipients.len() as u32,
                recipients.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
                ptr::null_mut(),
                &mut encoded_blob_size,
            ) != 0
        };

        if !result {
            return Err(CmsError::ProcessingError(unsafe { GetLastError() }));
        }

        let mut encoded_blob = vec![0u8; encoded_blob_size as usize];

        let result = unsafe {
            CryptSignAndEncryptMessage(
                &mut sign_param,
                &mut encrypt_param as *mut CRYPT_ENCRYPT_MESSAGE_PARA
                    as *mut CRYPT_DECRYPT_MESSAGE_PARA,
                self.recipients.len() as u32,
                recipients.as_mut_ptr(),
                data.as_ptr(),
                data.len() as u32,
                encoded_blob.as_mut_ptr(),
                &mut encoded_blob_size,
            ) != 0
        };

        if !result {
            Err(CmsError::ProcessingError(unsafe { GetLastError() }))
        } else {
            Ok(encoded_blob)
        }
    }
}
