use std::{error, ffi::NulError, fmt, mem, ptr, str::FromStr, sync::Arc};

use log::error;
use widestring::{U16CStr, U16CString};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::GetLastError,
        Security::{Cryptography::*, OBJECT_SECURITY_INFORMATION},
    },
};

pub const MY_ENCODING_TYPE: CERT_QUERY_ENCODING_TYPE =
    CERT_QUERY_ENCODING_TYPE(PKCS_7_ASN_ENCODING.0 | X509_ASN_ENCODING.0);

#[derive(Debug, Clone, PartialEq)]
pub enum CertError {
    StoreError(u32),
    ContextError(u32),
    CngError(u32),
    NameError,
    InvalidStoreType,
    PinError,
}

impl error::Error for CertError {}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertError::StoreError(e) => write!(f, "Certificate store error: {:08x}", e),
            CertError::ContextError(e) => write!(f, "Certificate context error: {:08x}", e),
            CertError::CngError(e) => write!(f, "CNG error: {:08x}", e),
            CertError::NameError => write!(f, "Name error"),
            CertError::InvalidStoreType => write!(f, "Invalid certificate store type"),
            CertError::PinError => write!(f, "PIN error"),
        }
    }
}

impl From<widestring::error::ContainsNul<u16>> for CertError {
    fn from(_: widestring::error::ContainsNul<u16>) -> Self {
        CertError::NameError
    }
}

impl From<NulError> for CertError {
    fn from(_: NulError) -> Self {
        CertError::NameError
    }
}

struct InnerKey(NCRYPT_HANDLE);

impl Drop for InnerKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(self.0);
        };
    }
}

#[derive(Clone)]
pub struct NCryptKey(Arc<InnerKey>);

impl NCryptKey {
    pub fn from_handle(handle: NCRYPT_HANDLE) -> Self {
        NCryptKey(Arc::new(InnerKey(handle)))
    }

    pub fn handle(&self) -> NCRYPT_HANDLE {
        (self.0).0
    }

    pub fn open(provider_name: &str, key_name: &str) -> Result<Self, CertError> {
        let mut handle = NCRYPT_PROV_HANDLE::default();

        unsafe {
            match NCryptOpenStorageProvider(&mut handle, provider_name, 0) {
                Ok(_) => {
                    let mut hkey = NCRYPT_KEY_HANDLE::default();

                    let result = NCryptOpenKey(
                        handle,
                        &mut hkey,
                        key_name,
                        CERT_KEY_SPEC::default(),
                        NCRYPT_FLAGS::default(),
                    );

                    let _ = NCryptFreeObject(NCRYPT_HANDLE(handle.0));

                    match result {
                        Ok(_) => Ok(NCryptKey::from_handle(NCRYPT_HANDLE(hkey.0))),
                        Err(e) => {
                            error!("Cannot open key: {}", key_name);
                            Err(CertError::CngError(e.code().0 as _))
                        }
                    }
                }
                Err(e) => {
                    error!("Cannot open storage provider: {}", provider_name);
                    Err(CertError::CngError(e.code().0 as _))
                }
            }
        }
    }

    pub fn get_name(&self) -> Result<String, CertError> {
        let mut key_name_prop = vec![0u8; 1024];
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.handle(),
                NCRYPT_NAME_PROPERTY,
                key_name_prop.as_mut_ptr(),
                key_name_prop.len() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );
            if let Err(e) = rc {
                error!("Cannot get key property: {}", NCRYPT_NAME_PROPERTY);
                return Err(CertError::ContextError(e.code().0 as _));
            }
            Ok(U16CStr::from_ptr_str(key_name_prop.as_ptr() as _).to_string_lossy())
        }
    }

    pub fn get_provider(&self) -> Result<String, CertError> {
        let mut prov_handle = NCRYPT_HANDLE::default();
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.handle(),
                NCRYPT_PROVIDER_HANDLE_PROPERTY,
                &mut prov_handle as *mut _ as _,
                mem::size_of::<NCRYPT_HANDLE>() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );

            if let Err(e) = rc {
                error!(
                    "Cannot get key property: {}",
                    NCRYPT_PROVIDER_HANDLE_PROPERTY
                );
                return Err(CertError::ContextError(e.code().0 as _));
            }

            let mut prov_name_prop = vec![0u8; 1024];

            let rc = NCryptGetProperty(
                prov_handle,
                NCRYPT_NAME_PROPERTY,
                prov_name_prop.as_mut_ptr(),
                prov_name_prop.len() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );

            let _ = NCryptFreeObject(prov_handle);

            match rc {
                Ok(_) => Ok(
                    U16CStr::from_ptr_str(prov_name_prop.as_ptr() as *const _).to_string_lossy()
                ),
                Err(e) => {
                    error!("Cannot get provider property: {}", NCRYPT_NAME_PROPERTY);
                    Err(CertError::ContextError(e.code().0 as _))
                }
            }
        }
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), CertError> {
        let pin_val = U16CString::from_str(&pin)?;

        let result = unsafe {
            NCryptSetProperty(
                self.handle(),
                NCRYPT_PIN_PROPERTY,
                pin_val.as_ptr() as _,
                pin.len() as u32,
                NCRYPT_FLAGS::default(),
            )
        };

        match result {
            Ok(_) => Ok(()),
            Err(_) => {
                error!("Cannot set pin code");
                Err(CertError::PinError)
            }
        }
    }
}

pub struct CertContext(*const CERT_CONTEXT, Option<NCryptKey>);

unsafe impl Send for CertContext {}
unsafe impl Sync for CertContext {}

impl Drop for CertContext {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

impl Clone for CertContext {
    fn clone(&self) -> Self {
        CertContext(
            unsafe { CertDuplicateCertificateContext(self.0) },
            self.1.clone(),
        )
    }
}

impl CertContext {
    pub fn new(context: *const CERT_CONTEXT) -> Self {
        CertContext(context, None)
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }

    pub fn key(&self) -> Option<NCryptKey> {
        self.1.clone()
    }

    pub fn acquire_key(&mut self, silent: bool) -> Result<NCryptKey, CertError> {
        let mut key = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();
        let mut flags =
            CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_FLAGS(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG);
        if silent {
            flags |= CRYPT_ACQUIRE_SILENT_FLAG;
        }
        unsafe {
            let result = CryptAcquireCertificatePrivateKey(
                self.as_ptr(),
                flags,
                ptr::null_mut(),
                &mut key,
                &mut key_spec,
                ptr::null_mut(),
            )
            .as_bool();
            if !result {
                error!("Cannot acquire certificate private key");
                Err(CertError::ContextError(GetLastError().0))
            } else {
                let retval = NCryptKey::from_handle(NCRYPT_HANDLE(key.0));
                self.1 = Some(retval.clone());
                Ok(retval)
            }
        }
    }

    pub fn get_data(&self) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                (*self.as_ptr()).pbCertEncoded,
                (*self.as_ptr()).cbCertEncoded as usize,
            )
            .into()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertStoreType {
    LocalMachine,
    CurrentUser,
    CurrentService,
}

impl CertStoreType {
    fn as_flags(&self) -> u32 {
        match self {
            CertStoreType::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE_ID,
            CertStoreType::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER_ID,
            CertStoreType::CurrentService => CERT_SYSTEM_STORE_CURRENT_SERVICE_ID,
        }
    }
}

impl FromStr for CertStoreType {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = match s {
            "machine" => CertStoreType::LocalMachine,
            "user" => CertStoreType::CurrentUser,
            "service" => CertStoreType::CurrentService,
            _ => return Err(CertError::InvalidStoreType),
        };
        Ok(result)
    }
}

pub struct CertStore(HCERTSTORE);

unsafe impl Send for CertStore {}
unsafe impl Sync for CertStore {}

impl CertStore {
    pub fn handle(&self) -> HCERTSTORE {
        self.0
    }

    pub fn open(store_type: CertStoreType, store_name: &str) -> Result<CertStore, CertError> {
        let store_name = U16CString::from_str(store_name)?;
        let handle = unsafe {
            CertOpenStore(
                PCSTR(10 as _),
                CERT_QUERY_ENCODING_TYPE::default(),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(store_type.as_flags() | CERT_STORE_OPEN_EXISTING_FLAG.0),
                store_name.as_ptr() as _,
            )
        };
        match handle {
            Ok(handle) => Ok(CertStore(handle)),
            Err(e) => {
                error!("Cannot open certificate store");
                Err(CertError::StoreError(e.code().0 as _))
            }
        }
    }

    pub fn from_pfx(data: &[u8], password: &str) -> Result<CertStore, CertError> {
        unsafe {
            let blob = CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let store = PFXImportCertStore(&blob, password, CRYPT_KEY_FLAGS::default());
            match store {
                Ok(handle) => Ok(CertStore(handle)),
                Err(e) => Err(CertError::StoreError(e.code().0 as _)),
            }
        }
    }

    pub fn find_cert_by_subject_str<S>(&self, subject: S) -> Result<Vec<CertContext>, CertError>
    where
        S: AsRef<str>,
    {
        let mut certs = Vec::new();
        let subject = U16CString::from_str(subject)?;

        let mut cert = ptr::null();

        loop {
            cert = unsafe {
                CertFindCertificateInStore(
                    self.0,
                    MY_ENCODING_TYPE.0,
                    0,
                    CERT_FIND_SUBJECT_STR,
                    subject.as_ptr() as _,
                    cert,
                )
            };
            if cert.is_null() {
                break;
            } else {
                // increase refcount because it will be released by next call to CertFindCertificateInStore
                let cert = unsafe { CertDuplicateCertificateContext(cert) };
                certs.push(CertContext::new(cert))
            }
        }
        Ok(certs)
    }

    pub fn add_cert_context(&self, cert: &CertContext) -> Result<(), CertError> {
        unsafe {
            let result = CertAddCertificateContextToStore(
                self.0,
                cert.as_ptr(),
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                ptr::null_mut(),
            )
            .as_bool();
            if !result {
                error!("Cannot add certificate context");
                Err(CertError::StoreError(GetLastError().0))
            } else {
                Ok(())
            }
        }
    }

    pub fn add_cert(&self, cert: &[u8], key: Option<NCryptKey>) -> Result<(), CertError> {
        let mut context: *mut CERT_CONTEXT = ptr::null_mut();

        unsafe {
            let result = CertAddEncodedCertificateToStore(
                self.0,
                MY_ENCODING_TYPE.0,
                cert.as_ptr(),
                cert.len() as u32,
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                &mut context,
            )
            .as_bool();

            if !result {
                error!("Cannot add certificate");
                return Err(CertError::StoreError(GetLastError().0));
            }

            let mut context = CertContext::new(context);
            context.1 = key.clone();

            if let Some(key) = key {
                let result = CertSetCertificateContextProperty(
                    context.as_ptr(),
                    CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                    0,
                    key.handle().0 as _,
                )
                .as_bool();

                if !result {
                    error!("Cannot set certificate private key");
                    return Err(CertError::StoreError(GetLastError().0));
                }
            }
        }
        Ok(())
    }
}

impl Drop for CertStore {
    fn drop(&mut self) {
        unsafe { CertCloseStore(self.0, 0) };
    }
}
