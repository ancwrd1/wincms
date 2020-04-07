use std::{error, ffi::NulError, fmt, mem, ptr, rc::Rc, str::FromStr};

use log::error;
use widestring::{U16CStr, U16CString};
use winapi::{
    shared::winerror::ERROR_SUCCESS,
    um::{
        errhandlingapi::GetLastError,
        ncrypt::{
            NCryptFreeObject, NCryptOpenStorageProvider, NCryptSetProperty, NCRYPT_HANDLE,
            SECURITY_STATUS,
        },
        wincrypt::{
            CertAddCertificateContextToStore, CertAddEncodedCertificateToStore, CertCloseStore,
            CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore,
            CertSetCertificateContextProperty, CryptAcquireCertificatePrivateKey,
            PFXImportCertStore, CERT_FIND_SUBJECT_STR, CERT_NCRYPT_KEY_HANDLE_PROP_ID,
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, CERT_STORE_OPEN_EXISTING_FLAG,
            CERT_STORE_PROV_SYSTEM, CERT_SYSTEM_STORE_CURRENT_SERVICE,
            CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
            CRYPT_ACQUIRE_CACHE_FLAG, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            CRYPT_ACQUIRE_SILENT_FLAG, CRYPT_DATA_BLOB, HCERTSTORE, PCCERT_CONTEXT,
            PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        },
    },
};

extern "system" {
    fn NCryptOpenKey(
        hprov: NCRYPT_HANDLE,
        hkey: *mut NCRYPT_HANDLE,
        key_name: *const u16,
        key_spec: u32,
        flags: u32,
    ) -> SECURITY_STATUS;

    fn NCryptGetProperty(
        hobject: NCRYPT_HANDLE,
        prop: *const u16,
        output: *mut u8,
        output_size: u32,
        result: *mut u32,
        flags: u32,
    ) -> SECURITY_STATUS;
}

pub const MY_ENCODING_TYPE: u32 = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
pub const NCRYPT_NAME_PROPERTY: &str = "Name";
pub const NCRYPT_PIN_PROPERTY: &str = "SmartCardPin";
pub const NCRYPT_PROVIDER_HANDLE_PROPERTY: &str = "Provider Handle";

#[derive(Debug, Clone, PartialEq)]
pub enum CertError {
    StoreError(u32),
    ContextError(u32),
    CngError(u32),
    NameError,
    NotFound,
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
            CertError::NotFound => write!(f, "Certificate not found in the certificate store"),
            CertError::InvalidStoreType => write!(f, "Invalid certificate store type"),
            CertError::PinError => write!(f, "PIN error"),
        }
    }
}

impl From<widestring::NulError<u16>> for CertError {
    fn from(_: widestring::NulError<u16>) -> Self {
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
        unsafe { NCryptFreeObject(self.0) };
    }
}

#[derive(Clone)]
pub struct NCryptKey(Rc<InnerKey>);

impl NCryptKey {
    pub fn new(handle: NCRYPT_HANDLE) -> NCryptKey {
        NCryptKey(Rc::new(InnerKey(handle)))
    }

    pub fn as_ptr(&self) -> NCRYPT_HANDLE {
        (self.0).0
    }

    pub fn open(provider_name: &str, key_name: &str) -> Result<NCryptKey, CertError> {
        let mut handle: NCRYPT_HANDLE = 0;
        let prov_name = U16CString::from_str(provider_name)?;

        unsafe {
            let result = NCryptOpenStorageProvider(&mut handle, prov_name.as_ptr(), 0) as u32;

            if result == ERROR_SUCCESS {
                let mut hkey: NCRYPT_HANDLE = 0;
                let key_name = U16CString::from_str(key_name)?;

                let result = NCryptOpenKey(handle, &mut hkey, key_name.as_ptr(), 0, 0) as u32;

                NCryptFreeObject(handle);

                if result == ERROR_SUCCESS {
                    Ok(NCryptKey::new(hkey))
                } else {
                    error!("Cannot open key: {}", key_name.to_string_lossy());
                    Err(CertError::CngError(result))
                }
            } else {
                error!(
                    "Cannot open storage provider: {}",
                    prov_name.to_string_lossy()
                );
                Err(CertError::CngError(result))
            }
        }
    }

    pub fn get_name(&self) -> Result<String, CertError> {
        let name = U16CString::from_str(NCRYPT_NAME_PROPERTY)?;
        let mut key_name_prop = vec![0u8; 1024];
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.as_ptr(),
                name.as_ptr(),
                key_name_prop.as_mut_ptr(),
                key_name_prop.len() as u32,
                &mut result,
                0,
            ) as u32;
            if rc != ERROR_SUCCESS {
                error!("Cannot get key property: {}", NCRYPT_NAME_PROPERTY);
                return Err(CertError::ContextError(rc));
            }
            Ok(U16CStr::from_ptr_str(key_name_prop.as_ptr() as *const _).to_string_lossy())
        }
    }

    pub fn get_provider(&self) -> Result<String, CertError> {
        let handle_str = U16CString::from_str(NCRYPT_PROVIDER_HANDLE_PROPERTY)?;
        let mut prov_handle: NCRYPT_HANDLE = 0;
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.as_ptr(),
                handle_str.as_ptr(),
                &mut prov_handle as *mut _ as *mut _,
                mem::size_of::<NCRYPT_HANDLE>() as u32,
                &mut result,
                0,
            ) as u32;

            if rc != ERROR_SUCCESS {
                error!(
                    "Cannot get key property: {}",
                    NCRYPT_PROVIDER_HANDLE_PROPERTY
                );
                return Err(CertError::ContextError(rc));
            }

            let name_str = U16CString::from_str(NCRYPT_NAME_PROPERTY)?;
            let mut prov_name_prop = vec![0u8; 1024];

            let rc = NCryptGetProperty(
                prov_handle,
                name_str.as_ptr(),
                prov_name_prop.as_mut_ptr(),
                prov_name_prop.len() as u32,
                &mut result,
                0,
            ) as u32;

            NCryptFreeObject(prov_handle);

            if rc != ERROR_SUCCESS {
                error!("Cannot get provider property: {}", NCRYPT_NAME_PROPERTY);
                Err(CertError::ContextError(rc))
            } else {
                Ok(U16CStr::from_ptr_str(prov_name_prop.as_ptr() as *const _).to_string_lossy())
            }
        }
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), CertError> {
        let pin_prop = U16CString::from_str(NCRYPT_PIN_PROPERTY)?;
        let pin_val = U16CString::from_str(&pin)?;

        let result = unsafe {
            NCryptSetProperty(
                self.as_ptr(),
                pin_prop.as_ptr(),
                pin_val.as_ptr() as *mut _,
                pin.len() as u32,
                0,
            ) as u32
        };

        if result != ERROR_SUCCESS {
            error!("Cannot set pin code");
            Err(CertError::PinError)
        } else {
            Ok(())
        }
    }
}

struct InnerContext(PCCERT_CONTEXT);

impl Drop for InnerContext {
    fn drop(&mut self) {
        unsafe { CertFreeCertificateContext(self.0) };
    }
}

#[derive(Clone)]
pub struct CertContext(Rc<InnerContext>, Option<NCryptKey>);

impl CertContext {
    pub fn new(context: PCCERT_CONTEXT) -> CertContext {
        CertContext(Rc::new(InnerContext(context)), None)
    }
    pub fn as_ptr(&self) -> PCCERT_CONTEXT {
        (self.0).0
    }

    pub fn key(&self) -> Option<NCryptKey> {
        self.1.clone()
    }

    pub fn acquire_key(&mut self, silent: bool) -> Result<NCryptKey, CertError> {
        let mut key: NCRYPT_HANDLE = 0;
        let mut key_spec: u32 = 0;
        let mut flags = CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
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
            ) != 0;
            if !result {
                error!("Cannot acquire certificate private key");
                Err(CertError::ContextError(GetLastError()))
            } else {
                let retval = NCryptKey::new(key);
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
    fn to_flags(&self) -> u32 {
        match self {
            CertStoreType::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
            CertStoreType::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            CertStoreType::CurrentService => CERT_SYSTEM_STORE_CURRENT_SERVICE,
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

impl CertStore {
    pub fn as_ptr(&self) -> HCERTSTORE {
        self.0
    }

    pub fn open(store_type: CertStoreType, store_name: &str) -> Result<CertStore, CertError> {
        let store_name = U16CString::from_str(store_name)?;
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM,
                0,
                0,
                store_type.to_flags() | CERT_STORE_OPEN_EXISTING_FLAG,
                store_name.as_ptr() as *const _,
            )
        };
        if handle.is_null() {
            error!("Cannot open certificate store");
            Err(CertError::StoreError(unsafe { GetLastError() }))
        } else {
            Ok(CertStore(handle))
        }
    }

    pub fn from_pfx(data: &[u8], password: &str) -> Result<CertStore, CertError> {
        unsafe {
            let mut blob = CRYPT_DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *const _ as *mut _,
            };
            let password = U16CString::from_str(password)?;

            let store = PFXImportCertStore(&mut blob, password.as_ptr(), 0);
            if store.is_null() {
                Err(CertError::StoreError(GetLastError()))
            } else {
                Ok(CertStore(store))
            }
        }
    }

    pub fn find_cert_by_subject_str<S>(&self, subject: S) -> Result<CertContext, CertError>
    where
        S: AsRef<str>,
    {
        let subject = U16CString::from_str(subject)?;
        let cert = unsafe {
            CertFindCertificateInStore(
                self.0,
                MY_ENCODING_TYPE,
                0,
                CERT_FIND_SUBJECT_STR,
                subject.as_ptr() as *const _,
                ptr::null(),
            )
        };
        if cert.is_null() {
            Err(CertError::NotFound)
        } else {
            Ok(CertContext::new(cert))
        }
    }

    pub fn add_cert_context(&self, cert: &CertContext) -> Result<(), CertError> {
        unsafe {
            let result = CertAddCertificateContextToStore(
                self.0,
                cert.as_ptr(),
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                ptr::null_mut(),
            ) != 0;
            if !result {
                error!("Cannot add certificate context");
                Err(CertError::StoreError(GetLastError()))
            } else {
                Ok(())
            }
        }
    }

    pub fn add_cert(&self, cert: &[u8], key: Option<NCryptKey>) -> Result<(), CertError> {
        let mut context: PCCERT_CONTEXT = ptr::null_mut();

        unsafe {
            let result = CertAddEncodedCertificateToStore(
                self.0,
                MY_ENCODING_TYPE,
                cert.as_ptr(),
                cert.len() as u32,
                CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES,
                &mut context,
            ) != 0;

            if !result {
                error!("Cannot add certificate");
                return Err(CertError::StoreError(GetLastError()));
            }

            let mut context = CertContext::new(context);
            context.1 = key.clone();

            if let Some(key) = key {
                let result = CertSetCertificateContextProperty(
                    context.as_ptr(),
                    CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                    0,
                    key.as_ptr() as *const _,
                ) != 0;

                if !result {
                    error!("Cannot set certificate private key");
                    return Err(CertError::StoreError(GetLastError()));
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
