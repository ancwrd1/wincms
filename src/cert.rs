use std::os::raw::c_void;
use std::{error, ffi::NulError, fmt, mem, ptr, slice, str::FromStr, sync::Arc};

use log::error;
use widestring::{u16cstr, U16CStr, U16CString};
use windows::{
    core::{PCSTR, PCWSTR},
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
    ChainError,
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
            CertError::ChainError => write!(f, "Chain error"),
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

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum SignaturePadding {
    None,
    Pkcs1,
    Pss,
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
            let u16provider = U16CString::from_str_unchecked(provider_name);
            let u16key = U16CString::from_str_unchecked(key_name);
            match NCryptOpenStorageProvider(&mut handle, PCWSTR(u16provider.as_ptr()), 0) {
                Ok(_) => {
                    let mut hkey = NCRYPT_KEY_HANDLE::default();

                    let result = NCryptOpenKey(
                        handle,
                        &mut hkey,
                        PCWSTR(u16key.as_ptr()),
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

    pub fn get_string_property(&self, property: &str) -> Result<String, CertError> {
        let mut result: u32 = 0;
        unsafe {
            let u16property = U16CString::from_str_unchecked(property);
            let rc = NCryptGetProperty(
                self.handle(),
                PCWSTR(u16property.as_ptr()),
                ptr::null_mut(),
                0,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );

            if let Err(e) = rc {
                error!("Cannot get property size: {}", property);
                return Err(CertError::ContextError(e.code().0 as _));
            }
            let mut prop_value = vec![0u8; result as usize];

            let rc = NCryptGetProperty(
                self.handle(),
                PCWSTR(u16property.as_ptr()),
                prop_value.as_mut_ptr(),
                prop_value.len() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );
            if let Err(e) = rc {
                error!("Cannot get property: {}", property);
                return Err(CertError::ContextError(e.code().0 as _));
            }

            Ok(U16CStr::from_ptr_str(prop_value.as_ptr() as _).to_string_lossy())
        }
    }

    pub fn get_name(&self) -> Result<String, CertError> {
        self.get_string_property(NCRYPT_NAME_PROPERTY)
    }

    pub fn get_provider_name(&self) -> Result<String, CertError> {
        let mut prov_handle = NCRYPT_HANDLE::default();
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.handle(),
                PCWSTR(u16cstr!(NCRYPT_PROVIDER_HANDLE_PROPERTY).as_ptr()),
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

            Self::from_handle(prov_handle).get_string_property(NCRYPT_NAME_PROPERTY)
        }
    }

    pub fn get_bits(&self) -> Result<u32, CertError> {
        let mut bits: u32 = 0;
        let mut result: u32 = 0;
        unsafe {
            let rc = NCryptGetProperty(
                self.handle(),
                PCWSTR(u16cstr!(NCRYPT_LENGTH_PROPERTY).as_ptr()),
                &mut bits as *mut _ as _,
                mem::size_of::<u32>() as u32,
                &mut result,
                OBJECT_SECURITY_INFORMATION::default(),
            );

            if let Err(e) = rc {
                error!("Cannot get key property: {}", NCRYPT_LENGTH_PROPERTY);
                return Err(CertError::ContextError(e.code().0 as _));
            }

            Ok(bits)
        }
    }

    pub fn set_pin(&self, pin: &str) -> Result<(), CertError> {
        let pin_val = U16CString::from_str(&pin)?;

        let result = unsafe {
            NCryptSetProperty(
                self.handle(),
                PCWSTR(u16cstr!(NCRYPT_PIN_PROPERTY).as_ptr()),
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

    pub fn get_algorithm_group(&self) -> Result<String, CertError> {
        self.get_string_property(NCRYPT_ALGORITHM_GROUP_PROPERTY)
    }

    pub fn get_algorithm(&self) -> Result<String, CertError> {
        self.get_string_property(NCRYPT_ALGORITHM_PROPERTY)
    }

    pub fn sign_hash(
        &self,
        hash: &[u8],
        hash_alg: &str,
        padding: SignaturePadding,
    ) -> Result<Vec<u8>, CertError> {
        let mut result = 0;
        unsafe {
            let alg_name = U16CString::from_str_unchecked(hash_alg);
            let mut pkcs1 = BCRYPT_PKCS1_PADDING_INFO::default();
            let mut pss = BCRYPT_PSS_PADDING_INFO::default();
            let (info, flag) = match padding {
                SignaturePadding::Pkcs1 => {
                    pkcs1.pszAlgId = PCWSTR(alg_name.as_ptr());
                    (&pkcs1 as *const _ as *const c_void, BCRYPT_PAD_PKCS1)
                }
                SignaturePadding::Pss => {
                    pss.pszAlgId = PCWSTR(alg_name.as_ptr());
                    pss.cbSalt = match hash_alg {
                        "SHA256" => 32,
                        "SHA384" => 48,
                        "SHA512" => 64,
                        _ => 0,
                    };
                    (&pss as *const _ as *const c_void, BCRYPT_PAD_PSS)
                }
                SignaturePadding::None => (ptr::null(), NCRYPT_FLAGS::default()),
            };

            NCryptSignHash(
                NCRYPT_KEY_HANDLE(self.handle().0),
                info,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )
            .map_err(|e| CertError::CngError(e.code().0 as _))?;

            let mut signature = vec![0u8; result as usize];

            NCryptSignHash(
                NCRYPT_KEY_HANDLE(self.handle().0),
                info,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut result,
                NCRYPT_SILENT_FLAG | flag,
            )
            .map_err(|e| CertError::CngError(e.code().0 as _))?;

            Ok(signature)
        }
    }
}

pub struct CertContext {
    context: *const CERT_CONTEXT,
    key: Option<NCryptKey>,
    owned: bool,
}

unsafe impl Send for CertContext {}
unsafe impl Sync for CertContext {}

impl Drop for CertContext {
    fn drop(&mut self) {
        if self.owned {
            unsafe { CertFreeCertificateContext(self.context) };
        }
    }
}

impl Clone for CertContext {
    fn clone(&self) -> Self {
        Self {
            context: unsafe { CertDuplicateCertificateContext(self.context) },
            key: self.key.clone(),
            owned: true,
        }
    }
}

impl CertContext {
    pub fn from_raw(context: *const CERT_CONTEXT) -> Self {
        Self {
            context,
            key: None,
            owned: true,
        }
    }

    pub fn from_raw_borrowed(context: *const CERT_CONTEXT) -> Self {
        Self {
            context,
            key: None,
            owned: false,
        }
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.context
    }

    pub fn key(&self) -> Option<NCryptKey> {
        self.key.clone()
    }

    pub fn acquire_key(&mut self, silent: bool) -> Result<NCryptKey, CertError> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();
        let mut flags = CRYPT_ACQUIRE_FLAGS(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG);
        if silent {
            flags |= CRYPT_ACQUIRE_SILENT_FLAG;
        }
        unsafe {
            let result = CryptAcquireCertificatePrivateKey(
                self.as_ptr(),
                flags,
                ptr::null_mut(),
                &mut handle,
                &mut key_spec,
                ptr::null_mut(),
            )
            .as_bool();
            if !result {
                error!("Cannot acquire certificate private key");
                Err(CertError::ContextError(GetLastError().0))
            } else {
                let key = NCryptKey::from_handle(NCRYPT_HANDLE(handle.0));
                self.key = Some(key.clone());
                Ok(key)
            }
        }
    }

    pub fn as_der(&self) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(
                (*self.as_ptr()).pbCertEncoded,
                (*self.as_ptr()).cbCertEncoded as usize,
            )
            .into()
        }
    }

    pub fn as_chain_der(&self) -> Result<Vec<Vec<u8>>, CertError> {
        unsafe {
            let mut param = CERT_CHAIN_PARA::default();
            param.cbSize = mem::size_of::<CERT_CHAIN_PARA>() as u32;

            let mut context: *mut CERT_CHAIN_CONTEXT = ptr::null_mut();

            let result = CertGetCertificateChain(
                HCERTCHAINENGINE::default(),
                self.context,
                ptr::null(),
                HCERTSTORE::default(),
                &param,
                0,
                ptr::null_mut(),
                &mut context,
            );

            if result.as_bool() {
                let mut chain = vec![];

                if (*context).cChain > 0 {
                    let chain_ptr = *(*context).rgpChain;
                    let elements = slice::from_raw_parts(
                        (*chain_ptr).rgpElement,
                        (*chain_ptr).cElement as usize,
                    );
                    for element in elements {
                        let context = (**element).pCertContext;
                        chain.push(Self::from_raw_borrowed(context).as_der());
                    }
                }

                CertFreeCertificateChain(context);

                Ok(chain)
            } else {
                Err(CertError::ChainError)
            }
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
            CertStoreType::LocalMachine => {
                CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentUser => {
                CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            CertStoreType::CurrentService => {
                CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
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

    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<CertStore, CertError> {
        unsafe {
            let blob = CRYPTOAPI_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as _,
            };

            let u16password = U16CString::from_str_unchecked(password);
            let store = PFXImportCertStore(
                &blob,
                PCWSTR(u16password.as_ptr()),
                CRYPT_KEY_FLAGS::default(),
            );
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
                certs.push(CertContext::from_raw(cert))
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

            let mut context = CertContext::from_raw(context);
            context.key = key.clone();

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
