use wincms::{cert::CertStore, cms::CmsContent};

const PFX: &[u8] = include_bytes!("wincms.p12");
const PASSWORD: &str = "changeit";
const SIGNER: &str = "wincms";
const RECIPIENT: &str = "wincms";
const MESSAGE: &str = "Security is our business";

#[test]
fn test_sign_encrypt() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let mut signers = store
        .find_cert_by_subject_str(SIGNER)
        .expect("No signer certificate");

    let _ = signers[0].acquire_key(true).expect("No signer private key");

    let mut recipients = store
        .find_cert_by_subject_str(RECIPIENT)
        .expect("No recipient certificate");

    let _ = recipients[0]
        .acquire_key(true)
        .expect("No recipient private key");

    let content = CmsContent::builder()
        .signer(signers.remove(0))
        .recipients(recipients)
        .build();

    let encrypted = content
        .encode(MESSAGE.as_bytes())
        .expect("Sign and encrypt failed");

    assert!(encrypted.len() > MESSAGE.len());

    let decrypted =
        CmsContent::decode(&store, &encrypted, true).expect("Decrypt and verify failed");

    assert_eq!(MESSAGE.as_bytes(), decrypted.as_slice());
}

#[test]
fn test_encrypt_only() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let mut recipients = store
        .find_cert_by_subject_str(RECIPIENT)
        .expect("No recipient certificate");

    let _ = recipients[0]
        .acquire_key(true)
        .expect("No recipient private key");

    let content = CmsContent::builder().recipients(recipients).build();

    let encrypted = content
        .encode(MESSAGE.as_bytes())
        .expect("Sign and encrypt failed");

    assert!(encrypted.len() > MESSAGE.len());

    let decrypted =
        CmsContent::decode(&store, &encrypted, false).expect("Decrypt and verify failed");

    assert_eq!(MESSAGE.as_bytes(), decrypted.as_slice());
}
