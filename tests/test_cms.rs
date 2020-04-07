use wincms::{cms::CmsContent, cng::CertStore};

const PFX: &[u8] = include_bytes!("wincms.p12");
const PASSWORD: &str = "changeit";
const SIGNER: &str = "wincms";
const RECIPIENT: &str = "wincms";
const MESSAGE: &str = "Security is our business";

#[test]
fn test_sign_encrypt() {
    let store = CertStore::from_pfx(PFX, PASSWORD).expect("Cannot open cert store");

    let mut signer = store
        .find_cert_by_subject_str(SIGNER)
        .expect("No signer certificate");

    let _ = signer.acquire_key(true).expect("No signer private key");

    let rcpt = store
        .find_cert_by_subject_str(RECIPIENT)
        .expect("No recipient certificate");

    let content = CmsContent::builder()
        .signer(signer)
        .recipients(vec![rcpt])
        .build()
        .expect("Content build failed");

    let encrypted = content
        .sign_and_encrypt(MESSAGE.as_bytes())
        .expect("Sign and encrypt failed");

    assert!(encrypted.len() > MESSAGE.len());

    let decrypted =
        CmsContent::decrypt_and_verify(&store, &encrypted).expect("Decrypt and verify failed");

    assert_eq!(MESSAGE.as_bytes(), decrypted.as_slice());
}
