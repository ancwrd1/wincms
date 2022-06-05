use sha2::digest::FixedOutput;
use sha2::Digest;
use wincms::cert::{CertStore, SignaturePadding};

const PFX: &[u8] = include_bytes!("wincms.p12");
const PASSWORD: &str = "changeit";
const SIGNER: &str = "wincms";
const MESSAGE: &str = "Security is our business";

#[test]
fn test_raw_sign() {
    let store = CertStore::from_pkcs12(PFX, PASSWORD).expect("Cannot open cert store");

    let mut signer = store
        .find_cert_by_subject_str(SIGNER)
        .expect("No signer certificate")
        .into_iter()
        .next()
        .unwrap();

    println!("Acquiring chain");
    let chain = signer.as_chain_der().unwrap();
    println!("Chain size: {}", chain.len());

    signer.acquire_key(true).expect("No signer private key");
    let key = signer.key().unwrap();
    println!("alg group: {}", key.get_algorithm_group().unwrap());
    println!("alg name: {}", key.get_algorithm().unwrap());

    let mut hash = sha2::Sha256::default();
    hash.update(MESSAGE.as_bytes());
    let output = hash.finalize_fixed();

    println!("Hash size: {}", output.len());
    let alg = "SHA256";

    let pkcs1_1 = key
        .sign_hash(output.as_ref(), alg, SignaturePadding::Pkcs1)
        .unwrap();

    let pkcs1_2 = key
        .sign_hash(output.as_ref(), alg, SignaturePadding::Pkcs1)
        .unwrap();

    assert_eq!(pkcs1_1, pkcs1_2);

    let pss1 = key
        .sign_hash(output.as_ref(), alg, SignaturePadding::Pss)
        .unwrap();

    let pss2 = key
        .sign_hash(output.as_ref(), alg, SignaturePadding::Pss)
        .unwrap();

    assert_ne!(pss1, pss2);
}
