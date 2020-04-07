use std::{error::Error, fs, path::PathBuf};

use log::debug;
use structopt::StructOpt;

pub mod cms;
pub mod cng;

use cng::*;

#[derive(StructOpt)]
#[structopt(
    about = "CMS encoding utility",
    name = "cmsutil",
    author = "Dmitry Pankratov"
)]
struct AppParams {
    #[structopt(short = "p", long = "pin", help = "Smart card pin")]
    pin: Option<String>,

    #[structopt(short = "q", long = "quiet", help = "Disable Windows CSP UI prompts")]
    silent: bool,

    #[structopt(
        short = "t",
        long = "store-type",
        help = "Certificate store type, one of: machine, user, service"
    )]
    store_type: Option<cng::CertStoreType>,

    #[structopt(short = "i", long = "in", help = "Input file")]
    input_file: PathBuf,

    #[structopt(short = "o", long = "out", help = "Output file")]
    output_file: PathBuf,

    #[structopt(short = "s", long = "signer", help = "Signer certificate ID")]
    signer: String,

    #[structopt(
        index = 1,
        required = true,
        help = "One or more recipient certificate IDs"
    )]
    recipients: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: AppParams = AppParams::from_args();

    env_logger::init();

    let input_file = fs::File::open(&args.input_file)?;
    let mmap = unsafe { memmap::MmapOptions::new().map(&input_file)? };

    let store_type = args.store_type.unwrap_or(CertStoreType::CurrentUser);
    let store = CertStore::open(store_type, "my")?;

    let mut signer = store.find_cert_by_subject_str(&args.signer)?;
    debug!("Acquired signer certificate for {}", args.signer);

    let mut recipients = Vec::new();
    for rcpt in &args.recipients {
        recipients.push(store.find_cert_by_subject_str(rcpt)?);
        debug!("Acquired recipient certificate for {}", rcpt);
    }

    let key = signer.acquire_key(args.silent)?;
    let key_prov = key.get_provider()?;
    let key_name = key.get_name()?;
    debug!("Acquired private key: {}: {}", key_prov, key_name);

    // TESTTEST
    // let raw_cert = signer.get_data();
    // let raw_key = NCryptKey::open(&key_prov, &key_name)?;
    // CertStore::open(CertStoreType::LocalMachine, "my")?.add_cert(&raw_cert, Some(raw_key))?;

    let mut builder = cms::CmsContent::builder()
        .signer(signer)
        .recipients(recipients);

    if let Some(pin) = args.pin {
        builder = builder.password(pin);
    }

    let content = builder.build()?;
    let data = content.sign_and_encrypt(&mmap)?;

    fs::write(args.output_file, &data)?;

    Ok(())
}
