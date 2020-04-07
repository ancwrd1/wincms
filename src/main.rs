use std::{error::Error, fs, path::PathBuf};

use structopt::StructOpt;

pub mod cms;
pub mod cng;

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

    let mut builder = cms::CmsContent::builder()
        .silent(args.silent)
        .signer(args.signer)
        .recipients(args.recipients);

    if let Some(pin) = args.pin {
        builder = builder.password(pin);
    }

    if let Some(store_type) = args.store_type {
        builder = builder.cert_store_type(store_type);
    }

    let content = builder.build()?;
    let data = content.sign_and_encrypt(&mmap)?;

    fs::write(args.output_file, &data)?;

    Ok(())
}
