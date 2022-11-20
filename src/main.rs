mod client;

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{PathBuf};
use clap::{Parser, Subcommand, ValueEnum};
use ureq::serde_json;
use crate::client::Product;
use ml_progress::progress;

#[derive(Debug, Parser)]
#[command(name = "rebellion")]
#[command(author, version)]
#[command(about = "A tool to download 2000AD comics", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long)]
    email: String,

    #[arg(long)]
    password: String
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum MediaType {
    PDF,
    CBZ
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Lists the available products
    List,

    /// Download
    Download {
        /// Path to place downloads
        #[arg(long)]
        path: PathBuf,

        /// The format to download - defaults to PDF
        #[arg(long)]
        format: Option<MediaType>,

        /// The individual product to download otherwise all available
        #[arg(long)]
        product: Option<String>
    }
}

fn md5_hex(s: &str) -> String {
    let mut md5 = md5_rs::Context::new();
    md5.read(s.as_bytes());
    md5.finish().iter().map(|x| format!("{:02x}", x)).collect::<String>()
}

fn main() {
    let args = Cli::parse();
    let client_id = md5_hex(args.email.as_str());
    let mut client = client::Client::new(client_id);

    client.login(args.email.as_str(), args.password.as_str()).expect("successful login");

    match args.command {
        Commands::List => {
            let entitlements = client.get_entitlements().expect("success");
            println!("{}", entitlements.join("\n"));
        },

        Commands::Download { path, product, format } => {
            let format = format.unwrap_or(MediaType::PDF);

            let manifest_path = path.join(".manifest.json");
            let manifest_path = manifest_path.as_path();
            let mut manifest: Vec<Product> = if manifest_path.exists() {
                let file = File::open(manifest_path).expect("manifest file");
                let reader = BufReader::new(file);

                serde_json::from_reader(reader).expect("successful parse")
            } else {
                Vec::new()
            };

            let mut index = HashSet::new();
            for prod in manifest.iter() {
                index.insert(prod.product_code.clone());
            }

            let to_download = if let Some(product) = product {
                if index.contains(product.as_str()) {
                    manifest.retain(|e| !e.product_code.eq_ignore_ascii_case(product.as_str()));
                }
                client.get_products(&vec![product]).expect("success")
            } else {
                let entitlements = client.get_entitlements().expect("success");

                let mut to_fetch = Vec::new();
                for code in entitlements {
                    if index.contains(code.as_str()) {
                        // do nothing
                    } else {
                        to_fetch.push(code);
                    }
                }

                if to_fetch.is_empty() {
                    println!("No new products available");
                    Vec::new()
                } else {
                    println!("Downloading product details...");
                    let progress = progress!(to_fetch.len()).expect("progress");
                    let mut result = Vec::new();
                    for pcodes in to_fetch.chunks(5) {
                        let mut chunk = client.get_products(&pcodes.to_vec()).expect("success");

                        progress.inc(chunk.len() as u64);
                        result.append(&mut chunk);
                    }

                    progress.finish();
                    result
                }
            };

            if to_download.is_empty() {
                // do nothing
            } else {
                let suffix = match format {
                    MediaType::PDF => "pdf",
                    MediaType::CBZ => "cbz"
                };

                for product in to_download {
                    for med in product.media.iter() {
                        if med.content_type.ends_with(suffix) {
                            let download_url = client.request_medium(med.id).expect("media query success");

                            let download_path = path.join(&med.file_name);
                            let download_path = download_path.as_path();
                            println!("Downloading {} to {}", product.product_code, download_path.display());
                            let progress = progress!(med.file_size).expect("progress");
                            let download = ureq::get(download_url.as_str()).call().expect("successful download");
                            let mut reader = download.into_reader();
                            let mut buf = [0u8; 1024 * 16];

                            let file = File::create(download_path).expect("download file");
                            let mut writer = BufWriter::new(file);

                            while let Ok(count) = reader.read(&mut buf)  {
                                if count == 0 {
                                    break;
                                }
                                progress.inc(count as u64);
                                writer.write(&buf[0..count]).expect("successful write");
                            }
                            progress.finish();
                        }
                    }

                    manifest.push(product);

                    let file = File::create(manifest_path).expect("manifest file");
                    let writer = BufWriter::new(file);
                    serde_json::to_writer(writer, &manifest).expect("successful write");
                }
            }
        }
    }
}
