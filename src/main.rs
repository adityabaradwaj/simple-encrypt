use simple_encrypt::{decrypt_bytes, encrypt_bytes};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use rpassword::read_password;
use std::fs;
use std::path::PathBuf;
use rand::{rngs::OsRng, TryRngCore};
use std::io::{self, Write};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new AES-GCM-256 encryption key
    GenerateKey {
        /// File to save the generated key to
        #[arg(long)]
        output: PathBuf,
    },
    /// Encrypt a file using AES-GCM-256
    Encrypt {
        /// File to encrypt
        #[arg(long)]
        input: PathBuf,
        /// Where to save the encrypted file
        #[arg(long)]
        output: PathBuf,
    },
    /// Decrypt a file using AES-GCM-256
    Decrypt {
        /// File to decrypt
        #[arg(long)]
        input: PathBuf,
        /// Where to save the decrypted file
        #[arg(long)]
        output: PathBuf,
    },
}

/// File Encryption/Decryption Tool
/// 
/// This tool encrypts and decrypts files using AES-GCM-256 encryption.
/// 
/// # Building
/// ```bash
/// cargo build --bin encrypt_decrypt_file
/// ```
/// 
/// # Examples
/// 
/// ## Generating a new encryption key:
/// ```bash
/// cargo run --bin encrypt_decrypt_file generate-key --output my_key.bin
/// ```
/// This will generate a 32-byte key and save it to 'my_key.bin' in base64 format
/// 
/// ## Encrypting a file:
/// ```bash
/// cargo run --bin encrypt_decrypt_file encrypt --input secrets.env --output secrets.env.enc
/// ```
/// You will be prompted to enter the base64-encoded encryption key
/// 
/// ## Decrypting a file:
/// ```bash
/// cargo run --bin encrypt_decrypt_file decrypt --input secrets.env.enc --output secrets.env.dec
/// ```
/// Enter the same base64-encoded key used for encryption
/// 
/// # Important Notes:
/// - The same encryption key must be used for encryption and decryption
/// - The encrypted file will be in binary format
/// - There's no way to recover encrypted data if you lose the encryption key
/// - Uses AES-GCM-256 encryption standard
/// - Keys must be base64-encoded 32-byte values
/// 
/// # Command Line Options:
/// - `-i, --input`: Input file path
/// - `-o, --output`: Output file path
/// - `-d, --decrypt`: Enable decrypt mode (default is encrypt mode)
/// - `-g, --generate-key`: Generate a new AES-GCM-256 key and save it to the specified file
/// 
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::GenerateKey { output } => {
            let mut key = [0u8; 32];
            OsRng.try_fill_bytes(&mut key)?;
            
            // Encode the key in base64
            let encoded_key = STANDARD.encode(key);
            fs::write(&output, encoded_key)?;
            
            println!("Generated new 32-byte AES-GCM-256 key and saved to {:?}", output);
            println!("Keep this key safe - you'll need it to decrypt files!");
        }

        Commands::Encrypt { input, output } => {
            let file_content = fs::read(&input)?;
            
            // Flush stdout to ensure prompt is displayed
            print!("Enter base64-encoded encryption key: ");
            io::stdout().flush()?;
            
            let encoded_key = read_password()?;
            let key = STANDARD.decode(encoded_key.trim())
                .map_err(|_| "Invalid base64-encoded key")?;
            
            if key.len() != 32 {
                return Err("Invalid key length - must be 32 bytes when decoded".into());
            }

            let result = encrypt_bytes(&file_content, &key)?;
            fs::write(&output, result)?;

            println!("Successfully encrypted file from {:?} to {:?}", input, output);
        }

        Commands::Decrypt { input, output } => {
            let file_content = fs::read(&input)?;
            
            // Flush stdout to ensure prompt is displayed
            print!("Enter base64-encoded encryption key: ");
            io::stdout().flush()?;
            
            let encoded_key = read_password()?;
            let key = STANDARD.decode(encoded_key.trim())
                .map_err(|_| "Invalid base64-encoded key")?;
            
            if key.len() != 32 {
                return Err("Invalid key length - must be 32 bytes when decoded".into());
            }

            let result = decrypt_bytes(&file_content, &key)?;
            fs::write(&output, result)?;

            println!("Successfully decrypted file from {:?} to {:?}", input, output);
        }
    }

    Ok(())
}

