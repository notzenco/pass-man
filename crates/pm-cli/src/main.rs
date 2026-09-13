//! `pm` — command-line interface for pass-man vaults.
//!
//! The CLI is the smallest complete client. It exercises the same `pm-core`
//! API the GUI shells use and is useful for scripting, testing, and recovery.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use pm_core::model::{CustomField, ItemBody};
use pm_core::totp::{self, TotpParams};
use pm_core::{entropy_bits, generate, search_items, ItemType, PasswordOptions, Vault};

#[derive(Parser)]
#[command(
    name = "pm",
    version,
    about = "pass-man command-line vault client",
    long_about = None,
)]
struct Cli {
    /// Path to the vault file.
    #[arg(
        short,
        long,
        env = "PM_VAULT",
        default_value = "personal.pmvault",
        global = true
    )]
    vault: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// List items, or search with an optional query.
    List {
        /// Filter by substring across title, username, url, and tags.
        query: Option<String>,
    },
    /// Show one item as JSON.
    Show { id: String },
    /// Add a login item.
    Add {
        title: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        /// Generate a strong password instead of supplying one.
        #[arg(short = 'g', long, conflicts_with = "password")]
        generate: bool,
        /// Length used with --generate.
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Login URL.
        #[arg(long = "url")]
        url: Option<String>,
        /// TOTP secret or otpauth:// URI.
        #[arg(long = "totp")]
        totp: Option<String>,
        #[arg(short = 'n', long)]
        notes: Option<String>,
        /// Extra field as `name=value`, repeatable.
        #[arg(short, long = "field", value_parser = parse_kv)]
        fields: Vec<(String, String)>,
    },
    /// Generate a password without storing it.
    Gen {
        #[arg(short, long, default_value_t = 20)]
        length: usize,
        /// Exclude lowercase letters.
        #[arg(long)]
        no_lowercase: bool,
        /// Exclude uppercase letters.
        #[arg(long)]
        no_uppercase: bool,
        /// Exclude digits.
        #[arg(long)]
        no_digits: bool,
        /// Exclude symbols.
        #[arg(long)]
        no_symbols: bool,
        /// Omit easily confused characters such as l, 1, O, and 0.
        #[arg(short, long)]
        no_ambiguous: bool,
        /// Print only the password, for piping.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show the current TOTP code for an item.
    Totp {
        /// Item id, or a title substring if it matches exactly one item.
        id: String,
        /// Print only the code, for piping.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Add a free-form secure note.
    AddNote {
        title: String,
        /// Note contents.
        #[arg(short, long)]
        notes: Option<String>,
    },
    /// Delete an item (writes a tombstone).
    Delete { id: String },
    /// Change the master password.
    Passwd,
    /// Print the vault id and format metadata as JSON.
    Info,
}

fn parse_kv(raw: &str) -> std::result::Result<(String, String), String> {
    raw.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected name=value, got `{raw}`"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { force } => init(&cli.vault, force),
        Command::List { query } => list(&cli.vault, query.as_deref()),
        Command::Show { id } => {
            let vault = unlock(&cli.vault)?;
            let item = vault.get_item(&id)?;
            println!("{}", serde_json::to_string_pretty(&item)?);
            Ok(())
        }
        Command::Add {
            title,
            username,
            password,
            generate: should_generate,
            length,
            url,
            totp,
            notes,
            fields,
        } => {
            let password = if should_generate {
                Some(generate_password(length, false)?)
            } else {
                password
            };
            add(
                &cli.vault,
                ItemType::Login,
                ItemBody {
                    username,
                    password,
                    url,
                    totp_secret: totp,
                    notes,
                    fields: fields
                        .into_iter()
                        .map(|(name, value)| CustomField {
                            name,
                            value,
                            hidden: false,
                        })
                        .collect(),
                    ..ItemBody::new(title)
                },
            )
        }
        Command::Gen {
            length,
            no_lowercase,
            no_uppercase,
            no_digits,
            no_symbols,
            no_ambiguous,
            quiet,
        } => gen(
            length,
            no_lowercase,
            no_uppercase,
            no_digits,
            no_symbols,
            no_ambiguous,
            quiet,
        ),
        Command::Totp { id, quiet } => totp_code(&cli.vault, &id, quiet),
        Command::AddNote { title, notes } => add(
            &cli.vault,
            ItemType::Note,
            ItemBody {
                notes,
                ..ItemBody::new(title)
            },
        ),
        Command::Delete { id } => {
            let vault = unlock(&cli.vault)?;
            vault.delete_item(&id)?;
            println!("deleted {id}");
            Ok(())
        }
        Command::Passwd => passwd(&cli.vault),
        Command::Info => info(&cli.vault),
    }
}

fn init(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    if force && path.exists() {
        std::fs::remove_file(path).context("removing existing vault")?;
    }
    let password = prompt_new_password()?;
    let vault = Vault::create(path, &password).context("creating vault")?;
    println!("created {} ({})", path.display(), vault.vault_id());
    Ok(())
}

fn prompt_secret(prompt: &str) -> Result<String> {
    use std::io::{BufRead, IsTerminal};

    // When stdin is piped (scripts, tests, CI) there is no TTY to read from, so
    // fall back to reading a line directly. Interactive use still hides input.
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn unlock(path: &std::path::Path) -> Result<Vault> {
    if !path.exists() {
        bail!("vault {} not found; run `pm init` first", path.display());
    }
    let password = prompt_secret("Master password: ")?;
    Vault::unlock(path, &password).context("unlocking vault")
}

fn list(path: &std::path::Path, query: Option<&str>) -> Result<()> {
    let vault = unlock(path)?;
    let items = vault.list_items()?;
    let results = search_items(&items, query.unwrap_or(""));
    if results.is_empty() {
        println!("no items");
        return Ok(());
    }
    for item in results {
        let username = item.body.username.as_deref().unwrap_or("");
        println!(
            "{}  {:<10}  {:<28}  {}",
            item.meta.id,
            item.meta.item_type.as_str(),
            item.body.title,
            username,
        );
    }
    Ok(())
}

fn add(path: &std::path::Path, item_type: ItemType, body: ItemBody) -> Result<()> {
    let vault = unlock(path)?;
    let item = vault.create_item(item_type, body)?;
    println!("added {} ({})", item.meta.id, item.body.title);
    Ok(())
}

fn passwd(path: &std::path::Path) -> Result<()> {
    let vault = unlock(path)?;
    let current = prompt_secret("Current password: ")?;
    let new = prompt_new_password()?;
    vault
        .change_password(&current, &new)
        .context("changing master password")?;
    println!("master password changed");
    Ok(())
}

fn info(path: &std::path::Path) -> Result<()> {
    let vault = unlock(path)?;
    let header = vault.header();
    let out = serde_json::json!({
        "vault_id": header.vault_id.to_string(),
        "format_version": header.format_version,
        "kdf_algorithm": header.kdf_algorithm,
        "kdf_m_cost": header.kdf_params.m_cost,
        "kdf_t_cost": header.kdf_params.t_cost,
        "kdf_p_cost": header.kdf_params.p_cost,
        "created_at": header.created_at,
        "updated_at": header.updated_at,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn prompt_new_password() -> Result<String> {
    let first = prompt_secret("New master password: ")?;
    let second = prompt_secret("Confirm master password: ")?;
    if first != second {
        bail!("passwords do not match");
    }
    if first.len() < 8 {
        bail!("master password must be at least 8 characters");
    }
    Ok(first)
}

fn build_password_options(length: usize, no_ambiguous: bool) -> PasswordOptions {
    PasswordOptions {
        length,
        exclude_ambiguous: no_ambiguous,
        ..PasswordOptions::default()
    }
}

fn generate_password(length: usize, no_ambiguous: bool) -> Result<String> {
    generate(&build_password_options(length, no_ambiguous)).context("generating password")
}

#[allow(clippy::too_many_arguments)]
fn gen(
    length: usize,
    no_lowercase: bool,
    no_uppercase: bool,
    no_digits: bool,
    no_symbols: bool,
    no_ambiguous: bool,
    quiet: bool,
) -> Result<()> {
    let opts = PasswordOptions {
        length,
        lowercase: !no_lowercase,
        uppercase: !no_uppercase,
        digits: !no_digits,
        symbols: !no_symbols,
        exclude_ambiguous: no_ambiguous,
    };
    let password = generate(&opts).context("generating password")?;
    if quiet {
        println!("{password}");
    } else {
        println!("{password}");
        eprintln!("~{:.1} bits of entropy", entropy_bits(&opts));
    }
    Ok(())
}

/// Resolve an item by exact id, or by a unique title substring.
fn resolve_item(vault: &Vault, id_or_title: &str) -> Result<pm_core::model::Item> {
    if let Ok(item) = vault.get_item(id_or_title) {
        return Ok(item);
    }
    let items = vault.list_items()?;
    let needle = id_or_title.to_lowercase();
    let matches: Vec<_> = items
        .into_iter()
        .filter(|i| i.body.title.to_lowercase().contains(&needle))
        .collect();
    match matches.len() {
        0 => bail!("no item matches `{id_or_title}`"),
        1 => Ok(matches.into_iter().next().expect("length checked")),
        n => bail!("{n} items match `{id_or_title}`; use the full id"),
    }
}

fn totp_code(path: &std::path::Path, id_or_title: &str, quiet: bool) -> Result<()> {
    let vault = unlock(path)?;
    let item = resolve_item(&vault, id_or_title)?;
    let stored = item
        .body
        .totp_secret
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("item `{}` has no TOTP secret", item.body.title))?;

    let (secret, params) = parse_stored_totp(stored)?;
    let now = pm_core::format::now_unix().max(0) as u64;
    let code = totp::code_at(&secret, now, params)?;
    if quiet {
        println!("{code}");
    } else {
        let remaining = totp::seconds_remaining(params.period, now);
        println!("{code}  (valid for {remaining}s)");
    }
    Ok(())
}

/// Accept either a raw base32 secret or a full `otpauth://` URI.
fn parse_stored_totp(stored: &str) -> Result<(Vec<u8>, TotpParams)> {
    if stored.starts_with("otpauth://") {
        let (secret, params, _) = totp::parse_otpauth_uri(stored)?;
        Ok((secret, params))
    } else {
        Ok((totp::decode_base32(stored)?, TotpParams::default()))
    }
}
