use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use lightcast::catalog::Catalog;
use lightcast::collectors;
use lightcast::model::Severity;
use lightcast::render;
use lightcast::report::{self, ScanOptions};

/// Inventory the AI services, agents, MCP servers, skills, extensions and keys on this machine.
/// Read-only. Makes no network calls. Never reads cookie values, conversation content or secret values.
#[derive(Parser)]
#[command(name = "lightcast", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Also write the full report as JSON to this file ("-" for stdout, which replaces the terminal report).
    #[arg(long, value_name = "FILE")]
    json: Option<PathBuf>,

    /// Also write a self-contained HTML report.
    #[arg(long, value_name = "FILE")]
    html: Option<PathBuf>,

    /// Also write a counts-only share card (SVG).
    #[arg(long, value_name = "FILE")]
    card: Option<PathBuf>,

    /// Run only these collectors (comma-separated): browser, mcp, agents, skills, ide, cli, keys.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,

    /// Also scan a project directory's committed agent configs (repeatable).
    #[arg(long, value_name = "DIR")]
    project: Vec<PathBuf>,

    /// Drop dates and per-profile/per-project detail, for reports shared outside the team.
    #[arg(long)]
    paranoid: bool,

    /// Opt-in network use: resolve destination hosts whose country is unknown through the system
    /// DNS resolver and geolocate the answers. Off by default; without it the scan makes no network calls.
    #[arg(long)]
    resolve: bool,

    /// Print the hostname (otherwise only its hash is kept).
    #[arg(long)]
    show_hostname: bool,

    /// Omit the one-paragraph product footer.
    #[arg(long)]
    no_footer: bool,

    /// Colour in the terminal report: auto (a terminal that supports it, and NO_COLOR unset), always, never.
    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,

    /// List every finding with its evidence.
    #[arg(long, short)]
    verbose: bool,

    /// Exit 1 when any finding's worst capability is at or above this severity (critical, high, medium, low).
    #[arg(long, value_name = "SEVERITY", default_value = "critical")]
    fail_on: String,

    /// Scan this directory as the home directory (testing and forensics on a mounted profile).
    #[arg(long, hide = true)]
    home: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// ANSI colour needs virtual-terminal processing on Windows consoles (conhost does not enable it for
/// programs by default). Returns false when the console refuses, so the caller prints plain text.
#[cfg(windows)]
fn enable_ansi() -> bool {
    type Handle = *mut core::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    // SAFETY: documented Win32 calls on this process's own stdout handle; `mode` outlives the call.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h as isize == -1 {
            return false;
        }
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 || SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi() -> bool {
    true
}

fn use_color(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Never => false,
        // Even when forced, a Windows console that cannot interpret ANSI would show raw escapes.
        ColorChoice::Always => enable_ansi() || !std::io::stdout().is_terminal(),
        ColorChoice::Auto => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() && enable_ansi(),
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect the bundled catalog.
    Catalog {
        #[command(subcommand)]
        action: CatalogCmd,
    },
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// Print the bundled catalog's version and row counts.
    Show,
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).filter(|p| p.is_dir())
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let catalog = Catalog::embedded()?;

    if let Some(Cmd::Catalog { action: CatalogCmd::Show }) = &cli.cmd {
        let f = &catalog.file;
        println!("catalog {} (sha256 {})", f.version, f.sha256);
        println!("  web services:   {}", f.web_services.len());
        println!("  provider hosts: {}", f.provider_hosts.len());
        println!("  fingerprints:   {}", f.fingerprints.len());
        println!("  AI CLIs:        {}", f.tools.ai_cli.len());
        println!("  IDE extensions: {}", f.tools.ide_extensions.len());
        println!("  key names:      {}", f.tools.key_names.len());
        println!("  MCP packages:   {}", f.tools.mcp_packages.len());
        return Ok(ExitCode::SUCCESS);
    }

    for o in &cli.only {
        if !collectors::ALL.contains(&o.as_str()) {
            bail!("unknown collector '{o}' (choose from {})", collectors::ALL.join(", "));
        }
    }
    let fail_on = Severity::parse(&cli.fail_on).with_context(|| format!("--fail-on must be critical, high, medium or low, not '{}'", cli.fail_on))?;
    let home = match &cli.home {
        Some(h) => h.clone(),
        None => home_dir().context("could not determine the home directory")?,
    };
    let mut opts = ScanOptions::for_home(home);
    opts.projects = cli.project.iter().map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())).collect();
    opts.only = cli.only.clone();
    opts.paranoid = cli.paranoid;
    opts.show_hostname = cli.show_hostname;
    opts.resolve = cli.resolve;

    let report = report::scan(&catalog, &opts);
    let footer = !cli.no_footer;

    let json_to_stdout = cli.json.as_deref().is_some_and(|p| p.as_os_str() == "-");
    if json_to_stdout {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let color = use_color(cli.color);
        print!("{}", render::terminal::render(&report, color, footer, cli.verbose));
    }
    if let Some(p) = cli.json.as_ref().filter(|_| !json_to_stdout) {
        std::fs::write(p, serde_json::to_string_pretty(&report)? + "\n").with_context(|| format!("writing {}", p.display()))?;
        eprintln!("wrote {}", p.display());
    }
    if let Some(p) = &cli.html {
        std::fs::write(p, render::html::render(&report, footer)).with_context(|| format!("writing {}", p.display()))?;
        eprintln!("wrote {}", p.display());
    }
    if let Some(p) = &cli.card {
        std::fs::write(p, render::card::render(&report)).with_context(|| format!("writing {}", p.display()))?;
        eprintln!("wrote {}", p.display());
    }
    Ok(if report::exceeds(&report, fail_on) { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn main() -> ExitCode {
    match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("lightcast: {e:#}");
            ExitCode::from(2)
        }
    }
}
