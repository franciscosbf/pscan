use anyhow::Result;
use clap::{
    arg, crate_authors, crate_name, crate_version, ArgAction, ArgGroup, ArgMatches, Command,
};
use pscan::{
    error::ScanError,
    is_user_sudo, logger, resolver,
    scan::{Ports, ScanType, Scanner, Technique},
};

struct ParsedArgs {
    debug: bool,
    ports: Ports,
    techniques: Vec<Technique>,
    target: String,
}

fn parse_args(matches: ArgMatches) -> Result<ParsedArgs, ScanError> {
    let debug = matches.get_flag("debug");

    let ports = match matches.get_many::<String>("port") {
        Some(rps) => Ports::Selected(
            rps.map(|rp| match rp.parse::<u16>() {
                Ok(p) => Ok(p),
                Err(_) => Err(ScanError::InvalidPort(String::from(rp))),
            })
            .collect::<Result<_, _>>()?,
        ),
        None => Ports::All,
    };

    let techniques = matches
        .get_many::<clap::Id>("techniques")
        .unwrap()
        .map(|rt| {
            let technique = Technique::from(rt.as_str());
            match technique.kind {
                ScanType::Syn if !is_user_sudo() => Err(ScanError::NormalUser),
                _ => Ok(technique),
            }
        })
        .collect::<Result<_, _>>()?;

    let target = matches.get_one::<String>("target").unwrap().to_owned();

    Ok(ParsedArgs {
        debug,
        ports,
        techniques,
        target,
    })
}

fn main() -> Result<()> {
    let arg_matches = Command::new(crate_name!())
        .about(
            "Port scanner capable of inspect TCP and UDP protocols. SYN scan requires sudo user.",
        )
        .version(crate_version!())
        .arg_required_else_help(true)
        .author(crate_authors!())
        .args([
            // Miscellaneous arguments.
            arg!(-d --debug "Turns on debugging information").action(ArgAction::SetTrue),
            arg!(-p --port <PORT> "One or more ports separated by a comma").value_delimiter(','),
            arg!([target] "Address or hostname to scan").required(true),
        ])
        .args([
            // Scan techniques.
            arg!(-t --tcp "TCP scan").action(ArgAction::SetTrue),
            arg!(-u --udp "UDP scan").action(ArgAction::SetTrue),
            arg!(-s --syn "SYN scan").action(ArgAction::SetTrue),
        ])
        .group(
            ArgGroup::new("techniques")
                .args(["tcp", "udp", "syn"])
                .multiple(true)
                .required(true),
        )
        .get_matches();

    // Extract arguments.
    let parsed = parse_args(arg_matches)?;

    // Set debug if desired.
    if parsed.debug {
        logger::init();
    }

    // Parse target.
    let ip = resolver::lookup(&parsed.target)?;

    // Start scanner.
    let result = Scanner::new(ip, parsed.ports, parsed.techniques).start();

    // Show result.
    // TODO:
    println!("{:?}", result);
    let _ = result;

    Ok(())
}
