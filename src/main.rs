use anyhow::Result;
use clap::{
    arg, crate_authors, crate_name, crate_version, ArgAction, ArgGroup, ArgMatches, Command,
};
use pad::PadStr;
use pscan::{
    error::ScanError,
    is_user_sudo, logger, resolver,
    scan::{PortsToScan, ScanResult, ScanType, Scanner, Technique},
};

struct ParsedArgs {
    debug: bool,
    ports: PortsToScan,
    techniques: Vec<Technique>,
    target: String,
}

fn parse_args(matches: ArgMatches) -> Result<ParsedArgs, ScanError> {
    let debug = matches.get_flag("debug");

    let ports = match matches.get_many::<String>("port") {
        Some(rps) => PortsToScan::Selected(
            rps.map(|rp| match rp.parse::<u16>() {
                Ok(p) => Ok(p),
                Err(_) => Err(ScanError::InvalidPort(String::from(rp))),
            })
            .collect::<Result<_, _>>()?,
        ),
        None => PortsToScan::All,
    };

    let techniques = matches
        .get_many::<clap::Id>("techniques")
        .unwrap()
        .map(|rt| {
            let technique = Technique::from(rt.as_str());
            match technique.kind {
                ScanType::Syn if !is_user_sudo() => Err(ScanError::NormalUserRequired),
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

fn print_results(result: ScanResult) {
    let mut out = format!("Scan Duration: {:.4}s\n\n", result.elapsed.as_secs_f32());
    if result.ports.is_empty() {
        out.push_str("Didn't find any open port.\n");
    } else {
        out.push_str("Port    State      Scan Method\n");

        result.ports.iter().for_each(|pr| {
            out.push_str(&format!(
                "{:<8}{}{}\n",
                pr.port,
                format!("{}", pr.state).pad_to_width(11),
                pr.kind,
            ))
        });
    }

    print!("{}", out);
}

fn main() -> Result<()> {
    let arg_matches = Command::new(crate_name!())
        .about(
            "Port scanner capable of inspecting the TCP protocol.\n\
            SYN scan requires sudo user.",
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
            arg!(-s --syn "SYN scan").action(ArgAction::SetTrue),
        ])
        .group(
            ArgGroup::new("techniques")
                .args(["tcp", "syn"])
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
    print_results(result);

    Ok(())
}
