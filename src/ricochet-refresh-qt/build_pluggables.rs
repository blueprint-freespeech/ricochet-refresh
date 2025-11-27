// standard crates
use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

// extern crates
use anyhow::{bail, Context, Error};
use regex::Regex;

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();

    let pluggables_path = &args[1];
    let pluggables_path = PathBuf::from_str(pluggables_path)?;
    use serde_json::Value;
    let pt_config_json = if args.len() == 3 {
        let pt_config_path = &args[2];
        let pt_config_path = PathBuf::from_str(pt_config_path)?;
        let pt_config_json = std::fs::read_to_string(pt_config_path.as_path())?;
        pt_config_json.replace("${pt_path}", "")
    } else {
        let pt_config_json = r#"
            {
              "recommendedDefault" : "",
              "pluggableTransports" : {},
              "bridges" : {}
            }"#.to_string();
        pt_config_json
    };
    let pt_config_json = Value::from_str(pt_config_json.as_str())?;

    let mut pluggables: Vec<u8> = Default::default();
    writeln!(pluggables, "#pragma once")?;
    writeln!(pluggables, "// Warning! This file is auto-generated from pt_config.json in the tor-expert-bundle")?;
    writeln!(pluggables ,"// See CMakeLists.txt in this directory for details")?;
    writeln!(pluggables)?;
    writeln!(pluggables, "// recommended bridge type")?;

    if let Value::Object(mut key_values) = pt_config_json {
        // read our recommendedDefault
        let recommended_bridge_type = if let Value::String(s) = key_values.remove("recommendedDefault").context("")? {
            s
        } else {
            unreachable!();
        };

        writeln!(pluggables, "const QString recommendedBridgeType = \"{recommended_bridge_type}\";")?;
        writeln!(pluggables)?;
        writeln!(pluggables, "// pt_config")?;
        writeln!(pluggables, "struct pt_config {{")?;
        writeln!(pluggables, "    std::string binary_name;")?;
        writeln!(pluggables, "    std::vector<std::string> transports;")?;
        writeln!(pluggables, "    std::vector<std::string> options;")?;
        writeln!(pluggables, "}};")?;
        writeln!(pluggables, "const std::vector<pt_config> pluggableTransportConfigs = {{")?;

        let mut supported_transports: BTreeSet<String> = Default::default();

        match key_values.remove("pluggableTransports").context("missing \"pluggableTransports\" object")? {
            Value::Object(key_values) => {
                let client_transport_plugin_pattern = Regex::new(r"(?m)^ClientTransportPlugin (?<transports>[a-zA-Z_][a-zA-Z0-9_]*(,[a-zA-Z_][a-zA-Z0-9_]*)*) exec (?<binary>[^ ]*)(?<options>( [^ ^\n]+)*)$")?;

                for (key, value) in key_values {
                    let value = value.as_str().context("\"pluggableTransports\" members must be type String")?;

                    let caps = client_transport_plugin_pattern.captures(value).context(format!("\"pluggableTransports.{key}\" must be type String"))?;
                    let transports = caps.name("transports").unwrap().as_str();
                    let transports: Vec<&str> = transports.split(',').collect();


                    for transport in &transports {
                        if !supported_transports.insert(transport.to_string()) {
                            bail!("multiple entries in \"pluggableTransports\" claim to support \"{transport}\" transport");
                        }
                    }

                    let transports: Vec<String> = transports.iter().map(|transport| format!("\"{transport}\"")).collect();
                    let transports = transports.join(", ");

                    let binary = caps.name("binary").unwrap().as_str();

                    let options = caps.name("options").unwrap().as_str().trim();
                    let options: String = if options.is_empty() {
                        Default::default()
                    } else {
                        let options: Vec<String> = options.split(' ').map(|option| format!("\"{option}\"")).collect();
                        options.join(", ")
                    };

                    writeln!(pluggables, "    {{ \"{binary}\", {{ {transports} }}, {{ {options} }} }},")?;
                }
            },
            value => bail!("unexpected value for \"pluggableTransports\": {value}"),
        };
        writeln!(pluggables, "}};")?;
        writeln!(pluggables)?;
        writeln!(pluggables, "// supported transports")?;
        let supported_transports: Vec<String> = supported_transports.iter().map(|transport| format!("    \"{transport}\",\n")).collect();
        let supported_transports = supported_transports.join("");
        writeln!(pluggables, "const std::set<std::string> supportedTransports = {{\n{supported_transports}}};")?;

        writeln!(pluggables)?;
        writeln!(pluggables, "// bridge lines")?;
        writeln!(pluggables, "const QMap<QString, std::vector<std::string>> defaultBridges = {{")?;
        match key_values.remove("bridges").context("missing \"bridges\" object")? {
            Value::Object(key_values) => {
                for (key, value) in key_values {
                    let bridge_type = key.as_str();

                    let bridge_lines = value.as_array().unwrap();
                    let bridge_lines: Vec<String> = bridge_lines.iter().map(|value| value.as_str().unwrap().to_string() ).collect();

                    for bridge_line in &bridge_lines {
                        let transport = bridge_line.split(' ').next().unwrap();
                        if !supported_transports.contains(transport) {
                            bail!("bridge line \"{bridge_line}\" requires unsupported transport");
                        }
                    }

                    let bridge_lines: Vec<String> = bridge_lines.iter().map(|value| format!("\"{value}\"")).collect();
                    let bridge_lines = bridge_lines.join(",\n        ");

                    writeln!(pluggables, "    {{ \"{bridge_type}\", {{\n        {bridge_lines}\n    }}}},")?;
                }
            },
            value => bail!("unexpected value for \"bridges\": {value}"),
        };
        writeln!(pluggables, "}};")?;
    }

    std::fs::write(pluggables_path, pluggables.as_slice())?;
    Ok(())
}