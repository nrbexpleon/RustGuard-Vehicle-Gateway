use std::env;
use std::fs;
use std::process::ExitCode;

use rustguard::replay::{parse_trace, replay};
use rustguard::{Gateway, Policy};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rustguard error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = env::args().collect();
    let policy_path = value_after(&arguments, "--policy").unwrap_or("policies/host.policy");
    let trace_path = value_after(&arguments, "--trace").unwrap_or("traces/demo.trace");
    let policy_text = fs::read_to_string(policy_path)
        .map_err(|error| format!("cannot read policy {policy_path}: {error}"))?;
    let trace_text = fs::read_to_string(trace_path)
        .map_err(|error| format!("cannot read trace {trace_path}: {error}"))?;
    let policy = Policy::parse(&policy_text)?;
    let messages = parse_trace(&trace_text)?;
    let mut gateway = Gateway::new(policy);
    let result = replay(&mut gateway, &messages);
    println!("{{");
    println!("  \"policyVersion\": \"{}\",", escape(&gateway.policy().version));
    println!("  \"messages\": {},", messages.len());
    println!("  \"allowed\": {},", result.allowed);
    println!("  \"audited\": {},", result.audited);
    println!("  \"dropped\": {},", result.dropped);
    println!("  \"rateLimited\": {},", result.rate_limited);
    println!("  \"quarantined\": {},", result.quarantined);
    println!("  \"auditValid\": {},", gateway.audit().verify());
    println!("  \"auditHead\": \"{}\"", gateway.audit().records().last().map_or("", |r| &r.hash));
    println!("}}");
    Ok(())
}

fn value_after<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|value| value == name)
        .and_then(|index| arguments.get(index + 1))
        .map(String::as_str)
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
