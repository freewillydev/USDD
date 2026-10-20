use ecx_stress_harness::run_standard_suite;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut seed = 1_u64;
    let mut accounts = 10_000_u32;
    let mut compact = false;
    let mut summary = false;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--seed" => {
                seed = arguments.next().ok_or("--seed requires a value")?.parse()?;
            }
            "--accounts" => {
                accounts = arguments
                    .next()
                    .ok_or("--accounts requires a value")?
                    .parse()?;
            }
            "--compact" => compact = true,
            "--summary" => summary = true,
            "--help" | "-h" => {
                println!("Usage: ecx-stress [--seed N] [--accounts N] [--summary | --compact]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {argument}").into()),
        }
    }

    let reports = run_standard_suite(seed, accounts)?;
    if summary {
        println!(
            "scenario\taccounts\tliquidations\tbad_debt\tuncovered\tinsurance\tsolvent\tledger"
        );
        for report in &reports {
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                report.scenario,
                report.accounts,
                report.total_liquidations,
                report.total_bad_debt_usdd,
                report.uncovered_bad_debt_usdd,
                report.final_insurance_usdd,
                report.solvent,
                report.ledger_conserved
            );
        }
    } else if compact {
        println!("{}", serde_json::to_string(&reports)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }
    Ok(())
}
