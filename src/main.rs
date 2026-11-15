fn main() {
    match whose::run() {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("whose: {err}");
            std::process::exit(1);
        }
    }
}
