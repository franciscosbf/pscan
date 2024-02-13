use std::process;

use error::ScanError;

#[cfg(not(target_os = "linux"))]
std::compile_error!("linux is the only target os that was tested");

pub mod error;
pub mod logger;
pub mod resolver;
pub mod scan;

pub fn is_user_sudo() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub fn abort(error: ScanError) -> ! {
    eprintln!("Internal Error: {}", error);
    process::exit(1);
}
