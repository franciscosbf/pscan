pub fn is_sudo() -> bool {
    unsafe { libc::getuid() == 0 }
}
