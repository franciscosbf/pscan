use log::LevelFilter;

struct DebugLogger;

static LOGGER: DebugLogger = DebugLogger;

impl log::Log for DebugLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        // This method wont be called.
        unreachable!()
    }

    fn log(&self, record: &log::Record) {
        println!("[Debug] {}", record.args());
    }

    fn flush(&self) {}
}

pub fn init() {
    // Result is ignored since we guarantee that init is called only one time.
    let _ = log::set_logger(&LOGGER).map(|_| log::set_max_level(LevelFilter::Debug));
}
