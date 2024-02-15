use std::time::Duration;

use once_cell::sync::Lazy;
use pnet::datalink::{channel, Channel, Config, DataLinkReceiver, DataLinkSender};

use crate::{abort, error::ScanError};

use super::interface;

static CHANNEL_CONFIG: Lazy<Config> = Lazy::new(|| Config {
    read_timeout: Some(Duration::from_millis(1500)),
    write_timeout: Some(Duration::from_millis(1500)),
    ..Default::default()
});

pub fn link() -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let interface = &interface::DEFAULT;
    let config = *CHANNEL_CONFIG;

    match channel(interface.raw(), config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => unreachable!(),
        Err(e) => abort(ScanError::DatalinkChannelFailed(e)),
    }
}
