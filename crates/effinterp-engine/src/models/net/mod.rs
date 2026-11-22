//! Network command models and the HTTPie and SFTP extensions to registered models.

mod curl;
mod dns_lookup;
mod http_transfer;
mod httpie;
mod mail;
mod netcat;
mod network_endpoint;
mod sftp;
mod socat;
mod socket_handler;
mod wget;

use super::CommandModel;
use curl::Curl;
pub(crate) use curl::{CurlFlowOutput, curl_flow_info};
use dns_lookup::DnsLookup;
pub(super) use httpie::with_httpie_request_item_files;
use mail::Mail;
use netcat::Netcat;
pub(super) use network_endpoint::parse_network_endpoint_operand;
pub(super) use sftp::with_sftp_transfers;
use socat::Socat;
use wget::Wget;
pub(crate) use wget::wget_flow_info;

/// Register the network command models in resolution order.
pub(super) fn network_models() -> Vec<Box<dyn CommandModel>> {
    vec![
        Box::new(Curl),
        Box::new(Wget),
        Box::new(Netcat),
        Box::new(Socat),
        Box::new(Mail),
        Box::new(DnsLookup),
    ]
}
