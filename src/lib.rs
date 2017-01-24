#[cfg(feature = "serde_derive")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "serde_derive")]
include!("serde_types.in.rs");

#[cfg(feature = "serde_codegen")]
include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));

/******************************************************************/

#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
extern crate openssl;

use std::io::BufReader;
use openssl::ssl::{SslMethod, SslConnectorBuilder, SslStream};
use std::net::TcpStream;
use std::path::PathBuf;

pub mod errors {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            SslStack(::openssl::error::ErrorStack);
            SslHandshake(::openssl::ssl::HandshakeError<::std::net::TcpStream>);
        }
    }
}
use errors::*;

#[derive(PartialEq)]
#[derive(Debug)]
enum POP3State {
    BEGIN,
    AUTHORIZATION,
    TRANSACTION,
    UPDATE,
}

enum TCPReader {
    Plain(BufReader<TcpStream>),
    SSL(BufReader<SslStream<TcpStream>>),
}

enum TCPStreamType {
    Plain(TcpStream),
    SSL(SslStream<TcpStream>),
}

pub struct POP3Connection {
    account: AccountConfig,
    stream: TCPStreamType,
    reader: TCPReader,
    state: POP3State,
    timestamp: String,
}

impl POP3Connection {
    pub fn new(account: AccountConfig) -> Result<POP3Connection> {
        trace!("Initiate POP3 Connection");
        let tcp_stream = TcpStream::connect((&account.host[..], account.port))?;
        let (stream, reader) = match account.auth.as_ref() {
            "Plain" => {
                debug!("Creating a Plain TCP Connection");
                let stream = TCPStreamType::Plain(tcp_stream.try_clone()?);
                let reader = TCPReader::Plain(BufReader::new(tcp_stream));
                (stream, reader)
            }
            "SSL" => {
                debug!("Creating a SSL Connection");
                let connector = SslConnectorBuilder::new(SslMethod::tls())?.build();
                let stream = TCPStreamType::SSL(connector.connect(&account.host[..], tcp_stream.try_clone()?)?);
                let reader = TCPReader::SSL(BufReader::new(connector.clone()
                    .connect(&account.host[..], tcp_stream)?));
                (stream, reader)
            }
            _ => return Err("Unknown auth type".into()),
        };

        let ctx = POP3Connection {
            account: account,
            stream: stream,
            reader: reader,
            state: POP3State::BEGIN,
            timestamp: String::new(),
        };
        trace!("Connection Established");
        debug!("POP3State::{:?}", ctx.state);
        Ok(ctx)
    }
}
