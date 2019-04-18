//! # POP3-RS
//!
//! A POP3 Client Library written in Rust
//!
//! ## Example
//! ```rust
//! extern crate pop3_rs;
//!
//! use pop3_rs::{AccountConfig, POP3Connection};
//!
//! fn main() {
//!     let config = AccountConfig {
//!         host: String::from("pop.gmail.com"),
//!         port: 995,
//!         username: String::from("username"),
//!         password: String::from("password"),
//!         auth: String::from("SSL"),
//!     };
//!
//!     let mut connection = POP3Connection::new(config).unwrap();
//!     connection.login().unwrap();
//!     let stat = connection.stat().unwrap();
//!     println!("{:?}", stat);
//!     let list = connection.list(Some(2)).unwrap();
//!     println!("{:?}", list);
//!     let msg1 = connection.retr(1).unwrap();
//!     println!("{:?}", msg1);
//!     connection.quit().unwrap();
//! }
//! ```

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate md5;
extern crate openssl;
extern crate regex;

use openssl::ssl::{SslConnector, SslMethod};
use regex::Regex;
use std::io::BufReader;
use std::net::TcpStream;

pub mod errors {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            SslStack(::openssl::error::ErrorStack);
            SslHandshake(::openssl::ssl::HandshakeError<::std::net::TcpStream>);
            UTF8Error(::std::string::FromUtf8Error);
            RegexError(::regex::Error);
        }
    }
}
use errors::*;

pub mod pop3result;
mod pop3resultimpl;
mod tcpstream;
mod utils;
use pop3result::{POP3List, POP3Retr, POP3Stat, POP3Uidl};
use tcpstream::TCPStreamType;

#[derive(Debug)]
pub struct AccountConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub auth: String,
}

#[derive(PartialEq, Debug)]
enum POP3State {
    BEGIN,
    AUTHORIZATION,
    TRANSACTION,
    // UPDATE, // State unused in a Client
    END,
}

pub struct POP3Connection {
    account: AccountConfig,
    stream: TCPStreamType,
    state: POP3State,
    timestamp: String,
}

impl POP3Connection {
    pub fn new(account: AccountConfig) -> Result<POP3Connection> {
        trace!("Initiate POP3 Connection");
        let tcp_stream = TcpStream::connect((&account.host[..], account.port))?;
        let stream = match account.auth.as_ref() {
            "Plain" => {
                debug!("Creating a Plain TCP Connection");
                TCPStreamType::Plain(BufReader::new(tcp_stream.try_clone()?))
            }
            "SSL" => {
                debug!("Creating a SSL Connection");
                let connector = SslConnector::builder(SslMethod::tls())?.build();
                TCPStreamType::SSL(BufReader::new(
                    connector.connect(&account.host[..], tcp_stream)?,
                ))
            }
            _ => return Err("Unknown auth type".into()),
        };

        let mut ctx = POP3Connection {
            account: account,
            stream: stream,
            state: POP3State::BEGIN,
            timestamp: String::new(),
        };
        trace!("Connection Established");
        debug!("POP3State::{:?}", ctx.state);
        ctx.read_greeting()?;
        ctx.state = POP3State::AUTHORIZATION;
        debug!("POP3State::{:?}", ctx.state);
        Ok(ctx)
    }

    pub fn login(&mut self) -> Result<()> {
        assert!(self.state == POP3State::AUTHORIZATION);
        trace!("Attempting to Login");
        let username = &self.account.username.clone();
        let auth_user_cmd = self.send_command("USER", Some(username));
        let auth_response = match auth_user_cmd {
            Ok(_) => {
                debug!("Plain USER/PASS authentication");
                let password = &self.account.password.clone();
                self.send_command("PASS", Some(password))
            }
            Err(_) => {
                debug!("Authenticating using APOP");
                let digest = utils::get_apop_digest(&self.timestamp, &self.account.password);
                let apop_param = &format!("{} {}", self.account.username, digest);
                self.send_command("APOP", Some(apop_param))
            }
        };

        // Switch the current state to TRANSACTION on a successful authentication
        match auth_response {
            Ok(_) => {
                self.state = POP3State::TRANSACTION;
                debug!("POP3State::{:?}", self.state);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn stat(&mut self) -> Result<POP3Stat> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: STAT");
        self.send_command("STAT", None)
            .map(|msg| POP3Stat::parse(&msg[0]))
    }

    pub fn list(&mut self, msgnum: Option<u32>) -> Result<POP3List> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: LIST");
        let msgnumval;
        let msgnum = match msgnum {
            Some(x) => {
                msgnumval = x.to_string();
                Some(msgnumval.as_ref())
            }
            None => None,
        };
        self.send_command("LIST", msgnum)
            .map(|msg| POP3List::parse(&msg))
    }

    pub fn retr(&mut self, msgnum: u32) -> Result<POP3Retr> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: RETR");
        self.send_command("RETR", Some(&msgnum.to_string()))
            .map(|msg| POP3Retr::parse(&msg))
    }

    pub fn dele(&mut self, msgnum: u32) -> Result<()> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: DELE");
        let _ = self.send_command("DELE", Some(&msgnum.to_string()))?;
        Ok(())
    }

    pub fn noop(&mut self) -> Result<()> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: NOOP");
        let _ = self.send_command("NOOP", None)?;
        Ok(())
    }

    pub fn rset(&mut self) -> Result<()> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: RSET");
        let _ = self.send_command("RSET", None)?;
        Ok(())
    }

    pub fn quit(&mut self) -> Result<()> {
        assert!(self.state == POP3State::AUTHORIZATION || self.state == POP3State::TRANSACTION);
        trace!("Cmd: QUIT");
        let _ = self.send_command("QUIT", None)?;
        self.state = POP3State::END;
        debug!("POP3State::{:?}", self.state);
        self.stream.shutdown();
        Ok(())
    }

    pub fn top(&mut self, msgnum: u32, lines: u32) -> Result<POP3Retr> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: TOP {} {}", msgnum, lines);
        let args = &format!("{} {}", msgnum, lines);
        self.send_command("TOP", Some(args))
            .map(|msg| POP3Retr::parse(&msg))
    }

    pub fn uidl(&mut self, msgnum: Option<u32>) -> Result<POP3Uidl> {
        assert!(self.state == POP3State::TRANSACTION);
        trace!("Cmd: UIDL");
        let msgnumval;
        let msgnum = match msgnum {
            Some(x) => {
                msgnumval = x.to_string();
                Some(msgnumval.as_ref())
            }
            None => None,
        };
        self.send_command("UIDL", msgnum)
            .map(|msg| POP3Uidl::parse(&msg))
    }

    fn read_greeting(&mut self) -> Result<()> {
        trace!("Reading Greeting from Server");
        let greeting = &self.read_response(false)?[0];
        let re = Regex::new(r"(<.*>)\r\n$")?;
        for cap in re.captures_iter(greeting) {
            self.timestamp = cap[1].to_string();
        }
        Ok(())
    }

    fn send_command(&mut self, command: &str, param: Option<&str>) -> Result<Vec<String>> {
        // Identify if the command is a multiline command
        let is_multiline = match command {
            "LIST" | "UIDL" => param.is_none(),
            "RETR" => true,
            _ => false,
        };

        // Create the actual POP3 Command by appending the parameters
        let command = match param {
            Some(x) => format!("{} {}", command, x),
            None => command.to_string(),
        };

        info!("C: {}", command);
        self.stream.write_string(&command)?;

        self.read_response(is_multiline)
    }

    fn read_response(&mut self, is_multiline: bool) -> Result<Vec<String>> {
        lazy_static! {
            static ref RESPONSE: Regex =
                Regex::new(r"^(?P<status>\+OK|-ERR) (?P<statustext>.*)").unwrap();
        }
        const LF: u8 = 0x0a;
        let mut response_data: Vec<String> = Vec::new();
        let mut buff = Vec::new();
        let mut complete;

        //First read the status line
        self.stream.read_until(LF, &mut buff)?;
        response_data.push(String::from_utf8(buff.clone())?);
        info!("S: {}", response_data[0]);

        // Test if the response is positive. Else exit early.
        let status_line = response_data[0].clone();
        let response_groups = RESPONSE.captures(&status_line).unwrap();
        match response_groups
            .name("status")
            .ok_or("Regex match failed")?
            .as_str()
        {
            "+OK" => complete = false,
            "-ERR" => return Err(response_groups["statustext"].to_string().into()),
            _ => return Err("Un-parseable Response".into()),
        };

        while !complete && is_multiline {
            buff.clear();
            self.stream.read_until(LF, &mut buff)?;
            let line = unsafe { String::from_utf8_unchecked(buff.clone()) };
            if line == ".\r\n" {
                complete = true;
            } else {
                // Don't add the final .CRLF to the response.
                // It's useless for us
                response_data.push(line);
            }
        }
        Ok(response_data)
    }
}
