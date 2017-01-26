use openssl::ssl::SslStream;
use std::net::TcpStream;
use std::io::{Write, Error};

#[derive(Debug)]
pub enum TCPStreamType {
    Plain(TcpStream),
    SSL(SslStream<TcpStream>),
}

impl Write for TCPStreamType {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.write(buf),
            TCPStreamType::SSL(ref mut stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.flush(),
            TCPStreamType::SSL(ref mut stream) => stream.flush(),
        }
    }
}

impl TCPStreamType {
    pub fn write_string(&mut self, buf: &str) -> Result<usize, Error> {
        self.write(format!("{}\r\n", buf).as_ref())
    }
}
