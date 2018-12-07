use openssl::ssl::SslStream;
use std::io::{BufRead, BufReader, Error, Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub enum TCPStreamType {
    Plain(BufReader<TcpStream>),
    SSL(BufReader<SslStream<TcpStream>>),
}

impl Write for TCPStreamType {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.get_mut().write(buf),
            TCPStreamType::SSL(ref mut stream) => stream.get_mut().write(buf),
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.get_mut().flush(),
            TCPStreamType::SSL(ref mut stream) => stream.get_mut().flush(),
        }
    }
}

impl Read for TCPStreamType {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.read(buf),
            TCPStreamType::SSL(ref mut stream) => stream.read(buf),
        }
    }
}

impl TCPStreamType {
    pub fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize, Error> {
        match *self {
            TCPStreamType::Plain(ref mut stream) => stream.read_until(byte, buf),
            TCPStreamType::SSL(ref mut stream) => stream.read_until(byte, buf),
        }
    }

    pub fn write_string(&mut self, buf: &str) -> Result<usize, Error> {
        self.write(format!("{}\r\n", buf).as_ref())
    }

    pub fn shutdown(&mut self) {
        if let TCPStreamType::Plain(ref mut stream) = *self {
            trace!("Closing TCP Stream");
            stream
                .get_mut()
                .shutdown(::std::net::Shutdown::Both)
                .unwrap();
        } else if let TCPStreamType::SSL(ref mut stream) = *self {
            trace!("Closing SSL Stream");
            stream.get_mut().shutdown().unwrap();
        }
    }
}
