use openssl::ssl::SslStream;
use std::net::TcpStream;
use std::io::{Read, BufRead, BufReader, Error};

pub enum TCPReader {
    Plain(BufReader<TcpStream>),
    SSL(BufReader<SslStream<TcpStream>>),
}

impl Read for TCPReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match *self {
            TCPReader::Plain(ref mut stream) => stream.read(buf),
            TCPReader::SSL(ref mut stream) => stream.read(buf),
        }
    }
}

impl TCPReader {
    pub fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> Result<usize, Error> {
        match *self {
            TCPReader::Plain(ref mut stream) => stream.read_until(byte, buf),
            TCPReader::SSL(ref mut stream) => stream.read_until(byte, buf),
        }
    }
}
