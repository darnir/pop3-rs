use openssl::ssl::SslStream;
use std::net::TcpStream;
use std::io::BufReader;

pub enum TCPReader {
    Plain(BufReader<TcpStream>),
    SSL(BufReader<SslStream<TcpStream>>),
}
