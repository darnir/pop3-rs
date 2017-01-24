use openssl::ssl::SslStream;
use std::net::TcpStream;

pub enum TCPStreamType {
    Plain(TcpStream),
    SSL(SslStream<TcpStream>),
}

