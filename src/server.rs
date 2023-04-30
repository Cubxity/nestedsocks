use std::env::var;
use std::io;
use fast_socks5::{consts};
use fast_socks5::client::{Config, Socks5Stream};
use fast_socks5::util::target_addr::{read_address, TargetAddr};
use futures::future;
use futures::future::Either;
use log::{debug};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use thiserror::Error;
use tokio::net::TcpStream;

macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("malformed request")]
    MalformedRequest,
    #[error("unsupported authentication")]
    UnsupportedAuthentication,
    #[error("unsupported socks version: {0}")]
    UnsupportedSocksVersion(u8),
    #[error("unsupported command")]
    UnsupportedCommand,
    #[error("bad request")]
    BadRequest,
    #[error("upstream error")]
    UpstreamError,
    #[error("io error")]
    IO(#[from] io::Error),
}

type Result<T> = std::result::Result<T, ProxyError>;

pub async fn process(mut client: TcpStream) -> Result<()> {
    let [version, auth_count] =
        read_exact!(client, [0u8; 2]).map_err(|_| ProxyError::MalformedRequest)?;

    debug!("handshake received, version: {}, nauth: {}", version, auth_count);

    if version != consts::SOCKS5_VERSION {
        return Err(ProxyError::UnsupportedSocksVersion(version));
    }

    // Auth handshake
    let mut auth_methods = vec![0u8; auth_count as usize];
    client.read_exact(&mut auth_methods).await.map_err(|_| ProxyError::MalformedRequest)?;
    if !auth_methods.contains(&consts::SOCKS5_AUTH_METHOD_PASSWORD) {
        client.write(&[
            consts::SOCKS5_VERSION,
            consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE
        ]).await.map_err(Into::<ProxyError>::into)?;

        return Err(ProxyError::UnsupportedAuthentication);
    }

    client.write(&[
        consts::SOCKS5_VERSION,
        consts::SOCKS5_AUTH_METHOD_PASSWORD
    ]).await.map_err(Into::<ProxyError>::into)?;

    let [_, user_len] =
        read_exact!(client, [0u8; 2]).map_err(|_| ProxyError::MalformedRequest)?;
    let mut username = vec![0u8; user_len as usize];
    client.read_exact(&mut username).await.map_err(|_| ProxyError::MalformedRequest)?;
    let username = String::from_utf8(username).map_err(|_| ProxyError::MalformedRequest)?;

    let [pass_len] =
        read_exact!(client, [0u8; 1]).map_err(|_| ProxyError::MalformedRequest)?;
    let mut password = vec![0u8; pass_len as usize];
    client.read_exact(&mut password).await.map_err(|_| ProxyError::MalformedRequest)?;
    let password = String::from_utf8(password).map_err(|_| ProxyError::MalformedRequest)?;

    if let Ok(pass) = var("PROXY_PASS") {
        if password != pass {
            client.write(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE]).await.map_err(Into::<ProxyError>::into)?;
            return Err(ProxyError::BadRequest);
        }
    }

    client.write(&[1, consts::SOCKS5_REPLY_SUCCEEDED]).await.map_err(Into::<ProxyError>::into)?;

    let [version, cmd, rsv, address_type] =
        read_exact!(client, [0u8; 4]).map_err(|_| ProxyError::MalformedRequest)?;

    debug!("request received, version: {}, cmd: {}, rsv: {}, address_type: {}", version, cmd, rsv, address_type);

    if version != consts::SOCKS5_VERSION {
        return Err(ProxyError::UnsupportedSocksVersion(version));
    }

    if cmd != consts::SOCKS5_CMD_TCP_CONNECT {
        return Err(ProxyError::UnsupportedCommand);
    }

    let target_addr = read_address(&mut client, address_type)
        .await.map_err(|_| ProxyError::MalformedRequest)?;

    let (host, port) = match target_addr {
        TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
        TargetAddr::Domain(host, port) => (host, port)
    };

    let reply = vec![
        consts::SOCKS5_VERSION,
        consts::SOCKS5_REPLY_SUCCEEDED,
        0x00, // reserved
        address_type,
        127, 0, 0, 1, 0, 0, // 127.0.0.1:0
    ];
    client.write_all(&reply).await.map_err(Into::<ProxyError>::into)?;

    debug!("connecting to upstream {}", username);

    let config = Config::default();
    let remote = Socks5Stream::connect(username, host, port, config).await
        .map_err(|_| ProxyError::UpstreamError)?;

    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut remote_reader, mut remote_writer) = remote.get_socket().into_split();

    let c2r = copy(&mut client_reader, &mut remote_writer);
    let r2c = copy(&mut remote_reader, &mut client_writer);

    tokio::pin!(c2r);
    tokio::pin!(r2c);

    match future::select(c2r, r2c).await {
        Either::Left((Ok(..), ..)) | Either::Right((Ok(..), ..)) => Ok(()),
        Either::Left((Err(err), ..)) | Either::Right((Err(err), ..)) => Err(err.into())
    }
}
