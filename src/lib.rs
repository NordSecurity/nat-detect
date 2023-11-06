use crate::NatType::{
    FullCone, OpenInternet, PortRestrictedCone, RestrictedCone, Symmetric, SymmetricUdpFirewall,
    Unknown,
};
use bytecodec::{DecodeExt, EncodeExt};
use log::{debug, info};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use stun_codec_blazh::{
    rfc3489::attributes::ChangedAddress,
    rfc5389::{
        attributes::{MappedAddress, UnknownAttributes},
        methods,
    },
    rfc5780::attributes::{ChangeRequest, OtherAddress},
    Attribute, Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
};
use tokio::net::UdpSocket;

type IoResult<T> = std::io::Result<T>;

pub const TIMEOUT: Duration = Duration::from_millis(1000);
pub const STUN_RETRY_COUNT: usize = 2;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum NatType {
    /// UDP is always blocked.
    UdpBlocked,

    /// No NAT, public IP, no firewall.
    OpenInternet,

    /// No NAT, public IP, but symmetric UDP firewall.
    SymmetricUdpFirewall,

    /// A full cone NAT is one where all requests from the same internal IP address and port are
    /// mapped to the same external IP address and port. Furthermore, any external host can send
    /// a packet to the internal host, by sending a packet to the mapped external address.
    FullCone,

    /// A restricted cone NAT is one where all requests from the same internal IP address and
    /// port are mapped to the same external IP address and port. Unlike a full cone NAT, an external
    /// host (with IP address X) can send a packet to the internal host only if the internal host
    /// had previously sent a packet to IP address X.
    RestrictedCone,

    /// A port restricted cone NAT is like a restricted cone NAT, but the restriction
    /// includes port numbers. Specifically, an external host can send a packet, with source IP
    /// address X and source port P, to the internal host only if the internal host had previously
    /// sent a packet to IP address X and port P.
    PortRestrictedCone,

    /// A symmetric NAT is one where all requests from the same internal IP address and port,
    /// to a specific destination IP address and port, are mapped to the same external IP address and
    /// port.  If the same host sends a packet with the same source address and port, but to
    /// a different destination, a different mapping is used. Furthermore, only the external host that
    /// receives a packet can send a UDP packet back to the internal host.
    Symmetric,

    /// Unknown
    Unknown,
}

impl NatType {
    pub fn weight(&self) -> usize {
        match self {
            NatType::UdpBlocked => 1,
            OpenInternet => 7,
            SymmetricUdpFirewall => 2,
            FullCone => 6,
            RestrictedCone => 5,
            PortRestrictedCone => 4,
            Symmetric => 3,
            NatType::Unknown => 0,
        }
    }
}

/*
                In test I, the client sends a STUN Binding Request to a server, without any flags set in the
                CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute. This causes the server
                to send the response back to the address and port that the request came from.

                In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
                from the CHANGE-REQUEST attribute set.

                In test III, the client sends a Binding Request with only the "change port" flag set.

                                    +--------+
                                    |  Test  |
                                    |   I    |
                                    +--------+
                                         |
                                         |
                                         V
                                        /\              /\
                                     N /  \ Y          /  \ Y             +--------+
                      UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
                      Blocked         \ ?  /          \Same/              |   II   |
                                       \  /            \? /               +--------+
                                        \/              \/                    |
                                                         | N                  |
                                                         |                    V
                                                         V                    /\
                                                     +--------+  Sym.      N /  \
                                                     |  Test  |  UDP    <---/Resp\
                                                     |   II   |  Firewall   \ ?  /
                                                     +--------+              \  /
                                                         |                    \/
                                                         V                     |Y
                              /\                         /\                    |
               Symmetric  N  /  \       +--------+   N  /  \                   V
                  NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
                            \Same/      |   I    |     \ ?  /               Internet
                             \? /       +--------+      \  /
                              \/                         \/
                              |                           |Y
                              |                           |
                              |                           V
                              |                           Full
                              |                           Cone
                              V              /\
                          +--------+        /  \ Y
                          |  Test  |------>/Resp\---->Restricted
                          |   III  |       \ ?  /
                          +--------+        \  /
                                             \/
                                              |N
                                              |       Port
                                              +------>Restricted
*/
pub async fn nat_detect_with_servers(stun_server_list: &[&str]) -> IoResult<(NatType, SocketAddr)> {
    let mut reduce_map: HashMap<NatType, usize> = HashMap::new();
    let mut handlers = Vec::new();

    let local_address = local_ip().await?;
    debug!("local ip: {}", local_address.ip());

    for s in stun_server_list {
        debug!("{} use", s);
        let stun_server = s.to_string();
        let local_address_clone = local_address;
        handlers.push(tokio::spawn(async move {
            nat_detect(local_address_clone, &stun_server).await
        }));
    }

    let mut public_address = empty_address();

    let empty_address = empty_address();

    for h in handlers {
        let result = h
            .await
            .map_err(|_| std::io::Error::from(ErrorKind::Other))?;
        if let Result::Ok((a, p, n)) = result {
            info!("{} -> {:?}", a, n);

            if !empty_address.eq(&p) {
                public_address = p;
            }

            reduce_map.entry(n).and_modify(|e| *e += 1).or_insert(1);
        }
    }

    // select maximum weight
    if let Option::Some(n) = reduce_map
        .keys()
        .max_by(|k1, k2| k1.weight().cmp(&k2.weight()))
    {
        return IoResult::Ok((*n, public_address));
    }

    other_error()
}

fn empty_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 0)
}

pub async fn local_ip() -> IoResult<SocketAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    socket.local_addr()
}

pub async fn nat_detect(
    local_address: SocketAddr,
    stun_server: &str,
) -> IoResult<(String, SocketAddr, NatType)> {
    let transaction_id = TransactionId::new([3; 12]);
    let mut socket = tokio::net::UdpSocket::bind(format!("{}:0", local_address.ip())).await?;
    let mut_socket_ref = &mut socket;
    let stun_server_string = stun_server.to_string();

    // Test 1
    let test1_message: Message<UnknownAttributes> = build_request_bind_message(transaction_id);
    debug!("[{}] test1 send: {:?}", stun_server, test1_message);

    let result = single_send(stun_server, test1_message, mut_socket_ref).await;
    debug!("[{}] test1: {}", stun_server, result.is_ok());

    if result.is_err() {
        return IoResult::Ok((stun_server_string, empty_address(), NatType::UdpBlocked));
    }

    let result = result.unwrap();

    let test1_response: Message<stun_codec_blazh::rfc5389::Attribute> =
        single_decode(&result, &transaction_id).unwrap();
    debug!("[{}] test1 rfc5389 recv: {:?}", stun_server, test1_response);

    let test1_mapped_address = {
        let opt: Option<&MappedAddress> = test1_response.get_attribute();
        match opt {
            None => return other_error(),
            Some(a) => a.address(),
        }
    };
    debug!(
        "[{}] test1 mapped_address: {}",
        stun_server, test1_mapped_address
    );

    let public_address = SocketAddr::new(test1_mapped_address.ip(), test1_mapped_address.port());

    let test1_changed_address = {
        let test1_response: Message<stun_codec_blazh::rfc3489::Attribute> =
            single_decode(&result, &transaction_id).unwrap();
        let opt: Option<&ChangedAddress> = test1_response.get_attribute();
        match opt {
            None => {
                let response: Message<stun_codec_blazh::rfc5780::Attribute> =
                    single_decode(&result, &transaction_id).unwrap();
                debug!("[{}] test1 rfc5780 recv: {:?}", stun_server, response);
                let opt: Option<&OtherAddress> = response.get_attribute();

                match opt {
                    None => return other_error(),
                    Some(a) => a.address(),
                }
            }
            Some(a) => a.address(),
        }
    };
    debug!(
        "[{}] test1 changed_address: {}",
        stun_server, test1_changed_address
    );

    // Test 2
    let test2_message =
        build_request_bind_message_with_attribute(transaction_id, ChangeRequest::new(true, true));

    let local_ip = mut_socket_ref.local_addr()?.ip();
    let test1_mapped_address_ip = test1_mapped_address.ip();
    let test1_is_same_ip = local_ip.eq(&test1_mapped_address_ip);
    debug!(
        "[{}] test1 is_same_ip: l:{} r:{}",
        stun_server, local_ip, test1_mapped_address_ip
    );

    if test1_is_same_ip {
        // No NAT
        debug!("[{}] test2 send: {:?}", stun_server, test2_message);
        let result = single_send::<ChangeRequest>(stun_server, test2_message, mut_socket_ref).await;
        debug!("[{}] test2: {}", stun_server, result.is_ok());

        if result.is_err() {
            IoResult::Ok((stun_server_string, public_address, OpenInternet))
        } else {
            debug!("[{}] test2 recv: {:?}", stun_server, result.unwrap());
            IoResult::Ok((stun_server_string, public_address, SymmetricUdpFirewall))
        }
    } else {
        // NAT
        debug!("[{}] test2 send: {:?}", stun_server, test2_message);

        let result = single_send::<ChangeRequest>(stun_server, test2_message, mut_socket_ref).await;
        debug!("[{}] test2: {}", stun_server, result.is_ok());

        if result.is_ok() {
            let test2_message = result.unwrap();
            debug!("[{}] test2 recv: {:?}", stun_server, test2_message);

            IoResult::Ok((stun_server_string, public_address, FullCone))
        } else {
            // Test 1(2)
            let test1_address = test1_changed_address.to_string();

            let test12_message: Message<UnknownAttributes> =
                build_request_bind_message(transaction_id);
            debug!("[{}] test12 send: {:?}", stun_server, test12_message);

            let result = single_send(test1_address.as_str(), test12_message, mut_socket_ref).await;
            debug!("[{}] test12: {}", stun_server, result.is_ok());

            if result.is_err() {
                IoResult::Ok((stun_server_string, public_address, Unknown))
            } else {
                // Symmetric NAT
                let test12_response: Message<stun_codec_blazh::rfc5389::Attribute> =
                    single_decode(&result.unwrap(), &transaction_id).unwrap();
                debug!("[{}] test12 recv: {:?}", stun_server, test12_response);

                let test12_mapped_address = {
                    let opt: Option<&MappedAddress> = test12_response.get_attribute();
                    match opt {
                        None => return other_error(),
                        Some(a) => a.address(),
                    }
                };
                debug!(
                    "[{}] test12 mapped_address: {}",
                    stun_server, test12_mapped_address
                );

                if !test1_mapped_address.eq(&test12_mapped_address) {
                    IoResult::Ok((stun_server_string, public_address, Symmetric))
                } else {
                    // Test 3
                    let test3_message = build_request_bind_message_with_attribute(
                        transaction_id,
                        ChangeRequest::new(false, true),
                    );
                    debug!("[{}] test3 send: {:?}", stun_server, test3_message);

                    let result = single_send::<ChangeRequest>(
                        test1_address.as_str(),
                        test3_message,
                        mut_socket_ref,
                    )
                    .await;
                    debug!("[{}] test3: {}", stun_server, result.is_ok());

                    if result.is_err() {
                        IoResult::Ok((stun_server_string, public_address, PortRestrictedCone))
                    } else {
                        debug!("[{}] test3 recv: {:?}", stun_server, result.unwrap());
                        IoResult::Ok((stun_server_string, public_address, RestrictedCone))
                    }
                }
            }
        }
    }
}

fn other_error<A>() -> IoResult<A> {
    IoResult::Err(std::io::Error::from(ErrorKind::Other))
}

fn build_request_bind_message<A: Attribute>(transaction_id: TransactionId) -> Message<A> {
    Message::new(MessageClass::Request, methods::BINDING, transaction_id)
}

fn build_request_bind_message_with_attribute<A: Attribute>(
    transaction_id: TransactionId,
    a: A,
) -> Message<A> {
    let mut message = build_request_bind_message(transaction_id);
    message.add_attribute(a);
    message
}

async fn single_send<A: Attribute>(
    stun_server: &str,
    message: Message<A>,
    socket: &mut UdpSocket,
) -> IoResult<Vec<u8>> {
    let mut encoder = MessageEncoder::default();
    let bytes: Vec<u8> = encoder
        .encode_into_bytes(message.clone())
        .map_err(|_e| std::io::Error::from(ErrorKind::Other))?;
    let mut buf = [0; 1 << 9];

    for _ in 0..STUN_RETRY_COUNT {
        match tokio::time::timeout(TIMEOUT, socket.send_to(bytes.as_slice(), stun_server)).await {
            Ok(Ok(_)) => {}
            _ => continue,
        }

        let len = {
            match tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf)).await {
                Ok(Ok((i, _))) => i,
                _ => continue,
            }
        };

        return Ok(buf[0..len].into());
    }

    IoResult::Err(std::io::Error::from(ErrorKind::Other))
}

fn single_decode<B: Attribute>(input: &Vec<u8>, id: &TransactionId) -> IoResult<Message<B>> {
    let mut decoder = MessageDecoder::<B>::new();

    if let Ok(Ok(m)) = decoder.decode_from_bytes(input.as_slice()) {
        if m.class() != MessageClass::ErrorResponse && id.eq(&m.transaction_id()) {
            return IoResult::Ok(m);
        }
    };

    IoResult::Err(std::io::Error::from(ErrorKind::Other))
}
