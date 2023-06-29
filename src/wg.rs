use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use boringtun::{noise::Tunn, noise::TunnResult, x25519};
use tracing::{error, info};

use std::convert::TryInto;

const MIN_BUF_SIZE: usize = 148;

pub fn foo() -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // wg genkey
    let mut our_privkey_bytes = Vec::with_capacity(32);
    b64.decode_vec("GMV47qVOSOolUe9c2IJmbQjv8B2eBMImZtir2Cv3J00=", &mut our_privkey_bytes).context("Our private key is longer than 32 bytes")?;

    // echo their_privkey | wg pubkey
    let mut their_pubkey_bytes = Vec::with_capacity(32);
    b64.decode_vec("SyYqye3/WKGNXq3QepvrcRJ53dI57jInIt4hobRMqSg=", &mut their_pubkey_bytes).context("Peer public key is longer than 32 bytes")?;

    let mut tunn = Tunn::new(
        x25519::StaticSecret::from(to_u8_32(our_privkey_bytes)?), // static_private, 32 bytes
        x25519::PublicKey::from(to_u8_32(their_pubkey_bytes)?), // peer_static_public, 32 bytes
        None, // preshared_key (TODO allow enabling by arg, 32 bytes)
        Some(25), // persistent_keepalive (TODO disable by default, allow enabling by arg)
        // TODO index pseudorandom https://github.com/cloudflare/boringtun/blob/878385f171d60effac4ad1a9d4dee41e777528b8/boringtun/src/device/mod.rs#L855-L861
        0, // index (increment once per configured peer?)
        None // rate_limiter
    ).map_err(|e| anyhow!(e))?;

    let message = "Panics if dst buffer is too small. Size of dst should be at least src.len() + 32, and no less than 148 bytes.";
    let mut bufsize = message.len() + 32;
    if bufsize < MIN_BUF_SIZE {
        bufsize = MIN_BUF_SIZE;
    }
    info!("message {} => bufsize {}", message.len(), bufsize);

    // TODO theres some timer handling in the Peers to be done https://github.com/cloudflare/boringtun/blob/878385f171d60effac4ad1a9d4dee41e777528b8/boringtun/src/device/mod.rs#L570-L587

    let mut bufs = Vec::new();
    // TODO udp writer example, seems to match up https://github.com/cloudflare/boringtun/blob/878385f171d60effac4ad1a9d4dee41e777528b8/boringtun/src/device/mod.rs#L827
    loop {
        let mut buf = Vec::<u8>::with_capacity(bufsize);
        buf.resize(bufsize, 0);
        let arr_len: usize;
        // TODO should additional calls omit message param?
        match tunn.encapsulate(message.as_bytes(), &mut buf) {
            TunnResult::Done => {
                info!("encapsulate done");
                break;
            },
            TunnResult::Err(e) => {
                error!("encapsulate error: {:?}", e);
                break;
            },
            TunnResult::WriteToNetwork(arr) => {
                info!("encapsulate writetonetwork({}): {:?}", arr.len(), arr);
                // arr is a ref to buf, so just resize/shrink buf to match arr
                arr_len = arr.len();
            },
            TunnResult::WriteToTunnelV4(arr, addr) => {
                info!("encapsulate writetotunnelv4({:?}, {}): {:?}", addr, arr.len(), arr);
                arr_len = arr.len();
            },
            TunnResult::WriteToTunnelV6(arr, addr) => {
                info!("encapsulate writetotunnelv6({:?}, {}): {:?}", addr, arr.len(), arr);
                arr_len = arr.len();
            },
        }
        if arr_len > 0 {
            buf.resize(arr_len, 0);
            bufs.push(buf);
        }
    }
    info!("bufs {}: {:?}", bufs.len(), bufs);

    // TODO udp reader example, note parsed packet thing: https://github.com/cloudflare/boringtun/blob/878385f171d60effac4ad1a9d4dee41e777528b8/boringtun/src/device/mod.rs#L627
    for buf in bufs {
        let mut buf2 = Vec::<u8>::with_capacity(MIN_BUF_SIZE);
        buf2.resize(MIN_BUF_SIZE, 0);
        let arr_len: usize;
        match tunn.decapsulate(None, &buf, &mut buf2) {
            TunnResult::Done => {
                info!("decapsulate done");
                break;
            },
            TunnResult::Err(e) => {
                error!("decapsulate error: {:?}", e);
                break;
            },
            TunnResult::WriteToNetwork(arr) => {
                info!("decapsulate writetonetwork({}): {:?}", arr.len(), arr);
                // arr is a ref to buf, so just resize/shrink buf to match arr
                arr_len = arr.len();
            },
            TunnResult::WriteToTunnelV4(arr, addr) => {
                info!("decapsulate writetotunnelv4({:?}, {}): {:?}", addr, arr.len(), arr);
                arr_len = arr.len();
            },
            TunnResult::WriteToTunnelV6(arr, addr) => {
                info!("decapsulate writetotunnelv6({:?}, {}): {:?}", addr, arr.len(), arr);
                arr_len = arr.len();
            },
        }
        if arr_len > 0 {
            buf2.resize(arr_len, 0);
            info!("buf2: {:?}", buf2);
        }
    }

    bail!("ok cya")
}

fn to_u8_32(v: Vec<u8>) -> Result<[u8; 32]> {
    let len = v.len();
    v.try_into().map_err(|_| anyhow!("Failed to create 32 byte array: data is {} bytes", len))
}
