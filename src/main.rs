extern crate libc;
extern crate nfqueue;
#[macro_use]
extern crate lazy_static;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use libc::AF_INET;
use nfqueue::{Message, Verdict, Queue, CopyMode};

const DROP_WITHIN_MILLIS: u64 = 8;

lazy_static! {
    static ref WAIT: Duration = Duration::from_millis(DROP_WITHIN_MILLIS);
}

#[derive(Debug)]
struct Packet {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    flag_ack: bool,
    flag_syn: bool,
}

impl Packet {
    fn parse(msg: &[u8]) -> Option<Packet> {
        if msg[0] != 0x45 || msg.len() < 20 + 16 {
            return None
        }
        let src_ip = Ipv4Addr::new(msg[12], msg[13], msg[14], msg[15]);
        let dst_ip = Ipv4Addr::new(msg[16], msg[17], msg[18], msg[19]);
        let src_port = (msg[20] as u16) << 8 | (msg[21] as u16);
        let dst_port = (msg[22] as u16) << 8 | (msg[23] as u16);
        let src = SocketAddrV4::new(src_ip, src_port);
        let dst = SocketAddrV4::new(dst_ip, dst_port);
        let flags = msg[33];
        let flag_ack = flags & (1 << 4) > 0;
        let flag_syn = flags & (1 << 1) > 0;
        Some(Packet { src, dst, flag_ack, flag_syn })
    }

    fn conn_tuple(&self) -> (SocketAddrV4, SocketAddrV4) {
        if self.src.ip() > self.dst.ip() {
            (self.src.clone(), self.dst.clone())
        } else {
            (self.dst.clone(), self.src.clone())
        }
    }

    fn from_local(&self) -> bool {
        self.src.port() != 80
    }

}


type Connections = HashMap<(SocketAddrV4, SocketAddrV4), Option<Instant>>;

fn callback(msg: &Message, conns: &mut Connections) {
    //println!("{} -> msg: {}", msg.get_indev(), msg);
    let mut verdict = Verdict::Accept;
    if let Some(pkt) = Packet::parse(msg.get_payload()) {
        //println!("{:?}", pkt);
        let key = pkt.conn_tuple();
        match (pkt.flag_syn, pkt.flag_ack) {
            (true, false) => (), // ignore SYN until SYN/ACK received
            (true, true) => drop(conns.insert(key, None)), // wait for ACK
            (false, _) => match conns.get(&key).cloned() {
                None => (), // not being tracked
                Some(_) if pkt.from_local() =>
                    // update time on client's request
                    drop(conns.insert(key, Some(Instant::now()))),
                Some(None) =>
                    // remote push data without request from local
                    return drop(conns.remove(&key)),
                Some(Some(t)) if t.elapsed() > *WAIT => {
                    // after waiting time, cancel tracking
                    //println!("accept {:?}ms from {:?}",
                    //         t.elapsed().subsec_millis(),
                    //         pkt.src);
                    conns.remove(&key);
                },
                Some(Some(t)) => {
                    // received just after handshaking, drop it
                    verdict = Verdict::Drop;
                    println!("drop {:?}ms from {:?}",
                             t.elapsed().subsec_millis(), pkt.src);
                },
            },
        }
    }
    msg.set_verdict(verdict);
}

fn main() {
    let conns = HashMap::new();
    let mut queue = Queue::new(conns);
    queue.open();
    if queue.bind(AF_INET) != 0 {
        panic!("fail to bind on queue");
    }
    queue.create_queue(0, callback);
    queue.set_mode(CopyMode::CopyPacket, 20 + 16);
    queue.run_loop();
}

