extern crate libc;
extern crate nfqueue;
#[macro_use]
extern crate lazy_static;
use std::cmp::min;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use libc::AF_INET;
use nfqueue::{Message, Verdict, Queue, CopyMode};

const DROP_WITHIN_MILLIS: u64 = 10;
const CONNECTION_TRACKING_SECS: u64 = 10;
const HASHMAP_LEN_HIGH: usize = 100;
const HASHMAP_LEN_MAX: usize = 1000;


lazy_static! {
    static ref WAIT: Duration = Duration::from_millis(DROP_WITHIN_MILLIS);
    static ref CONN_TIMEOUT: Duration = Duration::from_secs(CONNECTION_TRACKING_SECS);
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

#[derive(Debug, Clone)]
struct Connection {
    last_sent: Instant,
    delay: Option<Duration>,
}

impl Connection {
    fn new() -> Self {
        Connection {
            last_sent: Instant::now(),
            delay: None,
        }
    }

    fn syn_ack(&mut self) {
        if self.delay == None {
            let delay = self.last_sent.elapsed();
            self.delay = Some(delay);
        }
    }

    fn request_sent(&mut self) {
        self.last_sent = Instant::now();
    }
}


type Connections = HashMap<(SocketAddrV4, SocketAddrV4), Connection>;

fn callback(msg: &Message, conns: &mut Connections) {
    //println!("{} -> msg: {}", msg.get_indev(), msg);
    let mut verdict = Verdict::Accept;
    if let Some(pkt) = Packet::parse(msg.get_payload()) {
        //println!("{:?}", pkt);
        let key = pkt.conn_tuple();
        let mut expired = false;
        if pkt.flag_syn && !pkt.flag_ack {
            // track new connection on ACK
            conns.insert(key, Connection::new());
        } else if let Some(mut conn) = conns.get_mut(&key) {
            if pkt.flag_syn && pkt.flag_ack {
                conn.syn_ack();
            } else if pkt.from_local() {
                // request sent from local
                conn.request_sent();
            } else {
                // response from remote
                if let Connection { delay: Some(delay), last_sent } = conn {
                    if last_sent.elapsed() < min(*delay, *WAIT) {
                        verdict = Verdict::Drop;
                        println!("drop {:?}ms < rtt {}ms from {:?}",
                                 last_sent.elapsed().subsec_millis(),
                                 delay.subsec_millis(), pkt.src);
                    } else {
                        println!("accept {:?}ms (rtt {}ms) from {:?}",
                                 last_sent.elapsed().subsec_millis(),
                                 delay.subsec_millis(),pkt.src);
                        expired = true;
                    }
                }
            }
        }
        if expired {
            conns.remove(&key);
        }
        if conns.len() > HASHMAP_LEN_HIGH {
            let empties: Vec<_> = conns.iter().filter_map(|(key, conn)| {
                if conn.last_sent.elapsed() > *CONN_TIMEOUT {
                    Some(key.clone())
                } else {
                    None
                }
            }).collect();
            for key in empties {
                conns.remove(&key);
            }
        }
        if conns.len() > HASHMAP_LEN_MAX {
            conns.clear();
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

