#[macro_use]
extern crate log;
extern crate clap;
extern crate libc;
extern crate nfqueue;
extern crate env_logger;
#[macro_use]
extern crate lazy_static;
use std::cmp::min;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use clap::{Arg, App};
use libc::AF_INET;
use nfqueue::{Message, Verdict, Queue, CopyMode};

const CONNECTION_TRACKING_SECS: u64 = 30;
const HASHMAP_LEN_HIGH: usize = 100;
const HASHMAP_LEN_MAX: usize = 1000;


lazy_static! {
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



struct State {
    conns: HashMap<(SocketAddrV4, SocketAddrV4), Connection>,
    max_wait: Duration,
}

impl State {
    fn new(wait_millis: u64) -> Self {
        State {
            conns: HashMap::new(),
            max_wait: Duration::from_millis(wait_millis),
        }
    }
}

fn callback(msg: &Message, state: &mut State) {
    trace!("{} -> msg: {}", msg.get_indev(), msg);
    let mut verdict = Verdict::Accept;
    if let Some(pkt) = Packet::parse(msg.get_payload()) {
        trace!("{:?}", pkt);
        let key = pkt.conn_tuple();
        let mut expired = false;
        if pkt.flag_syn && !pkt.flag_ack {
            // track new connection on ACK
            state.conns.insert(key, Connection::new());
        } else if let Some(mut conn) = state.conns.get_mut(&key) {
            if pkt.flag_syn && pkt.flag_ack {
                conn.syn_ack();
            } else if pkt.from_local() {
                // request sent from local
                conn.request_sent();
            } else {
                // response from remote
                if let Connection { delay: Some(delay), last_sent } = conn {
                    let log = format!(
                        "{:?}ms (RTT {}ms, from {:?})",
                        last_sent.elapsed().subsec_millis(),
                        delay.subsec_millis(),
                        pkt.src,
                    );
                    if last_sent.elapsed() < min(*delay, state.max_wait) {
                        verdict = Verdict::Drop;
                        info!("drop {}", log);
                    } else {
                        if last_sent.elapsed() < state.max_wait {
                            info!("accept {}", log);
                        } else {
                            debug!("accept {}", log);
                        }
                        expired = true;
                    }
                }
            }
        }
        if expired {
            state.conns.remove(&key);
        }
        if state.conns.len() > HASHMAP_LEN_HIGH {
            let exp: Vec<_> = state.conns.iter().filter_map(|(key, conn)| {
                if conn.last_sent.elapsed() > *CONN_TIMEOUT {
                    Some(key.clone())
                } else {
                    None
                }
            }).collect();
            for key in exp {
                state.conns.remove(&key);
            }
        }
        if state.conns.len() > HASHMAP_LEN_MAX {
            // prevent DoS
            state.conns.clear();
        }
    }
    msg.set_verdict(verdict);
}

fn main() {
    let matches = App::new("antihijack")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Shell Chen <me@sorz.org>")
        .about("Drop specific TCP fragments according to their arrival time")
        .arg(Arg::with_name("queue-num")
             .long("queue")
             .short("n")
             .help("Netfilter queue number which this program bind on.")
             .takes_value(true)
             .default_value("0"))
        .arg(Arg::with_name("drop-within")
             .long("drop")
             .short("d")
             .help("Drop everything come in less that it in millisecond.")
             .takes_value(true)
             .default_value("5"))
        .arg(Arg::with_name("may-drop-within")
             .long("may-drop")
             .short("m")
             .help("Drop if less that it AND less than the RTT.")
             .takes_value(true)
             .default_value("20"))
        .get_matches();

    env_logger::init();
    let may_drop = matches.value_of("may-drop-within")
        .expect("missing argumment may-drop-within")
        .parse().expect("may-drop-within must be a postive integer");

    let state = State::new(may_drop);
    let mut queue = Queue::new(state);
    queue.open();
    if queue.bind(AF_INET) != 0 {
        panic!("fail to bind on queue");
    }
    let queue_num = 0;
    queue.create_queue(queue_num, callback);
    queue.set_mode(CopyMode::CopyPacket, 20 + 16);
    info!("Listen on netfilter queue {}", queue_num);
    queue.run_loop();
}

