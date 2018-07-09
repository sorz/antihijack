# antihijack
Drop TCP fragments come in unusual fast that is probably injected by the ISP.

The ISP injects fake HTTP responses with ADs to my connections. While they don't
prevent normal packets coming, simply drop injected ones will stop hijackings.

This simple tool listens on
[netfilter queue](https://www.netfilter.org/projects/libnetfilter_queue/index.html),
and check the first few packets of every TCP connections on port 80. It will
drop packets received within `drop-within` millisecond after any data sent by
our side in this connection; or within `may-drop-within` AND less than the RTT
estimated during the TCP handshaking.

## Build
Install [Rust toolchain](https://rustup.rs/), then

```bash
git clone https://github.com/sorz/antihijack
cargo build --release
target/release/antihijack --help
```

## Firewall
Firewall must be configured to check packets using this program.
Following is a iptables example.

```bash
iptables -N anti-hijack
# only check the fisrt few packets
iptables -A anti-hijack -m connbytes --connbytes-dir reply --connbytes-mode packets --connbytes 8 -j RETURN
iptables -A anti-hijack -j NFQUEUE --queue-bypass

# assume the WAN interface is ppp0 and we are an router
iptables -A FORWARD -o ppp0 -p tcp --dport 80 --tcp-flags FIN,RST NONE -j anti-hijack
iptables -A FORWARD -i ppp0 -p tcp --sport 80 --tcp-flags FIN,RST NONE -j anti-hijack

# if we are a host instead, use OUTPUT
iptables -A OUTPUT -o ppp0 -p tcp --dport 80 --tcp-flags FIN,RST NONE -j anti-hijack
iptables -A OUTPUT -i ppp0 -p tcp --sport 80 --tcp-flags FIN,RST NONE -j anti-hijack
```

Note that the port number 80 was hard-coded, others would not work.

## Effectiveness
In my case, the injected packets usually come around 2 milliseconds, while
sometimes is longer. `--drop 3 --wait 10` works well for me, although it
makes some false positives for near CDNs, TCP retransmission will be
tiggered quickly so not a big issue.

