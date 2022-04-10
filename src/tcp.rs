use std::io;

enum State {
    // Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ...
///                  1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed
///
/// ...

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool, 
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32, 

}


/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ...
///                       1          2          3
///                   ----------|----------|----------
///                          RCV.NXT    RCV.NXT
///                                    +RCV.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers allowed for new reception
///        3 - future sequence numbers which are not yet allowed
///
/// ...

struct RecvSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice::<'a>, 
        tcph: etherparse::TcpHeaderSlice::<'a>, 
        data: &'a [u8]
    ) -> io::Result<Option<Self>> {

        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only syn packet expected
            return Ok(None);
        }
        

        // Creating a new connection as SYN was recv'd
        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss, // last thing we sent that is not ack'd by client
                nxt: iss,
                wnd: wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(), 
                tcph.source_port(), 
                iss,  // 0 for now, truly random ISN implementation later
                wnd,
            ),
            ip: etherparse::Ipv4Header::new(
                0,                
                64, 
                etherparse::IpTrafficClass::Tcp, 
                [
                    iph.destination()[0], 
                    iph.destination()[1], 
                    iph.destination()[2], 
                    iph.destination()[3],
                ], 
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ], 
            ),
        };


        // start establishing a connection

        c.tcp.syn = true;
        c.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(buf.len(), self.tcp.header_len() as usize + self.ip.header_len() as usize + payload.len(),);
        self.ip.set_payload_len(size - self.ip.header_len() as usize);
        self.tcp.checksum = self.tcp
         .calc_checksum_ipv4(&self.ip, &[])
         .expect("failed to compute checksum"); 
        
        // write headers into buffer
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }

    fn send_reset(
        &mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix seq. numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //

        // TODO: Handle synchronized RST
        //    3.  If the connection is in a synchronized state (ESTABLISHED,
        //    FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        //    any unacceptable segment (out of window sequence number or
        //    unacceptible acknowledgment number) must elicit only an empty
        //    acknowledgment segment containing the current send-sequence number
        //    and an acknowledgment indicating the next sequence number expected
        //    to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(())
    }


    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice::<'a>, 
        tcph: etherparse::TcpHeaderSlice::<'a>, 
        data: &'a [u8]
    ) -> io::Result<()> {
        //
        // valid segment check
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            //separate rules for acceptance apply if segment is of zero length
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                   false 
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) && 
                !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn.wrapping_add( slen - 1 ), wend) {
                    false
            } else {
                true
            }
        };

        if !okay {
            self.write(nic, &[])?;
            return Ok(());
        }

        self.recv.nxt = seqn.wrapping_add(slen);

        //
        // Check that seq. numbers are valid (RFC 793 S3.3)
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        //


        let ackn = tcph.acknowledgment_number();
        if let State::SynRcvd = self.state {
            if is_between_wrapped(self.send.una.wrapping_sub(1), ackn, self.send.nxt.wrapping_add(1)) {
                // packet must be an ACK to our SYN, as at least one un-ACK'd byte has been ACK'd and we only 
                // sent a SYN
                self.state = State::Estab;
            } else {
                // TODO: RST <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                println!("Arun: it looks like ack is not b/w una and nxt");
            }
        }
        

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            // TODO: a lot, later
            assert!(data.is_empty());
            // let's terminate the connection
            // TODO: needs to be stored in the retransmission queue
            if let State::Estab = self.state {
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }
        
        
        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // our FIN has been ACK'd
                self.state = State::FinWait2;
            }
        }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                },
                _ => unreachable!(),
            }
        }


        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::{Ordering};
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            // check is violated iff end is b/w start and x
            if end >= start && end <= x {
                return false; 
            }
        },
        Ordering::Greater => {
            // check is ok iff end is b/w start and x
            if end < start && end > x {
                return true;
            } else {
                return false;
            }
        },
    }
    true
}
