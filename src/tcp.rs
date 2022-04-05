use std::io;

enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
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
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss, // last thing we sent that is not ack'd by client
                nxt: iss + 1,
                wnd: 10,
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

        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(), 
            tcph.source_port(), 
            c.send.iss,  // 0 for now, truly random ISN implementation later
            c.send.wnd,
        );
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        c.ip.set_payload_len(syn_ack.header_len() as usize + 0);
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &[]).expect("failed to compute checksum"); This is not needed as it is handled by kernel
        // write headers into buffer
        let unwritten = {
            let mut unwritten = &mut buf[..];
            c.ip.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten]);
        Ok(Some(c))
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice::<'a>, 
        tcph: etherparse::TcpHeaderSlice::<'a>, 
        data: &'a [u8]
    ) -> io::Result<()> {
        //
        // Check that seq. numbers are valid (RFC 793 S3.3)
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        //

        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        //
        // valid segment check
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // or
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn,
         self.recv.nxt.wrapping_add(self.recv.wnd as u32)) && 
         !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + data.len() as u32 - 1,
          self.recv.nxt.wrapping_add(self.recv.wnd as u32)) {{
            return Ok(());
        }


        match self.state{
            State::SynRcvd => {
                // if we are in SynRcvd, we expect to get an ACK for our SYN (sent in resp to their ACK)
            }
            State::Estab => {
                unimplemented!();
            }
        }
        Ok(())
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::{Ordering};
    match start.cmp(x) {
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
            } else {
                return false;
           }
        },
    }
    true,
}