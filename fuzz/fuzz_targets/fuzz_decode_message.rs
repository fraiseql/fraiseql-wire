#![no_main]

use bytes::BytesMut;
use fraiseql_wire::protocol::decode::decode_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytesMut::from(data);

    // Feed the buffer in a loop to simulate multiple messages arriving
    // in a single TCP segment.
    loop {
        if buf.is_empty() {
            break;
        }
        match decode_message(&mut buf) {
            Ok((_, consumed)) => {
                if consumed == 0 {
                    break;
                }
                let _ = buf.split_to(consumed);
            }
            Err(_) => break,
        }
    }
});
