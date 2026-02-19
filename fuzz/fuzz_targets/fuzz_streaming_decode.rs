#![no_main]

use bytes::BytesMut;
use fraiseql_wire::protocol::decode::decode_message;
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

#[derive(Debug)]
struct StreamingInput {
    data: Vec<u8>,
    split_points: Vec<u8>,
}

impl<'a> Arbitrary<'a> for StreamingInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> libfuzzer_sys::arbitrary::Result<Self> {
        let data: Vec<u8> = u.arbitrary()?;
        let split_points: Vec<u8> = u.arbitrary()?;
        Ok(Self { data, split_points })
    }
}

fuzz_target!(|input: StreamingInput| {
    if input.data.is_empty() {
        return;
    }

    // Generate split indices from the raw split_points bytes
    let mut splits: Vec<usize> = input
        .split_points
        .iter()
        .map(|&b| (b as usize) % (input.data.len() + 1))
        .collect();
    splits.push(0);
    splits.push(input.data.len());
    splits.sort_unstable();
    splits.dedup();

    // Feed data in chunks defined by split points
    let mut buf = BytesMut::new();
    for window in splits.windows(2) {
        let chunk = &input.data[window[0]..window[1]];
        buf.extend_from_slice(chunk);

        // Try to decode after each chunk arrives
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
    }
});
