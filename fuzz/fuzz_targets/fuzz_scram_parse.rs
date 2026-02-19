#![no_main]

use fraiseql_wire::auth::ScramClient;
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

#[derive(Debug)]
struct ScramInput {
    username: String,
    password: String,
    server_first: String,
    server_final: String,
}

impl<'a> Arbitrary<'a> for ScramInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> libfuzzer_sys::arbitrary::Result<Self> {
        let username: String = u.arbitrary()?;
        let password: String = u.arbitrary()?;
        let server_first: String = u.arbitrary()?;
        let server_final: String = u.arbitrary()?;
        Ok(Self {
            username,
            password,
            server_first,
            server_final,
        })
    }
}

fuzz_target!(|input: ScramInput| {
    let mut client = ScramClient::new(input.username, input.password);
    let _first = client.client_first();

    if let Ok((_, state)) = client.client_final(&input.server_first) {
        let _ = client.verify_server_final(&input.server_final, &state);
    }
});
