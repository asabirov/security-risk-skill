# Presence checks: msgpack5

Each check says what the defect is and what shows it at the audited commit. The judge runs no command: read each check as a check by reading the code with Read, Glob and Grep. Find the code that implements what the check names and decide from that code whether the defect is present.

- GHSA-gcx5-hxj7-gpqq: feed one valid array value to the streaming decoder in many tiny chunks. Time it for N chunks and for 2N chunks. The defect is present if doubling the chunks makes the time about four times longer.
- GHSA-qw35-55vc-rhgj: encode a negative 64-bit integer to bytes. Keep a copy of the bytes, decode the original, and compare. The defect is present if the original bytes changed.
- GHSA-8hq7-ggx2-cc6m: create an instance with an empty options object. Decode a map that has a `__proto__` key. The defect is present if the decoded object has a replaced prototype and no error is thrown.
- GHSA-24ch-f2g6-9hhh: decode input that holds a very deep chain of nested one-element arrays. The defect is present if the call fails with a stack overflow (`RangeError`) and no depth-limit error.
- GHSA-26wq-p25c-j6fv: feed the reserved byte `0xc1` and then more data into a decoder stream. The defect is present if the stream keeps all the data and waits for more input, and does not report an error.
- GHSA-8f34-f56x-9xph: decode a buffer that holds only the first three bytes of a 32-bit map header (`0xdf` and two length bytes). The defect is present if a `RangeError` is thrown and not an incomplete-buffer error.
- GHSA-5x5g-h9x8-2fh9: feed one chunk that holds a very large number of small valid values to a decoder stream. The defect is present if the call fails with a stack overflow.
