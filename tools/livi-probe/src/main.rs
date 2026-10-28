// SPDX-FileCopyrightText: 2026 MockMFI contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Drives LIVI's own MFi coprocessor implementations against a libmfi `mfid net`
// service:
//
//   * FileCoprocessor   — the macOS "imported files" authenticator
//   * NcmCoprocessor    — the network coprocessor client used with a LIVI Link
//
// Output is line oriented (`key=value`) so a shell script can verify both
// signatures with `mfid verify`.
use iap2_mfi::{AuthCoprocessor, FileCoprocessor, NcmCoprocessor};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).expect("usage: mfi-probe <identity-dir> <host:port>");
    let addr = args.get(2).expect("usage: mfi-probe <identity-dir> <host:port>");

    let mut files = FileCoprocessor::open(std::path::Path::new(dir)).expect("file coprocessor");
    let mut ncm = NcmCoprocessor::new(addr);

    let digest: Vec<u8> = (0u8..32).collect();

    let file_major = files.protocol_major().expect("file protocol major");
    let file_cert = files.read_certificate().expect("file certificate");
    let file_sig = files.generate_challenge_response(&digest).expect("file signature");

    let ncm_major = ncm.protocol_major().expect("network protocol major");
    let ncm_cert = ncm.read_certificate().expect("network certificate");
    let ncm_sig = ncm.generate_challenge_response(&digest).expect("network signature");

    println!("digest={}", hex(&digest));
    println!("file_major={file_major}");
    println!("ncm_major={ncm_major}");
    println!("cert_equal={}", file_cert == ncm_cert);
    println!("file_sig={}", hex(&file_sig));
    println!("ncm_sig={}", hex(&ncm_sig));
}
