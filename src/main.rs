use chrono::DateTime;
use serialport::{available_ports, Error, SerialPort, SerialPortInfo, SerialPortType};
use sha3::{Digest, Sha3_512};
use std::{
    io::{self, Write},
    process::ExitCode,
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    vec,
};

const SERIAL_TIMEOUT: std::time::Duration = Duration::from_millis(400);
const INIT_TIMEOUT: std::time::Duration = Duration::from_millis(1500);
const CMD_TIMEOUT: std::time::Duration = Duration::from_millis(3000);
const PROBE_GRANUALITY: std::time::Duration = Duration::from_millis(25);

const NONCE_LEN: usize = (40 + 2) * 2;

/// Locates a device with the correct VID/PID and manufacturer/product
/// strings in the list of ports returned by `serialport::available_ports`
fn locate_token(mut ports: Vec<SerialPortInfo>) -> Option<String> {
    loop {
        let port = ports.pop()?;
        if let SerialPortType::UsbPort(port_info) = port.port_type {
            if port_info.vid == 0x0420
                && port_info.pid == 0x2137
                && port_info.manufacturer.unwrap_or("".to_string()) == "ABW"
                && port_info.product.unwrap_or("".to_string()) == "STM32 NTRU Token"
            {
                return Some(port.port_name);
            }
        }
    }
}

/// Initializes communication with the device by sending a newline and waiting
/// for the device to send a response ending with a newline.
/// Will timeout after INIT_TIMEOUT milliseconds of no response.
fn init_communication(port: &mut Box<dyn SerialPort>) -> Result<(), Error> {
    port.set_timeout(SERIAL_TIMEOUT)?;
    port.write("\r\n".as_bytes())?;
    let mut buf: Vec<u8> = vec![0; 64];
    let mut res: Vec<u8> = Vec::with_capacity(1024);
    let start = Instant::now();
    loop {
        match port.read(&mut buf) {
            Ok(n_read) => {
                if n_read > 0 {
                    res.extend_from_slice(&buf[..n_read]);
                    buf = vec![0; 64];
                }
            }
            Err(_) => {}
        }
        if res.iter().filter(|&&c| c == b'\n').count() > 0 {
            return Ok(());
        }
        if Instant::now().duration_since(start) > INIT_TIMEOUT {
            return Err(Error::new(serialport::ErrorKind::NoDevice, "No response"));
        }
        sleep(PROBE_GRANUALITY);
    }
}

/// Sends a command to the device and awaits n newline-terminated responses.
/// Will timeout after CMD_TIMEOUT milliseconds of no response.
fn send_and_read_resp(
    port: &mut Box<dyn SerialPort>,
    res: &mut Vec<u8>,
    cmd: &[u8],
    mut n: i32,
) -> Result<(), Error> {
    port.write_all(&cmd)?;
    let mut buf: Vec<u8> = vec![0; 64];
    let start = Instant::now();
    loop {
        match port.read(&mut buf) {
            Ok(n_read) => {
                if n_read > 0 {
                    res.extend_from_slice(&buf[..n_read]);
                    n -= buf.iter().filter(|&&c| c == b'\n').count() as i32;
                    buf = vec![0; 64];
                }
            }
            Err(_) => {}
        }
        if n <= 0 {
            while n <= 0 {
                let last_ch = *res.last().unwrap_or(&b'\0');
                if last_ch == b'\n' || last_ch == b'\r'{
                    while *res.last().unwrap_or(&b'\0') == b'\n' || *res.last().unwrap_or(&b'\0') == b'\r' {
                        res.pop();
                    }
                n += 1;
                } else {
                    res.pop();
                }
            }
            return Ok(());
        }
        if Instant::now().duration_since(start) > CMD_TIMEOUT {
            return Err(Error::new(serialport::ErrorKind::NoDevice, "No response"));
        }
        sleep(PROBE_GRANUALITY);
    }
}

fn get_files(file_path: &str) -> Result<(Vec<u8>, Option<std::fs::File>), std::io::Error> {
    let mut file = std::fs::File::open(file_path)?;
    if !file_path.ends_with(".sig") {
        // timestamp + | + sha3_512 of file
        let mut hasher = Sha3_512::new();
        std::io::copy(&mut file, &mut hasher)?;
        let mut data: Vec<u8> = Vec::with_capacity(Sha3_512::output_size() + 10);
        data.extend_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_le_bytes(),
        );
        data.extend_from_slice(&"|".as_bytes());
        data.extend_from_slice(hasher.finalize().as_slice());

        // get a writeable handle at file_path + ".sig"
        let sig_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path.to_string() + ".sig")?;
        Ok((data, Some(sig_file)))
    } else {
        // read the signature file
        let mut data = std::fs::read(file_path)?;
        while *data.last().unwrap() == b'\n' || *data.last().unwrap() == b'\r' {
            data.pop();
        }
        if data.len() % 2 != 0 || data.len() < NONCE_LEN + Sha3_512::output_size() * 2 + 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature file",
            ));
        }
        Ok((data, None))
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn main() -> ExitCode {
    let file_path = std::env::args().nth(1);
    if let None = file_path {
        eprintln!("Argument required: path to file to sign");
        return ExitCode::FAILURE;
    }
    let file_path = file_path.unwrap();
    let port_name = match available_ports() {
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
        Ok(ports) => {
            if let Some(port_name) = locate_token(ports) {
                port_name
            } else {
                eprintln!("Error: Token not found");
                return ExitCode::FAILURE;
            }
        }
    };
    let mut handle;
    if let Ok(port) = serialport::new(port_name, 115200).open() {
        handle = port;
    } else {
        eprintln!("Error: Failed to open serial port");
        return ExitCode::FAILURE;
    }
    if let Err(e) = init_communication(&mut handle) {
        eprintln!("Error while starting up: {}", e);
        return ExitCode::FAILURE;
    }

    let (data, sig_file) = match get_files(&file_path) {
        Ok((data, sig_file)) => (data, sig_file),
        Err(e) => {
            eprintln!("Error acquiring file: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Response buffer
    let mut buffer: Vec<u8> = Vec::with_capacity(10240);

    // Get device info
    if let Err(e) = send_and_read_resp(&mut handle, &mut buffer, "AT+I\r\n".as_bytes(), 4) {
        eprintln!("Error getting device info: {}", e);
        return ExitCode::FAILURE;
    }
    let info_msg = String::from_utf8_lossy(&buffer);
    println!("Found a token! Device info: \r\n{}", info_msg);
    // Get maximum accepted message length from device info
    let max_msg_len = info_msg
        .lines()
        .last()
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .parse::<usize>()
        .unwrap();
    // Check if device capacity is sufficient to handle sha3_512 + timestamp + separator + newline
    if max_msg_len < Sha3_512::output_size() + 8 + 2 {
        eprintln!("Error: Device message capacity insufficient");
        return ExitCode::FAILURE;
    }
    match sig_file {
        // We are signing the file
        Some(mut sig_file) => {
            let mut cmd = "AT+S ".as_bytes().to_vec();
            let hex_data = data
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>();
            cmd.extend_from_slice(hex_data.as_bytes());
            cmd.extend_from_slice("\r\n".as_bytes());
            buffer.clear();
            if let Err(e) = send_and_read_resp(&mut handle, &mut buffer, &cmd, 1) {
                eprintln!("Error while signing: {}", e);
                return ExitCode::FAILURE;
            }
            if String::from_utf8_lossy(&buffer).contains("ERROR") {
                eprintln!("Signature creation failed");
                return ExitCode::FAILURE;
            }
            buffer.extend_from_slice("\r\n".as_bytes());
            if let Err(e) = sig_file.write_all(&buffer)
            {
                eprintln!("Error writing signature to file: {}", e);
                return ExitCode::FAILURE;
            }
            println!("Signature written to file: {}", file_path.to_string() + ".sig");
        }
        // We are verifying the signature
        None => {
            let mut cmd = "AT+V ".as_bytes().to_vec();
            cmd.extend_from_slice(&data);
            cmd.extend_from_slice("\r\n".as_bytes());
            buffer.clear();
            if let Err(e) = send_and_read_resp(&mut handle, &mut buffer, &cmd, 1) {
                eprintln!("Error while verifying: {}", e);
                return ExitCode::FAILURE;
            }
            if String::from_utf8_lossy(&buffer).contains("ERROR") {
                eprintln!("Signature is invalid");
                return ExitCode::FAILURE;
            }
            let timestamp = u64::from_le_bytes(
                decode_hex(&String::from_utf8_lossy(&data[NONCE_LEN..NONCE_LEN + 16]))
                    .unwrap_or(vec![0; 8])
                    .try_into()
                    .unwrap_or([0; 8]),
            ) as i64;
            if timestamp == 0 {
                eprintln!("Error: Malformed timestamp in signature");
                return ExitCode::FAILURE;
            }
            let hash = decode_hex(&String::from_utf8_lossy(
                &data[NONCE_LEN + 18..NONCE_LEN + 18 + Sha3_512::output_size() * 2],
            )).unwrap();
            let timestamp = match DateTime::from_timestamp(timestamp, 0) {
                Some(t) => t,
                None => {
                    eprintln!("Error: Invalid timestamp in signature");
                    return ExitCode::FAILURE;
                }
            };

            // Compute original file hash
            let mut hasher = Sha3_512::new();
            let file_path = file_path.replace(".sig", "");
            let mut file = match std::fs::File::open(&file_path) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Could not open base file ({}): {}", &file_path, e);
                    return ExitCode::FAILURE;
                }
            };
            io::copy(&mut file, &mut hasher).unwrap();
            let file_hash = hasher.finalize().to_vec();
            
            // Compare the hashes
            if file_hash != hash {
                eprintln!("Error: Signature does not match base file");
                return ExitCode::FAILURE;
            }

            println!(
                "Signature verified successfully.\r\nCreation time: {}",
                timestamp.to_rfc2822()
            );
            println!("Matches file: {}", &file_path);
        }
    }
    return ExitCode::SUCCESS;
}
