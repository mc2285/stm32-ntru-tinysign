use serialport::{available_ports, Error, SerialPort, SerialPortInfo, SerialPortType};
use sha3::{Digest, Sha3_512};
use std::{
    process::ExitCode,
    thread::sleep,
    time::{Duration, Instant},
    vec,
};

const SERIAL_TIMEOUT: std::time::Duration = Duration::from_millis(400);
const INIT_TIMEOUT: std::time::Duration = Duration::from_millis(1500);
const CMD_TIMEOUT: std::time::Duration = Duration::from_millis(3000);
const PROBE_GRANUALITY: std::time::Duration = Duration::from_millis(25);

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
                if res[res.len() - 1] == b'\n' {
                    res.pop();
                    if res[res.len() - 2] == b'\r' {
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
    let data = std::fs::read(file_path)?;
    if data.len() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Empty file",
        ));
    }
    if !file_path.ends_with(".sig") {
        // get a writeable handle at file_path + ".sig"
        let sig_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(file_path.to_string() + ".sig")?;
        Ok((data, Some(sig_file)))
    } else {
        Ok((data, None))
    }
}

fn main() -> ExitCode {
    let file_path = std::env::args().nth(1);
    if let None = file_path {
        eprintln!("Argument required: path to file to sign");
        return ExitCode::FAILURE;
    }
    let (data, sig_file) = match get_files(&file_path.unwrap()) {
        Ok((data, sig_file)) => (data, sig_file),
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };
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

    // Response buffer
    let mut buffer: Vec<u8> = Vec::with_capacity(10240);

    // Get device info
    if let Err(e) = send_and_read_resp(&mut handle, &mut buffer, "AT+I\r\n".as_bytes(), 4) {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }
    let info_msg = String::from_utf8_lossy(&buffer);
    println!("Found a token! Device info: \n{}", info_msg);
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
    if max_msg_len < Sha3_512::output_size() + 16 + 2 {
        eprintln!("Error: Device message capacity insufficient");
        return ExitCode::FAILURE;
    }
    return ExitCode::SUCCESS;
}
