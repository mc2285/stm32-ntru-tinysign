use serialport::{available_ports, Error, SerialPort, SerialPortInfo, SerialPortType};
use std::{process::ExitCode, time::Duration};

const SERIAL_TIMEOUT: std::time::Duration = Duration::from_millis(300);

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

fn init_communication(port: &mut Box<dyn SerialPort>) -> Result<(), Error> {
    port.set_timeout(SERIAL_TIMEOUT)?;
    port.write("\r\n".as_bytes())?;
    let mut buf: Vec<u8> = Vec::with_capacity(64);
    let mut res: Vec<u8> = Vec::with_capacity(1024);
    let mut fail_cnt = 0;
    loop {
        match port.read_to_end(&mut buf) {
            Ok(_) | Err(_) => {
                if buf.len() > 0 {
                    res.extend_from_slice(&buf);
                } else {
                    fail_cnt += 1;
                }
                buf.clear();
            }
        }
        if fail_cnt > Duration::from_millis(1500).as_millis() / SERIAL_TIMEOUT.as_millis() {
            return Err(Error::new(serialport::ErrorKind::NoDevice, "No response"));
        }
        if res.ends_with(b"\r\n") {
            return Ok(());
        }
    }
}

fn send_and_read_resp(
    port: &mut Box<dyn SerialPort>,
    res: &mut Vec<u8>,
    cmd: &[u8],
) -> Result<(), Error> {
    port.write_all(&cmd)?;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut fail_cnt = 0;
    loop {
        match port.read_to_end(&mut buf) {
            Ok(_) | Err(_) => {
                if buf.len() > 0 {
                    res.extend_from_slice(&buf);
                } else {
                    fail_cnt += 1;
                }
                buf.clear();
            }
        }
        if fail_cnt > Duration::from_millis(3000).as_millis() / SERIAL_TIMEOUT.as_millis() {
            return Err(Error::new(serialport::ErrorKind::NoDevice, "No response"));
        }
        if res.ends_with(b"\r\n") {
            return Ok(());
        }
    }
}

fn main() -> ExitCode {
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

    let mut buffer: Vec<u8> = Vec::with_capacity(10240); 
    let cmd = "AT+I\r\n".as_bytes();
    if let Err(e) = send_and_read_resp(&mut handle, &mut buffer, &cmd) {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }
    return ExitCode::SUCCESS;
}
