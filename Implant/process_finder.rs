use windows::{
    Win32::Foundation::CloseHandle, 
    Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, 
        PROCESSENTRY32W, TH32CS_SNAPPROCESS
    },
};

pub fn find_process_by_name(target_name: &str) -> Option<u32> {
    unsafe {
        let snapshot_res = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if let Ok(snapshot) = snapshot_res {
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let len = entry.szExeFile.iter().take_while(|&&c| c != 0).count();
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]);

                    if name.eq_ignore_ascii_case(target_name) {
                        let _ = CloseHandle(snapshot);
                        return Some(entry.th32ProcessID);
                    }

                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
        }
    }
    None
}