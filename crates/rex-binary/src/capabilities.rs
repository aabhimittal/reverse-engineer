//! Behavioural capability detection, mapped to MITRE ATT&CK.
//!
//! Inspired by Mandiant's *capa*, but deliberately simpler: rules match on
//! imported APIs, strings, and byte patterns rather than on instruction
//! semantics. Analogy: you're judging what a workshop is for by looking at the
//! tools on the wall. A soldering iron plus a multimeter says "electronics";
//! `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` says
//! "injects code into other processes".
//!
//! A rule is a conjunction of groups; each group is a disjunction of features.
//! `[[A, B], [C]]` reads as "(A or B) and C".

use rex_core::Severity;
use serde::Serialize;

/// A primitive feature.
#[derive(Debug, Clone, Copy)]
pub enum Feat {
    /// Imported (or dynamically-resolved-by-name) API. Matches `X`, `XA`, `XW`.
    Api(&'static str),
    /// Case-insensitive substring of any extracted string.
    Str(&'static str),
    /// Raw byte sequence anywhere in the file.
    Bytes(&'static [u8]),
}

use Feat::*;

/// A capability rule.
pub struct Rule {
    /// Stable id.
    pub id: &'static str,
    /// Human name.
    pub name: &'static str,
    /// Namespace, e.g. `anti-analysis/anti-debugging`.
    pub namespace: &'static str,
    /// Severity when matched.
    pub severity: Severity,
    /// ATT&CK technique ids.
    pub attack: &'static [&'static str],
    /// Conjunction of disjunctions.
    pub groups: &'static [&'static [Feat]],
}

/// A matched capability.
#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    /// Rule id.
    pub id: &'static str,
    /// Name.
    pub name: &'static str,
    /// Namespace.
    pub namespace: &'static str,
    /// Severity.
    pub severity: Severity,
    /// ATT&CK ids.
    pub attack: Vec<&'static str>,
    /// What matched.
    pub evidence: Vec<String>,
}

macro_rules! rule {
    ($id:literal, $name:literal, $ns:literal, $sev:ident, [$($att:literal),*], [$([$($f:expr),+ $(,)?]),+ $(,)?]) => {
        Rule { id: $id, name: $name, namespace: $ns, severity: Severity::$sev, attack: &[$($att),*], groups: &[$(&[$($f),+]),+] }
    };
}

/// Built-in rule set.
pub static RULES: &[Rule] = &[
    // ── anti-analysis
    rule!(
        "CAP-ANTI-DEBUG-WIN",
        "check for debugger (Windows)",
        "anti-analysis/anti-debugging",
        Medium,
        ["T1622"],
        [[
            Api("IsDebuggerPresent"),
            Api("CheckRemoteDebuggerPresent"),
            Api("NtQueryInformationProcess"),
            Api("OutputDebugString"),
            Api("NtSetInformationThread")
        ]]
    ),
    rule!(
        "CAP-ANTI-DEBUG-LINUX",
        "check for debugger (Linux)",
        "anti-analysis/anti-debugging",
        Medium,
        ["T1622"],
        [
            [Str("TracerPid"), Str("PTRACE_TRACEME")],
            [Api("ptrace"), Str("/proc/self/status")]
        ]
    ),
    rule!(
        "CAP-VM-DETECT",
        "detect virtual machine / sandbox",
        "anti-analysis/anti-vm",
        Medium,
        ["T1497.001"],
        [[
            Str("VBoxService"),
            Str("VBoxTray"),
            Str("vmtoolsd"),
            Str("VMware Tools"),
            Str("vboxguest"),
            Str("SbieDll"),
            Str("QEMU HARDDISK"),
            Str("VirtualBox"),
            Str("sandboxie"),
            Str("wine_get_unix_file_name")
        ]]
    ),
    rule!(
        "CAP-TIMING-EVASION",
        "timing-based evasion",
        "anti-analysis/anti-vm",
        Low,
        ["T1497.003"],
        [
            [
                Api("GetTickCount"),
                Api("QueryPerformanceCounter"),
                Api("GetTickCount64")
            ],
            [Api("Sleep"), Api("SleepEx"), Api("NtDelayExecution")]
        ]
    ),
    // ── execution
    rule!(
        "CAP-PROC-CREATE",
        "create process",
        "host-interaction/process/create",
        Info,
        ["T1106"],
        [[
            Api("CreateProcess"),
            Api("CreateProcessAsUser"),
            Api("WinExec"),
            Api("ShellExecute"),
            Api("ShellExecuteEx"),
            Api("execve"),
            Api("execvp"),
            Api("execl"),
            Api("execlp"),
            Api("posix_spawn"),
            Api("system"),
            Api("popen")
        ]]
    ),
    rule!(
        "CAP-SHELL-CMD",
        "run shell commands",
        "host-interaction/process/shell",
        Medium,
        ["T1059"],
        [[
            Str("cmd.exe /c"),
            Str("cmd /c"),
            Str("/bin/sh -c"),
            Str("/bin/bash -c"),
            Str("powershell -"),
            Str("powershell.exe -"),
            Str("-EncodedCommand")
        ]]
    ),
    // ── injection
    rule!(
        "CAP-INJECT-REMOTE-THREAD",
        "inject code into another process",
        "host-interaction/process/inject",
        High,
        ["T1055"],
        [
            [
                Api("VirtualAllocEx"),
                Api("NtAllocateVirtualMemory"),
                Api("NtMapViewOfSection")
            ],
            [Api("WriteProcessMemory"), Api("NtWriteVirtualMemory")],
            [
                Api("CreateRemoteThread"),
                Api("CreateRemoteThreadEx"),
                Api("NtCreateThreadEx"),
                Api("RtlCreateUserThread"),
                Api("QueueUserAPC"),
                Api("SetThreadContext")
            ]
        ]
    ),
    rule!(
        "CAP-PROCESS-HOLLOWING",
        "process hollowing",
        "host-interaction/process/inject",
        High,
        ["T1055.012"],
        [
            [Api("NtUnmapViewOfSection"), Api("ZwUnmapViewOfSection")],
            [Api("SetThreadContext"), Api("Wow64SetThreadContext")],
            [Api("ResumeThread")]
        ]
    ),
    rule!(
        "CAP-INJECT-LINUX",
        "inject into process via ptrace / proc mem",
        "host-interaction/process/inject",
        High,
        ["T1055.008"],
        [[
            Api("process_vm_writev"),
            Str("/proc/%d/mem"),
            Str("PTRACE_POKETEXT"),
            Str("PTRACE_ATTACH")
        ]]
    ),
    // ── persistence
    rule!(
        "CAP-PERSIST-RUNKEY",
        "persist via Run registry key",
        "persistence/registry",
        Medium,
        ["T1547.001"],
        [[
            Str("\\CurrentVersion\\Run"),
            Str("\\CurrentVersion\\RunOnce"),
            Str("\\Winlogon\\Shell"),
            Str("\\Winlogon\\Userinit")
        ]]
    ),
    rule!(
        "CAP-PERSIST-SERVICE",
        "create or modify Windows service",
        "persistence/service",
        Medium,
        ["T1543.003"],
        [
            [Api("CreateService"), Api("ChangeServiceConfig")],
            [Api("OpenSCManager")]
        ]
    ),
    rule!(
        "CAP-PERSIST-SCHTASK",
        "schedule task",
        "persistence/scheduled-task",
        Medium,
        ["T1053.005"],
        [[
            Str("schtasks"),
            Str("ITaskService"),
            Str("\\Microsoft\\Windows\\Task")
        ]]
    ),
    rule!(
        "CAP-PERSIST-LINUX",
        "persist via cron / systemd / shell profile",
        "persistence/linux",
        Medium,
        ["T1053.003", "T1543.002", "T1546.004"],
        [[
            Str("/etc/crontab"),
            Str("/var/spool/cron"),
            Str("crontab -"),
            Str("/etc/systemd/system/"),
            Str("/etc/rc.local"),
            Str("/etc/init.d/"),
            Str(".bashrc"),
            Str("/etc/profile.d")
        ]]
    ),
    rule!(
        "CAP-LD-PRELOAD",
        "hijack dynamic linker (LD_PRELOAD)",
        "persistence/hijack",
        High,
        ["T1574.006"],
        [[Str("/etc/ld.so.preload"), Str("LD_PRELOAD=")]]
    ),
    rule!(
        "CAP-KERNEL-MODULE",
        "load kernel module",
        "persistence/kernel",
        Medium,
        ["T1547.006"],
        [[
            Api("init_module"),
            Api("finit_module"),
            Str("insmod "),
            Str("modprobe ")
        ]]
    ),
    // ── credential access / collection
    rule!(
        "CAP-LSASS-DUMP",
        "dump LSASS memory",
        "credential-access/os-credential-dumping",
        Critical,
        ["T1003.001"],
        [
            [Str("lsass")],
            [
                Api("MiniDumpWriteDump"),
                Api("OpenProcess"),
                Str("comsvcs.dll")
            ]
        ]
    ),
    rule!(
        "CAP-BROWSER-CREDS",
        "steal browser credentials or cookies",
        "credential-access/browser",
        High,
        ["T1555.003", "T1539"],
        [[
            Str("\\Login Data"),
            Str("logins.json"),
            Str("key4.db"),
            Str("\\Network\\Cookies"),
            Str("cookies.sqlite"),
            Str("\\Google\\Chrome\\User Data"),
            Str("Local State")
        ]]
    ),
    rule!(
        "CAP-CRYPTO-WALLET",
        "access cryptocurrency wallets",
        "collection/wallets",
        High,
        ["T1005"],
        [[
            Str("wallet.dat"),
            Str("\\Electrum\\wallets"),
            Str("Exodus\\exodus.wallet"),
            Str("MetaMask"),
            Str("\\Ethereum\\keystore")
        ]]
    ),
    rule!(
        "CAP-KEYLOG",
        "log keystrokes",
        "collection/keylog",
        High,
        ["T1056.001"],
        [[
            Api("SetWindowsHookEx"),
            Api("GetAsyncKeyState"),
            Api("GetKeyboardState"),
            Api("RegisterRawInputDevices"),
            Str("/dev/input/event")
        ]]
    ),
    rule!(
        "CAP-CLIPBOARD",
        "read clipboard",
        "collection/clipboard",
        Medium,
        ["T1115"],
        [[Api("GetClipboardData")], [Api("OpenClipboard")]]
    ),
    rule!(
        "CAP-SCREENSHOT",
        "capture screenshots",
        "collection/screen",
        Medium,
        ["T1113"],
        [
            [Api("BitBlt"), Api("StretchBlt")],
            [
                Api("GetDC"),
                Api("GetWindowDC"),
                Api("GetDesktopWindow"),
                Api("CreateCompatibleBitmap")
            ]
        ]
    ),
    rule!(
        "CAP-AUDIO-VIDEO",
        "capture audio or video",
        "collection/av",
        High,
        ["T1123", "T1125"],
        [[
            Api("waveInOpen"),
            Api("capCreateCaptureWindow"),
            Str("MFEnumDeviceSources")
        ]]
    ),
    // ── discovery
    rule!(
        "CAP-SYSINFO",
        "gather system information",
        "discovery/system",
        Info,
        ["T1082"],
        [[
            Api("GetComputerName"),
            Api("GetUserName"),
            Api("GetVersionEx"),
            Api("RtlGetVersion"),
            Api("GetNativeSystemInfo"),
            Api("uname"),
            Api("gethostname")
        ]]
    ),
    rule!(
        "CAP-PROC-ENUM",
        "enumerate processes",
        "discovery/process",
        Low,
        ["T1057"],
        [[
            Api("CreateToolhelp32Snapshot"),
            Api("EnumProcesses"),
            Api("Process32First"),
            Api("NtQuerySystemInformation")
        ]]
    ),
    rule!(
        "CAP-FILE-ENUM",
        "enumerate files",
        "discovery/file",
        Info,
        ["T1083"],
        [[
            Api("FindFirstFile"),
            Api("FindFirstFileEx"),
            Api("opendir"),
            Api("nftw"),
            Api("fts_open")
        ]]
    ),
    // ── network
    rule!(
        "CAP-HTTP-CLIENT",
        "communicate over HTTP",
        "communication/http",
        Low,
        ["T1071.001"],
        [[
            Api("InternetOpen"),
            Api("InternetOpenUrl"),
            Api("HttpSendRequest"),
            Api("WinHttpOpen"),
            Api("WinHttpSendRequest"),
            Api("curl_easy_perform"),
            Api("URLDownloadToFile"),
            Str("User-Agent:")
        ]]
    ),
    rule!(
        "CAP-SOCKET-CLIENT",
        "open network connections",
        "communication/socket",
        Info,
        ["T1095"],
        [
            [Api("connect"), Api("WSAConnect"), Api("WSAStartup")],
            [Api("socket"), Api("WSASocket"), Api("WSAStartup")]
        ]
    ),
    rule!(
        "CAP-SOCKET-SERVER",
        "listen for incoming connections",
        "communication/socket",
        Low,
        ["T1571"],
        [
            [Api("bind")],
            [Api("listen")],
            [Api("accept"), Api("accept4"), Api("WSAAccept")]
        ]
    ),
    rule!(
        "CAP-DOWNLOAD-EXEC",
        "download and execute",
        "communication/download-exec",
        High,
        ["T1105", "T1204"],
        [
            [
                Api("URLDownloadToFile"),
                Api("InternetReadFile"),
                Api("WinHttpReadData"),
                Str("wget http"),
                Str("curl -o"),
                Str("curl -s")
            ],
            [
                Api("ShellExecute"),
                Api("WinExec"),
                Api("CreateProcess"),
                Api("execve"),
                Api("system"),
                Str("chmod +x"),
                Str("chmod 777")
            ]
        ]
    ),
    rule!(
        "CAP-TOR",
        "use Tor / onion services",
        "communication/proxy",
        Medium,
        ["T1090.003"],
        [[
            Str(".onion"),
            Str("tor2web"),
            Str("socks5://127.0.0.1:9050")
        ]]
    ),
    // ── crypto / encoding
    rule!(
        "CAP-CRYPTO-API",
        "use OS cryptography API",
        "data-manipulation/encryption",
        Info,
        ["T1027"],
        [[
            Api("CryptEncrypt"),
            Api("CryptDecrypt"),
            Api("CryptAcquireContext"),
            Api("BCryptEncrypt"),
            Api("BCryptDecrypt"),
            Api("EVP_EncryptInit_ex"),
            Api("EVP_CipherInit_ex"),
            Api("CCCrypt")
        ]]
    ),
    rule!(
        "CAP-AES-CONST",
        "contains AES S-box",
        "data-manipulation/encryption/aes",
        Info,
        ["T1027"],
        [[Bytes(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76
        ])]]
    ),
    rule!(
        "CAP-SHA256-CONST",
        "contains SHA-256 constants",
        "data-manipulation/hashing/sha256",
        Info,
        [],
        [[
            Bytes(&[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71]),
            Bytes(&[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91])
        ]]
    ),
    rule!(
        "CAP-MD5-CONST",
        "contains MD5 constants",
        "data-manipulation/hashing/md5",
        Info,
        [],
        [[
            Bytes(&[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8]),
            Bytes(&[0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56])
        ]]
    ),
    rule!(
        "CAP-CRC32-TABLE",
        "contains CRC32 table",
        "data-manipulation/checksum/crc32",
        Info,
        [],
        [[Bytes(&[
            0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee
        ])]]
    ),
    rule!(
        "CAP-CHACHA-SALSA",
        "contains ChaCha/Salsa20 constant",
        "data-manipulation/encryption/chacha",
        Info,
        ["T1027"],
        [[Str("expand 32-byte k"), Str("expand 16-byte k")]]
    ),
    rule!(
        "CAP-BASE64",
        "encode or decode Base64",
        "data-manipulation/encoding/base64",
        Info,
        ["T1132.001"],
        [[Str(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )]]
    ),
    // ── impact
    rule!(
        "CAP-RANSOM-RECOVERY",
        "inhibit system recovery",
        "impact/inhibit-recovery",
        Critical,
        ["T1490"],
        [[
            Str("vssadmin delete shadows"),
            Str("vssadmin.exe delete shadows"),
            Str("wmic shadowcopy delete"),
            Str("wbadmin delete catalog"),
            Str("recoveryenabled no"),
            Str("bootstatuspolicy ignoreallfailures")
        ]]
    ),
    rule!(
        "CAP-RANSOM-NOTE",
        "ransom note text",
        "impact/encrypt",
        Critical,
        ["T1486"],
        [[
            Str("your files have been encrypted"),
            Str("your files are encrypted"),
            Str("decrypt your files"),
            Str("bitcoin to"),
            Str("private key will be destroyed")
        ]]
    ),
    rule!(
        "CAP-MINER",
        "cryptocurrency mining",
        "impact/resource-hijacking",
        High,
        ["T1496"],
        [[
            Str("stratum+tcp://"),
            Str("stratum+ssl://"),
            Str("xmrig"),
            Str("cryptonight"),
            Str("--donate-level"),
            Str("randomx")
        ]]
    ),
    // ── defence evasion
    rule!(
        "CAP-DYN-RESOLVE",
        "resolve APIs dynamically",
        "anti-analysis/obfuscation",
        Low,
        ["T1027.007"],
        [
            [
                Api("GetProcAddress"),
                Api("dlsym"),
                Api("LdrGetProcedureAddress")
            ],
            [
                Api("LoadLibrary"),
                Api("LoadLibraryEx"),
                Api("GetModuleHandle"),
                Api("dlopen"),
                Api("LdrLoadDll")
            ]
        ]
    ),
    rule!(
        "CAP-MEM-PROTECT",
        "change memory protection",
        "host-interaction/memory",
        Low,
        ["T1055"],
        [[
            Api("VirtualProtect"),
            Api("VirtualProtectEx"),
            Api("NtProtectVirtualMemory"),
            Api("mprotect")
        ]]
    ),
    rule!(
        "CAP-SELF-DELETE",
        "delete itself",
        "anti-forensics/self-deletion",
        Medium,
        ["T1070.004"],
        [[
            Str("ping 127.0.0.1 -n"),
            Str("cmd /c del "),
            Str("cmd.exe /c del "),
            Str("choice /C Y /N /D Y /T")
        ]]
    ),
    rule!(
        "CAP-CLEAR-LOGS",
        "clear event logs",
        "anti-forensics/clear-logs",
        High,
        ["T1070.001"],
        [[
            Api("ClearEventLog"),
            Api("EvtClearLog"),
            Str("wevtutil cl"),
            Str("wevtutil.exe cl"),
            Str("Clear-EventLog"),
            Str("/var/log/wtmp"),
            Str("history -c")
        ]]
    ),
    rule!(
        "CAP-DISABLE-DEFENDER",
        "disable security tools",
        "defense-evasion/impair-defenses",
        High,
        ["T1562.001"],
        [[
            Str("Set-MpPreference"),
            Str("DisableAntiSpyware"),
            Str("DisableRealtimeMonitoring"),
            Str("netsh advfirewall set"),
            Str("setenforce 0"),
            Str("systemctl stop apparmor")
        ]]
    ),
    rule!(
        "CAP-PRIV-TOKEN",
        "adjust token privileges",
        "privilege-escalation/token",
        Medium,
        ["T1134"],
        [[
            Api("AdjustTokenPrivileges"),
            Str("SeDebugPrivilege"),
            Api("ImpersonateLoggedOnUser"),
            Api("DuplicateTokenEx")
        ]]
    ),
    rule!(
        "CAP-UAC-BYPASS",
        "bypass UAC",
        "privilege-escalation/uac-bypass",
        High,
        ["T1548.002"],
        [[
            Str("ms-settings\\shell\\open\\command"),
            Str("mscfile\\shell\\open\\command"),
            Str("fodhelper.exe"),
            Str("ICMLuaUtil")
        ]]
    ),
    rule!(
        "CAP-SETUID",
        "change user id to root",
        "privilege-escalation/setuid",
        Low,
        ["T1548.001"],
        [
            [Api("setuid"), Api("setreuid"), Api("setresuid")],
            [
                Api("setgid"),
                Api("setregid"),
                Api("setresgid"),
                Api("setuid")
            ]
        ]
    ),
];

/// Inputs to the matcher.
pub struct Evidence<'a> {
    /// Import names (case-sensitive as found).
    pub imports: &'a [String],
    /// Extracted strings.
    pub strings: &'a [String],
    /// Whole file.
    pub data: &'a [u8],
}

fn api_matches(name: &str, want: &str) -> bool {
    let n = name.trim_start_matches('_');
    n == want
        || n.strip_suffix('A') == Some(want)
        || n.strip_suffix('W') == Some(want)
        || n.strip_prefix("Zw")
            .is_some_and(|r| want.strip_prefix("Nt") == Some(r))
}

fn feature_hit(f: &Feat, ev: &Evidence, lower_strings: &[String]) -> Option<String> {
    match f {
        Api(want) => {
            if let Some(i) = ev.imports.iter().find(|i| api_matches(i, want)) {
                return Some(format!("api: {i}"));
            }
            // API names present as strings → resolved at runtime by name.
            ev.strings
                .iter()
                .find(|s| api_matches(s.trim(), want))
                .map(|s| format!("api (by name): {}", s.trim()))
        }
        Str(needle) => {
            let n = needle.to_ascii_lowercase();
            lower_strings
                .iter()
                .position(|s| s.contains(&n))
                .map(|i| format!("string: {}", truncate(&ev.strings[i], 100)))
        }
        Bytes(b) => memchr::memmem::find(ev.data, b).map(|off| {
            format!(
                "bytes at {off:#x}: {}",
                rex_core::hash::hex(&b[..b.len().min(8)])
            )
        }),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// Evaluate all built-in rules.
pub fn detect(ev: &Evidence) -> Vec<Capability> {
    let lower: Vec<String> = ev.strings.iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut out = Vec::new();
    for r in RULES {
        let mut evidence = Vec::new();
        let ok = r.groups.iter().all(|g| {
            let hits: Vec<String> = g
                .iter()
                .filter_map(|f| feature_hit(f, ev, &lower))
                .collect();
            let any = !hits.is_empty();
            evidence.extend(hits.into_iter().take(3));
            any
        });
        if ok {
            evidence.sort();
            evidence.dedup();
            out.push(Capability {
                id: r.id,
                name: r.name,
                namespace: r.namespace,
                severity: r.severity,
                attack: r.attack.to_vec(),
                evidence,
            });
        }
    }
    // Embedded executables (droppers): a second DOS stub or ELF header past the start.
    let stub = b"This program cannot be run in DOS mode";
    let n = memchr::memmem::find_iter(ev.data, stub).count();
    if n > 1 {
        out.push(Capability {
            id: "CAP-EMBEDDED-PE",
            name: "contains embedded PE file(s)",
            namespace: "executable/embedded",
            severity: Severity::Medium,
            attack: vec!["T1027.009"],
            evidence: vec![format!("{} DOS stubs found", n)],
        });
    }
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.namespace.cmp(b.namespace))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_requires_all_groups() {
        let imports = vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
        ];
        let ev = Evidence {
            imports: &imports,
            strings: &[],
            data: &[],
        };
        assert!(
            !detect(&ev)
                .iter()
                .any(|c| c.id == "CAP-INJECT-REMOTE-THREAD")
        );
        let imports = vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
            "CreateRemoteThread".to_string(),
        ];
        let ev = Evidence {
            imports: &imports,
            strings: &[],
            data: &[],
        };
        let caps = detect(&ev);
        let c = caps
            .iter()
            .find(|c| c.id == "CAP-INJECT-REMOTE-THREAD")
            .unwrap();
        assert_eq!(c.attack, vec!["T1055"]);
        assert_eq!(c.evidence.len(), 3);
    }

    #[test]
    fn suffixes_and_dynamic_names() {
        assert!(api_matches("ShellExecuteW", "ShellExecute"));
        assert!(api_matches("_ptrace", "ptrace"));
        assert!(api_matches("ZwUnmapViewOfSection", "NtUnmapViewOfSection"));
        assert!(!api_matches("CreateProcessInternal", "CreateProcess"));
        let strings = vec!["IsDebuggerPresent".to_string()];
        let ev = Evidence {
            imports: &[],
            strings: &strings,
            data: &[],
        };
        assert!(detect(&ev).iter().any(|c| c.id == "CAP-ANTI-DEBUG-WIN"));
    }

    #[test]
    fn strings_and_bytes() {
        let strings = vec![
            "C:\\x\\YOUR FILES ARE ENCRYPTED".to_string(),
            "vssadmin delete shadows /all".into(),
        ];
        let data = [
            0u8, 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe,
            0xd7, 0xab, 0x76,
        ];
        let ev = Evidence {
            imports: &[],
            strings: &strings,
            data: &data,
        };
        let ids: Vec<_> = detect(&ev).iter().map(|c| c.id).collect();
        assert!(ids.contains(&"CAP-RANSOM-NOTE"));
        assert!(ids.contains(&"CAP-RANSOM-RECOVERY"));
        assert!(ids.contains(&"CAP-AES-CONST"));
        assert_eq!(
            ids[0..2]
                .iter()
                .filter(|i| i.starts_with("CAP-RANSOM"))
                .count(),
            2,
            "critical first"
        );
    }

    #[test]
    fn rule_ids_unique() {
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(n, ids.len());
    }
}
