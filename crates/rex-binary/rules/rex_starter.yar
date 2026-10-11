// rex starter YARA rules. Deliberately generic, low-false-positive heuristics.
// Add your own with `rex scan --rules <dir>`.

rule rex_upx_packed
{
    meta:
        description = "UPX packed executable"
        severity = "medium"
    strings:
        $a = "UPX!"
        $b = "UPX0"
        $c = "UPX1"
    condition:
        2 of them
}

rule rex_embedded_pe
{
    meta:
        description = "Contains more than one MZ/PE stub (possible dropper)"
        severity = "medium"
    strings:
        $dos = "This program cannot be run in DOS mode"
    condition:
        #dos > 1
}

rule rex_powershell_encoded
{
    meta:
        description = "Encoded PowerShell command line"
        severity = "high"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "FromBase64String" nocase
    condition:
        $a and ($b or $c)
}

rule rex_shadow_copy_deletion
{
    meta:
        description = "Deletes Volume Shadow Copies (ransomware behaviour)"
        severity = "critical"
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "wbadmin delete catalog" nocase
    condition:
        any of them
}

rule rex_private_key
{
    meta:
        description = "Embedded private key"
        severity = "high"
    strings:
        $a = "-----BEGIN RSA PRIVATE KEY-----"
        $b = "-----BEGIN PRIVATE KEY-----"
        $c = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $d = "-----BEGIN EC PRIVATE KEY-----"
    condition:
        any of them
}

rule rex_xmrig_miner
{
    meta:
        description = "XMRig / Monero miner strings"
        severity = "high"
    strings:
        $a = "stratum+tcp://" nocase
        $b = "xmrig" nocase
        $c = "--donate-level" nocase
    condition:
        2 of them
}
