const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub const StringClass = enum {
    url,
    ip_address,
    ipv6_address,
    windows_path,
    registry_key,
    shell_command,
    crypto_key,
    email,
    unix_path,
    jwt_token,
    base64_block,
    hex_string,
    unclassified,
};

pub const StringFinding = struct {
    offset: usize,
    value: []const u8,
    classification: StringClass,
    severity: u8,
    description: []const u8 = "",
};

pub const StringAnalysis = struct {
    findings: []StringFinding,
    total_strings: usize,
    url_count: usize,
    ip_count: usize,
    path_count: usize,
    registry_count: usize,
    shell_count: usize,
    crypto_key_count: usize,
    email_count: usize,
    jwt_count: usize,
    base64_count: usize,
    interesting_ratio: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        for (self.findings) |f| {
            allocator.free(f.value);
        }
        allocator.free(self.findings);
    }
};

const min_ascii_len = 4;
const max_str_len = 1024;

pub fn analyzeStrings(allocator: Allocator, bytes: []const u8) !StringAnalysis {
    var findings = std.ArrayList(StringFinding).init(allocator);
    errdefer {
        for (findings.items) |f| allocator.free(f.value);
        findings.deinit();
    }

    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    var url_count: usize = 0;
    var ip_count: usize = 0;
    var path_count: usize = 0;
    var registry_count: usize = 0;
    var shell_count: usize = 0;
    var crypto_key_count: usize = 0;
    var email_count: usize = 0;
    var jwt_count: usize = 0;
    var base64_count: usize = 0;
    var total: usize = 0;

    {
        var i: usize = 0;
        while (i < bytes.len) {
            if (bytes[i] >= 32 and bytes[i] < 127) {
                const start = i;
                while (i < bytes.len and bytes[i] >= 32 and bytes[i] < 127) {
                    i += 1;
                }
                const len = i - start;
                if (len >= min_ascii_len and len <= max_str_len) {
                    const s = bytes[start..i];
                    if ((try classifyAndAppend(allocator, &findings, &seen, s, start, &url_count, &ip_count, &path_count, &registry_count, &shell_count, &crypto_key_count, &email_count, &jwt_count, &base64_count))) {
                        total += 1;
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    {
        var i: usize = 0;
        while (i + 1 < bytes.len) {
            if (bytes[i] != 0 and bytes[i + 1] == 0 and bytes[i] >= 32 and bytes[i] < 127) {
                const start = i;
                var run_len: usize = 0;
                while (i + 1 < bytes.len and bytes[i] >= 32 and bytes[i] < 127 and bytes[i + 1] == 0) {
                    run_len += 1;
                    i += 2;
                }
                if (run_len >= min_ascii_len) {
                    var u8_buf: [max_str_len]u8 = undefined;
                    var j: usize = 0;
                    while (j < run_len and j < max_str_len) {
                        u8_buf[j] = bytes[start + j * 2];
                        j += 1;
                    }
                    const s = u8_buf[0..j];
                    if ((try classifyAndAppend(allocator, &findings, &seen, s, start, &url_count, &ip_count, &path_count, &registry_count, &shell_count, &crypto_key_count, &email_count, &jwt_count, &base64_count))) {
                        total += 1;
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    const ratio = if (total > 0) @as(f64, @floatFromInt(findings.items.len)) / @as(f64, @floatFromInt(total)) * 100.0 else 0.0;

    return .{
        .findings = try findings.toOwnedSlice(),
        .total_strings = total,
        .url_count = url_count,
        .ip_count = ip_count,
        .path_count = path_count,
        .registry_count = registry_count,
        .shell_count = shell_count,
        .crypto_key_count = crypto_key_count,
        .email_count = email_count,
        .jwt_count = jwt_count,
        .base64_count = base64_count,
        .interesting_ratio = ratio,
    };
}

fn classifyAndAppend(allocator: Allocator, findings: *std.ArrayList(StringFinding), seen: *std.StringHashMap(void), s: []const u8, offset: usize, url_count: *usize, ip_count: *usize, path_count: *usize, registry_count: *usize, shell_count: *usize, crypto_key_count: *usize, email_count: *usize, jwt_count: *usize, base64_count: *usize) !bool {
    if (s.len < min_ascii_len) return false;

    const class = classify(s);
    if (class == .unclassified) return true;

    const gop = try seen.getOrPut(s);
    if (gop.found_existing) return false;

    const owned = try allocator.dupe(u8, s);
    gop.key_ptr.* = owned;

    const sev = severityFor(class);
    var desc: []const u8 = "";
    switch (class) {
        .url => {
            desc = "URL found in binary";
            url_count.* += 1;
        },
        .ip_address => {
            desc = "IPv4 address hardcoded in binary";
            ip_count.* += 1;
        },
        .ipv6_address => {
            desc = "IPv6 address hardcoded in binary";
            ip_count.* += 1;
        },
        .windows_path => {
            desc = "Windows file path found in binary";
            path_count.* += 1;
        },
        .registry_key => {
            desc = "Windows Registry key found in binary";
            registry_count.* += 1;
        },
        .shell_command => {
            desc = "Shell command or interpreter invocation found";
            shell_count.* += 1;
        },
        .crypto_key => {
            desc = "Potential cryptographic key or certificate material found";
            crypto_key_count.* += 1;
        },
        .email => {
            desc = "Email address found in binary";
            email_count.* += 1;
        },
        .unix_path => {
            desc = "Unix file path found in binary";
            path_count.* += 1;
        },
        .jwt_token => {
            desc = "JWT token found in binary";
            jwt_count.* += 1;
        },
        .base64_block => {
            desc = "Potential base64-encoded data found";
            base64_count.* += 1;
        },
        .hex_string => {
            desc = "Hex string (potential hash or key material) found";
            crypto_key_count.* += 1;
        },
        .unclassified => {},
    }

    try findings.append(.{
        .offset = offset,
        .value = owned,
        .classification = class,
        .severity = sev,
        .description = desc,
    });
    return true;
}

fn classify(s: []const u8) StringClass {
    if (s.len < 4) return .unclassified;

    if (isJwt(s)) return .jwt_token;
    if (isUrl(s)) return .url;
    if (isEmail(s)) return .email;
    if (isIpv6(s)) return .ipv6_address;
    if (isIpv4(s)) return .ip_address;
    if (isRegistryKey(s)) return .registry_key;
    if (isWindowsPath(s)) return .windows_path;
    if (isShellCommand(s)) return .shell_command;
    if (isUnixPath(s)) return .unix_path;
    if (isCryptoKey(s)) return .crypto_key;
    if (isBase64Block(s)) return .base64_block;
    if (isHexString(s)) return .hex_string;

    return .unclassified;
}

fn isUrl(s: []const u8) bool {
    if (containsIcc(s, "http://") or containsIcc(s, "https://") or
        containsIcc(s, "ftp://") or containsIcc(s, "ws://") or containsIcc(s, "wss://"))
    {
        if (std.mem.indexOf(u8, s, "://")) |pos| {
            const rest = s[pos + 3 ..];
            if (rest.len >= 3 and std.mem.indexOfAny(u8, rest, ".") != null) return true;
        }
    }
    if (s.len >= 6 and startsWithIcc(s, "www.")) {
        if (std.mem.indexOf(u8, s, ".") != null) return true;
    }
    return false;
}

fn isEmail(s: []const u8) bool {
    if (s.len < 6) return false;
    if (countChar(s, '@') != 1) return false;
    const at_pos = std.mem.indexOfScalar(u8, s, '@') orelse return false;
    if (at_pos < 1 or at_pos > s.len - 5) return false;
    const local = s[0..at_pos];
    const domain = s[at_pos + 1 ..];
    if (domain.len < 4) return false;
    if (std.mem.indexOf(u8, domain, ".") == null) return false;
    for (local) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '_' and c != '-' and c != '+') return false;
    }
    if (local.len > 64) return false;
    const dot_pos = std.mem.lastIndexOfScalar(u8, domain, '.') orelse return false;
    const tld = domain[dot_pos + 1 ..];
    if (tld.len < 2 or tld.len > 6) return false;
    for (tld) |c| {
        if (!std.ascii.isAlphabetic(c)) return false;
    }
    return true;
}

fn isIpv4(s: []const u8) bool {
    var dots: u8 = 0;
    var seg_start: usize = 0;
    var i: usize = 0;
    while (i <= s.len) {
        if (i == s.len or s[i] == '.') {
            if (i == seg_start) return false;
            const seg_len = i - seg_start;
            if (seg_len > 3) return false;
            const seg_str = s[seg_start..i];
            const val = std.fmt.parseInt(u8, seg_str, 10) catch return false;
            _ = val;
            if (i < s.len) dots += 1;
            seg_start = i + 1;
        } else if (s[i] < '0' or s[i] > '9') {
            return false;
        }
        i += 1;
    }
    return dots == 3;
}

fn isIpv6(s: []const u8) bool {
    var colons: u8 = 0;
    var has_double_colon = false;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == ':') {
            if (i + 1 < s.len and s[i + 1] == ':') {
                has_double_colon = true;
                i += 2;
                continue;
            }
            colons += 1;
        } else if (!std.ascii.isHex(s[i])) {
            return false;
        }
        i += 1;
    }
    return (colons >= 2 and colons <= 7) or has_double_colon;
}

fn isWindowsPath(s: []const u8) bool {
    if (s.len < 4) return false;

    if (s.len >= 3 and std.ascii.isAlphabetic(s[0]) and s[1] == ':' and (s[2] == '\\' or s[2] == '/')) return true;

    if (std.mem.startsWith(u8, s, "\\\\")) return true;

    if (s.len >= 6 and std.mem.indexOf(u8, s, "\\") != null) {
        const known = [_][]const u8{
            "Windows\\", "Program Files", "System32", "\\Temp\\",
            "\\Users\\", "\\AppData\\", "\\ProgramData\\", "\\Windows\\",
        };
        for (known) |k| {
            if (containsIcc(s, k)) return true;
        }
    }

    if (s.len >= 6 and (containsIcc(s, ".exe") or containsIcc(s, ".dll") or containsIcc(s, ".sys") or containsIcc(s, ".bat"))) {
        if (std.mem.indexOfAny(u8, s, "\\/") != null) return true;
    }

    return false;
}

fn isRegistryKey(s: []const u8) bool {
    if (std.mem.startsWith(u8, s, "HKEY_") or
        std.mem.startsWith(u8, s, "HKLM") or
        std.mem.startsWith(u8, s, "HKCU") or
        std.mem.startsWith(u8, s, "HKCR") or
        std.mem.startsWith(u8, s, "HKU") or
        std.mem.startsWith(u8, s, "HKCC"))
    {
        return true;
    }
    if (std.mem.indexOf(u8, s, "SOFTWARE\\") != null and
        std.mem.indexOf(u8, s, "\\") != null)
    {
        return true;
    }
    if (std.mem.indexOf(u8, s, "\\Registry\\") != null) return true;
    return false;
}

fn isShellCommand(s: []const u8) bool {
    const shell_indicators = [_][]const u8{
        "cmd.exe", "cmd /c", "powershell", "pwsh",
        "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash",
        "wscript", "cscript", "mshta",
        "rundll32", "regsvr32", "wmic", "msiexec", "schtasks",
        "system(", "exec(", "popen", "subprocess", "shell_exec",
        "CreateProcess", "WinExec", "ShellExecute",
    };
    for (shell_indicators) |indicator| {
        if (containsIcc(s, indicator)) return true;
    }
    if (s.len > 4 and (std.mem.startsWith(u8, s, "#!") or containsIcc(s, "#!/"))) return true;
    if (std.mem.indexOf(u8, s, "&&") != null or
        std.mem.indexOf(u8, s, "||") != null or
        std.mem.indexOf(u8, s, "| ") != null)
    {
        return true;
    }
    return false;
}

fn isCryptoKey(s: []const u8) bool {
    const indicators = [_][]const u8{
        "-----begin ", "-----end ",
        "private key", "public key", "rsa ", "ecdsa", "aes-",
        "-----begin rsa", "ssh-rsa", "ssh-ed25519",
        "pgp ", "-----begin pgp",
    };
    for (indicators) |indicator| {
        if (containsIcc(s, indicator)) return true;
    }
    if (s.len >= 512 and (std.mem.indexOf(u8, s, "MII") != null or
        std.mem.indexOf(u8, s, "MI") != null and s.len > 200))
    {
        const b64_chars = countIf(s, isBase64Char);
        if (@as(f64, @floatFromInt(b64_chars)) / @as(f64, @floatFromInt(s.len)) > 0.85) {
            return true;
        }
    }
    return false;
}

fn isBase64Block(s: []const u8) bool {
    if (s.len < 28) return false;
    if (s.len % 4 != 0) return false;
    const b64_chars = countIf(s, isBase64Char);
    if (@as(f64, @floatFromInt(b64_chars)) / @as(f64, @floatFromInt(s.len)) < 0.95) return false;
    var digit_count: usize = 0;
    var upper_count: usize = 0;
    for (s) |c| {
        if (std.ascii.isDigit(c)) digit_count += 1;
        if (std.ascii.isUpper(c)) upper_count += 1;
    }
    if (digit_count == 0 and upper_count == 0) return false;
    return true;
}

fn isHexString(s: []const u8) bool {
    if (s.len < 8) return false;
    const hex_chars = countIf(s, std.ascii.isHex);
    if (@as(f64, @floatFromInt(hex_chars)) / @as(f64, @floatFromInt(s.len)) > 0.95) {
        return true;
    }
    return false;
}

fn isJwt(s: []const u8) bool {
    if (s.len < 16) return false;
    const dots = countChar(s, '.');
    if (dots != 2) return false;
    var parts = std.mem.splitScalar(u8, s, '.');
    var part_count: usize = 0;
    while (parts.next()) |part| {
        part_count += 1;
        if (part.len == 0) return false;
        for (part) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') {
                return false;
            }
        }
    }
    return part_count == 3;
}

fn isUnixPath(s: []const u8) bool {
    if (s.len < 4) return false;
    if (std.mem.startsWith(u8, s, "/") or std.mem.startsWith(u8, s, "./") or std.mem.startsWith(u8, s, "../")) {
        if (std.mem.indexOf(u8, s[1..], "/") != null) return true;
    }
    if (std.mem.indexOf(u8, s, "/usr/") != null or
        std.mem.indexOf(u8, s, "/etc/") != null or
        std.mem.indexOf(u8, s, "/var/") != null or
        std.mem.indexOf(u8, s, "/tmp/") != null or
        std.mem.indexOf(u8, s, "/home/") != null or
        std.mem.indexOf(u8, s, "/opt/") != null or
        std.mem.indexOf(u8, s, "/bin/") != null)
    {
        return true;
    }
    return false;
}

fn severityFor(class: StringClass) u8 {
    return switch (class) {
        .crypto_key => 75,
        .jwt_token => 70,
        .shell_command => 65,
        .email => 50,
        .url => 45,
        .ip_address => 55,
        .ipv6_address => 55,
        .registry_key => 50,
        .windows_path => 40,
        .unix_path => 35,
        .base64_block => 45,
        .hex_string => 50,
        .unclassified => 0,
    };
}

fn containsIcc(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const end = haystack.len - needle.len;
    var i: usize = 0;
    while (i <= end) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn startsWithIcc(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..needle.len], needle);
}

fn countChar(s: []const u8, c: u8) usize {
    var count: usize = 0;
    for (s) |ch| {
        if (ch == c) count += 1;
    }
    return count;
}

fn countIf(s: []const u8, pred: fn (u8) bool) usize {
    var count: usize = 0;
    for (s) |ch| {
        if (pred(ch)) count += 1;
    }
    return count;
}

fn isBase64Char(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '+' or c == '/' or c == '=';
}
