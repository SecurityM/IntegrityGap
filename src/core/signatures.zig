const std = @import("std");
const types = @import("../types.zig");
const utils = @import("utils.zig");

const CallCategory = types.CallCategory;
const CallRole = types.CallRole;
const ImportSymbol = types.ImportSymbol;

pub fn addScannedKnownImports(imports: *std.ArrayList(ImportSymbol), bytes: []const u8) !void {
    const known = [_][]const u8{
        "socket", "connect", "send", "recv", "WSAStartup", "WSASocketA", "InternetOpenA", "InternetConnectA",
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "DeleteFileA", "DeleteFileW",
        "malloc", "calloc", "realloc", "free", "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree",
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegCloseKey",
        "CreateProcessA", "CreateProcessW", "OpenProcess", "WriteProcessMemory", "CreateRemoteThread",
        "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt", "CryptReleaseContext",
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt", "BCryptCloseAlgorithmProvider",
        "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex", "EVP_CIPHER_CTX_free",
        "syslog", "ReportEventA", "ReportEventW", "EventWrite", "OutputDebugStringA", "OutputDebugStringW",
        "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf",
        "EnterCriticalSection", "LeaveCriticalSection", "InitializeCriticalSection",
        "CreateThread", "pthread_create", "pthread_mutex_lock", "pthread_mutex_unlock",
        "WaitForSingleObject", "WaitForMultipleObjects", "SetEvent", "ResetEvent", "CreateEventA",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "dlopen", "dlsym",
        "NtCreateFile", "NtOpenFile", "NtWriteFile", "NtReadFile", "NtClose",
        "NtCreateProcess", "NtOpenProcess", "NtCreateThread", "NtOpenThread",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory",
        "SetWindowsHookExA", "SetWindowsHookExW", "CallNextHookEx",
        "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow", "GetWindowTextA",
        "NtQueryInformationProcess", "NtSetInformationProcess",
        "MiniDumpWriteDump", "DbgHelp", "dbghelp",
        "CoInitializeEx", "CoInitializeSecurity", "CoCreateInstance",
        "gets", "scanf", "fscanf", "vsprintf", "wcscpy", "wcscat",
        "GetTempPathA", "GetTempFileNameA", "MoveFileExA",
        "WmiOpenBlock", "WmiReceiveNotifications", "WmiExecuteQuery",
    };
    for (known) |name| {
        if (std.mem.indexOf(u8, bytes, name) != null) {
            try appendImportUnique(imports, name, "", 0);
        }
    }
}

fn appendImportUnique(imports: *std.ArrayList(ImportSymbol), name: []const u8, dll: []const u8, iat_va: u64) !void {
    for (imports.items) |existing| {
        if (utils.asciiEqlIgnoreCase(existing.name, name)) return;
    }
    try imports.append(.{ .name = name, .dll = dll, .iat_va = iat_va });
}

pub fn categorizeCall(name: []const u8) CallCategory {
    if (name.len == 0 or utils.asciiEqlIgnoreCase(name, "direct_call") or utils.asciiEqlIgnoreCase(name, "indirect_call")) return .generic;
    if (utils.containsAny(name, &.{ "socket", "connect", "send", "recv", "internet", "http", "winhttp", "curl", "dns", "wsa", "ntreadfile", "ntwritefile", "ntcreatefile" })) return .network;
    if (utils.containsAny(name, &.{ "file", "fopen", "open", "read", "write", "deletefile", "copyfile", "movefile", "closehandle", "ntopenfile", "ntcreatefile" })) return .file;
    if (utils.containsAny(name, &.{ "malloc", "calloc", "realloc", "free", "heap", "virtualalloc", "virtualfree", "localalloc", "localfree", "mmap", "munmap", "ntallocatevirtualmemory", "ntfreevirtualmemory" })) return .memory;
    if (utils.containsAny(name, &.{ "crypt", "bcrypt", "evp_", "aes", "rsa", "sha", "cipher", "encrypt", "decrypt", "hash", "hmac" })) return .crypto;
    if (utils.containsAny(name, &.{ "regopen", "regset", "regquery", "regclose", "registry", "RegCreateKey", "RegDeleteKey" })) return .registry;
    if (utils.containsAny(name, &.{ "createprocess", "openprocess", "writeprocessmemory", "createremotethread", "exec", "fork", "system", "ntcreateprocess", "ntopenthread", "ntcreatethread" })) return .process;
    if (utils.containsAny(name, &.{ "syslog", "reportevent", "eventwrite", "outputdebugstring", "log_" }) or utils.asciiContainsIgnoreCase(name, "logger")) return .logging;
    if (utils.containsAny(name, &.{ "cleanup", "close", "destroy", "release" })) return .cleanup;
    if (utils.containsAny(name, &.{ "EnterCriticalSection", "LeaveCriticalSection", "pthread_mutex", "pthread_rwlock", "pthread_spin", "ReleaseMutex", "WaitForSingleObject", "Interlocked" })) return .synchronization;
    if (utils.containsAny(name, &.{ "CreateThread", "pthread_create", "_beginthreadex", "CreateRemoteThread" })) return .threading;
    if (utils.containsAny(name, &.{ "serialize", "marshal", "pack", "unpack", "binary_reader", "binary_writer" })) return .serialization;
    return .generic;
}

pub fn callRole(name: []const u8, category: CallCategory) CallRole {
    if (category == .crypto) {
        if (utils.containsAny(name, &.{ "init", "open", "acquire" })) return .crypto_init;
        if (utils.containsAny(name, &.{ "final", "finish" })) return .crypto_final;
        if (utils.containsAny(name, &.{ "destroy", "free", "close", "release" })) return .crypto_destroy;
        return .crypto_op;
    }
    if (category == .synchronization) {
        if (utils.containsAny(name, &.{ "EnterCriticalSection", "Lock", "lock", "WaitForSingleObject", "Wait", "pthread_mutex_lock", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_spin_lock" })) return .lock_acquire;
        if (utils.containsAny(name, &.{ "LeaveCriticalSection", "Unlock", "unlock", "ReleaseMutex", "pthread_mutex_unlock", "pthread_rwlock_unlock", "pthread_spin_unlock" })) return .lock_release;
        return .neutral;
    }
    if (category == .threading) {
        if (utils.containsAny(name, &.{ "CreateThread", "pthread_create", "_beginthreadex", "CreateRemoteThread" })) return .thread_create;
        if (utils.containsAny(name, &.{ "pthread_join", "WaitForSingleObject", "WaitForMultipleObjects" })) return .thread_join;
        return .neutral;
    }
    if (utils.containsAny(name, &.{ "malloc", "calloc", "realloc", "alloc", "open", "create", "socket", "connect", "acquire", "mmap", "HeapAlloc", "VirtualAlloc" })) return .acquire;
    if (utils.containsAny(name, &.{ "free", "close", "destroy", "release", "closesocket", "munmap", "HeapFree", "VirtualFree" })) return .release;
    return .neutral;
}

pub const SuspiciousSignature = struct {
    name: []const u8,
    severity: u8,
    category: CallCategory,
    description: []const u8,
    cwe: u32,
};

pub const known_suspicious_patterns = [_]SuspiciousSignature{
    .{ .name = "CreateRemoteThread", .severity = 95, .category = .process, .description = "Remote thread creation in external process", .cwe = 749 },
    .{ .name = "WriteProcessMemory", .severity = 95, .category = .process, .description = "Writing memory to external process", .cwe = 749 },
    .{ .name = "SetWindowsHookEx", .severity = 85, .category = .process, .description = "Global Windows hook installation", .cwe = 506 },
    .{ .name = "MiniDumpWriteDump", .severity = 90, .category = .process, .description = "Process memory dumping for credential theft", .cwe = 524 },
    .{ .name = "GetAsyncKeyState", .severity = 80, .category = .process, .description = "Keystroke monitoring API", .cwe = 778 },
    .{ .name = "NtSetInformationProcess", .severity = 70, .category = .process, .description = "NT process manipulation", .cwe = 250 },
    .{ .name = "VirtualAllocEx", .severity = 85, .category = .memory, .description = "Remote memory allocation in external process", .cwe = 749 },
    .{ .name = "NtProtectVirtualMemory", .severity = 80, .category = .memory, .description = "Memory protection changes via NT API", .cwe = 250 },
    .{ .name = "QueueUserAPC", .severity = 85, .category = .process, .description = "APC injection into threads", .cwe = 749 },
    .{ .name = "SetThreadContext", .severity = 90, .category = .process, .description = "Thread context manipulation", .cwe = 749 },
    .{ .name = "Wow64SetThreadContext", .severity = 90, .category = .process, .description = "64-bit thread context manipulation", .cwe = 749 },
    .{ .name = "NtUnmapViewOfSection", .severity = 80, .category = .process, .description = "Process hollowing technique", .cwe = 749 },
    .{ .name = "NtCreateThreadEx", .severity = 85, .category = .process, .description = "NT-level thread creation", .cwe = 749 },
    .{ .name = "CryptUnprotectData", .severity = 60, .category = .crypto, .description = "Data unprotection for credential theft", .cwe = 312 },
    .{ .name = "WmiExecuteQuery", .severity = 65, .category = .process, .description = "WMI query for reconnaissance", .cwe = 200 },
};

pub fn detectLoggingPresent(bytes: []const u8, imports: []const ImportSymbol) bool {
    for (imports) |imp| {
        if (categorizeCall(imp.name) == .logging) return true;
    }
    for (known_suspicious_patterns) |pattern| {
        if (utils.asciiContainsIgnoreCase(bytes, pattern.name)) {
            if (pattern.category == .logging) return true;
        }
    }
    return std.mem.indexOf(u8, bytes, "logger") != null or
        std.mem.indexOf(u8, bytes, "audit") != null or
        std.mem.indexOf(u8, bytes, "syslog") != null or
        std.mem.indexOf(u8, bytes, "log_file") != null or
        std.mem.indexOf(u8, bytes, "EventWrite") != null;
}

pub fn isHighRiskCategory(category: CallCategory) bool {
    return switch (category) {
        .network, .file, .crypto, .registry, .process, .threading => true,
        else => false,
    };
}

pub fn isCriticalReturnCall(category: CallCategory, role: CallRole) bool {
    return isHighRiskCategory(category) or
        role == .acquire or
        role == .crypto_init or
        role == .crypto_op or
        role == .lock_acquire or
        category == .memory or
        category == .synchronization;
}

pub fn isCopyLike(name: []const u8) bool {
    return utils.containsAny(name, &.{ "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "readfile", "recv", "read", "wcscpy", "wcscat", "strcat" });
}

pub fn detectAntiDebug(bytes: []const u8) bool {
    const patterns = [_][]const u8{
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugString", "CloseHandle", "SetUnhandledExceptionFilter",
        "NtClose", "NtSetInformationThread", "ZwQueryInformationProcess",
        "GetTickCount", "QueryPerformanceCounter", "rdtsc",
    };
    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern) != null) return true;
    }
    return false;
}

pub fn detectPackedBinary(bytes: []const u8, image: types.BinaryImage) bool {
    if (image.imports.len < 5) return true;
    var found_getproc = false;
    var found_loadlib = false;
    for (image.imports) |imp| {
        if (utils.asciiContainsIgnoreCase(imp.name, "GetProcAddress")) found_getproc = true;
        if (utils.asciiContainsIgnoreCase(imp.name, "LoadLibrary")) found_loadlib = true;
        if (utils.asciiContainsIgnoreCase(imp.name, "VirtualAlloc")) {
            if (found_getproc and found_loadlib) return true;
        }
    }
    const entropy = calculateEntropy(bytes);
    return entropy > 6.5;
}

pub fn calculateEntropy(bytes: []const u8) f64 {
    if (bytes.len == 0) return 0;
    var freq: [256]usize = [_]usize{0} ** 256;
    for (bytes) |byte| freq[byte] += 1;
    var entropy: f64 = 0;
    const inv_len = 1.0 / @as(f64, @floatFromInt(bytes.len));
    for (freq) |count| {
        if (count == 0) continue;
        const p = @as(f64, @floatFromInt(count)) * inv_len;
        entropy -= p * @log2(p);
    }
    return entropy;
}
