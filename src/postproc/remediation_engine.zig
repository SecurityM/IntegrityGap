const std = @import("std");
const types = @import("../types.zig");
const cvss_scorer = @import("cvss_scorer.zig");

const Allocator = types.Allocator;

pub const RemediationPriority = enum {
    immediate,
    short_term,
    medium_term,
    long_term,
    informational,
};

pub const RemediationCategory = enum {
    code_change,
    configuration_change,
    dependency_update,
    compiler_flag,
    architectural_change,
    process_change,
    monitoring_addition,
};

pub const RemediationSuggestion = struct {
    finding_address: u64,
    category: []const u8,
    priority: RemediationPriority,
    remediation_category: RemediationCategory,
    title: []const u8,
    description: []const u8,
    effort_hours: u32,
    code_example: []const u8 = "",
    references: []const []const u8 = &[_][]const u8{},
    cvss_score: f64 = 0,
    cwe_id: u32 = 0,
};

pub const RemediationReport = struct {
    suggestions: []RemediationSuggestion,
    immediate_count: usize,
    short_term_count: usize,
    total_effort_hours: usize,
    critical_remediations: usize,
    high_remediations: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.suggestions);
    }
};

fn categorizePriority(severity: u8) RemediationPriority {
    if (severity >= 85) return .immediate;
    if (severity >= 65) return .short_term;
    if (severity >= 40) return .medium_term;
    if (severity >= 20) return .long_term;
    return .informational;
}

fn categorizeRemediationType(category: []const u8) RemediationCategory {
    if (std.mem.eql(u8, category, "error_handling")) return .code_change;
    if (std.mem.eql(u8, category, "resource_lifecycle") or std.mem.eql(u8, category, "resource_leak")) return .code_change;
    if (std.mem.eql(u8, category, "input_validation")) return .code_change;
    if (std.mem.eql(u8, category, "cryptographic") or std.mem.eql(u8, category, "crypto")) return .code_change;
    if (std.mem.eql(u8, category, "logging") or std.mem.eql(u8, category, "audit")) return .code_change;
    if (std.mem.eql(u8, category, "concurrency")) return .code_change;
    if (std.mem.eql(u8, category, "memory_safety")) return .compiler_flag;
    if (std.mem.eql(u8, category, "config") or std.mem.eql(u8, category, "configuration")) return .configuration_change;
    if (std.mem.eql(u8, category, "dependency") or std.mem.eql(u8, category, "supply_chain")) return .dependency_update;
    if (std.mem.eql(u8, category, "privacy")) return .process_change;
    if (std.mem.eql(u8, category, "compliance")) return .process_change;
    if (std.mem.eql(u8, category, "packed_binary")) return .process_change;
    if (std.mem.eql(u8, category, "anti_debug")) return .code_change;
    return .code_change;
}

fn estimateEffort(category: []const u8, severity: u8) u32 {
    const base = if (severity >= 80) 16 else if (severity >= 60) 8 else if (severity >= 40) 4 else 2;
    if (std.mem.eql(u8, category, "cryptographic") or std.mem.eql(u8, category, "crypto")) return base * 3;
    if (std.mem.eql(u8, category, "concurrency")) return base * 2;
    if (std.mem.eql(u8, category, "compliance")) return base * 2;
    if (std.mem.eql(u8, category, "memory_safety")) return base;
    if (std.mem.eql(u8, category, "config") or std.mem.eql(u8, category, "configuration")) return @divTrunc(base, 2);
    if (std.mem.eql(u8, category, "dependency")) return @divTrunc(base, 2);
    return base;
}

fn buildRemediationTitle(category: []const u8, severity: u8) []const u8 {
    _ = severity;
    if (std.mem.eql(u8, category, "error_handling")) return "Add return value validation for critical calls";
    if (std.mem.eql(u8, category, "resource_lifecycle") or std.mem.eql(u8, category, "resource_leak")) return "Ensure balanced resource acquisition and release";
    if (std.mem.eql(u8, category, "input_validation")) return "Add input validation before pointer dereference";
    if (std.mem.eql(u8, category, "cryptographic") or std.mem.eql(u8, category, "crypto")) return "Strengthen cryptographic implementation";
    if (std.mem.eql(u8, category, "logging") or std.mem.eql(u8, category, "audit")) return "Add audit logging for high-risk operations";
    if (std.mem.eql(u8, category, "concurrency")) return "Fix concurrency and synchronization issues";
    if (std.mem.eql(u8, category, "memory_safety")) return "Fix memory safety violations";
    if (std.mem.eql(u8, category, "config") or std.mem.eql(u8, category, "configuration")) return "Harden configuration settings";
    if (std.mem.eql(u8, category, "dependency") or std.mem.eql(u8, category, "supply_chain")) return "Update vulnerable dependencies";
    if (std.mem.eql(u8, category, "privacy")) return "Address privacy compliance gaps";
    if (std.mem.eql(u8, category, "packed_binary")) return "Remove packer obfuscation";
    if (std.mem.eql(u8, category, "anti_debug")) return "Remove anti-debugging mechanisms";
    if (std.mem.eql(u8, category, "api_misuse")) return "Fix API usage pattern";
    return "Review and address security finding";
}

fn buildRemediationDescription(category: []const u8, message: []const u8) []const u8 {
    _ = message;
    if (std.mem.eql(u8, category, "error_handling"))
        return "After each critical API call, check the return value before proceeding. Use if(err) patterns or SEH try/except blocks. Ensure all error paths are handled.";
    if (std.mem.eql(u8, category, "resource_lifecycle") or std.mem.eql(u8, category, "resource_leak"))
        return "Track resource handles from acquisition through release. Use RAII patterns, defer/finally blocks, or scope guards. Ensure every open/create has a matching close/release on all exit paths.";
    if (std.mem.eql(u8, category, "input_validation"))
        return "Validate all function arguments before use. Check for NULL pointers, buffer sizes, and range constraints. Use __try/__except or if guards for safety.";
    if (std.mem.eql(u8, category, "cryptographic") or std.mem.eql(u8, category, "crypto"))
        return "Use AEAD modes (AES-256-GCM, ChaCha20-Poly1305). Store keys in secure hardware or derive via PBKDF2/Argon2. Never hardcode keys. Generate random IVs per operation.";
    if (std.mem.eql(u8, category, "logging") or std.mem.eql(u8, category, "audit"))
        return "Add structured logging for authentication, authorization, data access, and configuration changes. Use syslog, EventLog, or structured logging libraries.";
    if (std.mem.eql(u8, category, "concurrency"))
        return "Use mutexes or critical sections around shared data. Acquire locks in consistent order to prevent deadlocks. Use atomic operations for simple counters.";
    if (std.mem.eql(u8, category, "memory_safety"))
        return "Replace unsafe functions with bounded alternatives (strlcpy, strlcat, snprintf). Enable compiler protections: -fstack-protector-strong, -D_FORTIFY_SOURCE=2.";
    if (std.mem.eql(u8, category, "config") or std.mem.eql(u8, category, "configuration"))
        return "Move credentials to environment variables or secret vault. Disable debug mode. Enable all security controls. Apply principle of least privilege.";
    if (std.mem.eql(u8, category, "dependency") or std.mem.eql(u8, category, "supply_chain"))
        return "Update to latest patched version. Pin dependencies with integrity hashes. Use software composition analysis tools. Remove unused dependencies.";
    if (std.mem.eql(u8, category, "privacy"))
        return "Implement consent management. Encrypt PII at rest and in transit. Apply data minimization. Provide data deletion mechanisms. Update privacy policy.";
    if (std.mem.eql(u8, category, "packed_binary"))
        return "Rebuild binary with legitimate toolchain. Packed binaries indicate obfuscation or malware. Verify source code integrity and rebuild from trusted CI.";
    if (std.mem.eql(u8, category, "anti_debug"))
        return "Remove anti-debugging and anti-analysis techniques from production builds. These impede security analysis and incident response.";
    if (std.mem.eql(u8, category, "api_misuse"))
        return "Review Microsoft/API documentation for correct usage pattern. Ensure paired APIs are called in correct order.";
    return "Review the finding in context and apply appropriate security controls.";
}

pub fn generateRemediations(allocator: Allocator, evidence: []const types.Evidence) !RemediationReport {
    var suggestions = std.ArrayList(RemediationSuggestion).init(allocator);
    errdefer suggestions.deinit();

    var imm_count: usize = 0;
    var short_count: usize = 0;
    var total_effort: usize = 0;
    var crit_count: usize = 0;
    var high_count: usize = 0;

    for (evidence) |ev| {
        const priority = categorizePriority(ev.severity);
        const rem_cat = categorizeRemediationType(ev.category);
        const effort = estimateEffort(ev.category, ev.severity);

        if (priority == .immediate) imm_count += 1;
        if (priority == .short_term) short_count += 1;
        total_effort += effort;
        if (ev.severity >= 85) crit_count += 1;
        if (ev.severity >= 70) high_count += 1;

        try suggestions.append(.{
            .finding_address = ev.address,
            .category = ev.category,
            .priority = priority,
            .remediation_category = rem_cat,
            .title = buildRemediationTitle(ev.category, ev.severity),
            .description = buildRemediationDescription(ev.category, ev.message),
            .effort_hours = effort,
            .code_example = getCodeExample(ev.category),
            .references = getReferences(ev.category),
            .cvss_score = @as(f64, @floatFromInt(ev.severity)) / 10.0,
            .cwe_id = ev.cwe_id,
        });
    }

    return .{
        .suggestions = try suggestions.toOwnedSlice(),
        .immediate_count = imm_count,
        .short_term_count = short_count,
        .total_effort_hours = total_effort,
        .critical_remediations = crit_count,
        .high_remediations = high_count,
    };
}

fn getCodeExample(category: []const u8) []const u8 {
    if (std.mem.eql(u8, category, "error_handling"))
        return "if (SomeFunction() != SUCCESS) { /* handle error */ return; }";
    if (std.mem.eql(u8, category, "resource_lifecycle") or std.mem.eql(u8, category, "resource_leak"))
        return "HANDLE h = CreateFile(...); if (h != INVALID_HANDLE_VALUE) { /* use */ CloseHandle(h); }";
    if (std.mem.eql(u8, category, "input_validation"))
        return "if (ptr == NULL || size > MAX_SIZE) return ERROR_INVALID_PARAMETER;";
    if (std.mem.eql(u8, category, "crypto") or std.mem.eql(u8, category, "cryptographic"))
        return "Generates random 16-byte IV for each encryption...";
    if (std.mem.eql(u8, category, "memory_safety"))
        return "strlcpy(dst, src, sizeof(dst)); snprintf(buf, sizeof(buf), \"%s\", input);";
    return "";
}

fn getReferences(category: []const u8) []const []const u8 {
    _ = category;
    return &[_][]const u8{};
}

pub fn prioritizeRemediations(suggestions: []RemediationSuggestion, allocator: Allocator) ![]RemediationSuggestion {
    var sorted = try allocator.alloc(RemediationSuggestion, suggestions.len);
    @memcpy(sorted, suggestions);
    std.mem.sort(RemediationSuggestion, sorted, {}, struct {
        fn less(_: void, a: RemediationSuggestion, b: RemediationSuggestion) bool {
            const ap = @intFromEnum(a.priority);
            const bp = @intFromEnum(b.priority);
            if (ap != bp) return ap < bp;
            return a.effort_hours < b.effort_hours;
        }
    }.less);
    return sorted;
}

test "remediation - priority mapping" {
    try std.testing.expect(categorizePriority(90) == .immediate);
    try std.testing.expect(categorizePriority(70) == .short_term);
    try std.testing.expect(categorizePriority(50) == .medium_term);
    try std.testing.expect(categorizePriority(10) == .informational);
}

test "remediation - generate from evidence" {
    const allocator = std.testing.allocator;
    var evidence = try allocator.alloc(types.Evidence, 2);
    defer allocator.free(evidence);
    evidence[0] = .{ .function_va = 0, .address = 0x1000, .category = "error_handling", .message = "unchecked return", .severity = 85, .cwe_id = 252 };
    evidence[1] = .{ .function_va = 0, .address = 0x2000, .category = "crypto", .message = "weak cipher", .severity = 75 };
    const report = try generateRemediations(allocator, evidence);
    defer report.deinit(allocator);
    try std.testing.expect(report.suggestions.len == 2);
    try std.testing.expect(report.immediate_count >= 1);
    try std.testing.expect(report.total_effort_hours > 0);
}
