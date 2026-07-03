const std = @import("std");
const types = @import("../types.zig");
const utils = @import("utils.zig");
const parser = @import("parser.zig");
const decoder = @import("decoder.zig");
const signatures = @import("signatures.zig");

const Allocator = types.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Analysis = types.Analysis;
const BinaryImage = types.BinaryImage;
const Decoded = types.Decoded;
const FunctionSpan = types.FunctionSpan;
const CategoryScores = types.CategoryScores;
const Evidence = types.Evidence;
const FunctionProfile = types.FunctionProfile;
const ResolvedCall = types.ResolvedCall;
const CleanupPathStats = types.CleanupPathStats;
const CleanupState = types.CleanupState;
const Summary = types.Summary;
const ThreatClass = types.ThreatClass;
const CallRole = types.CallRole;
const CallCategory = types.CallCategory;
const CallEdge = types.CallEdge;
const InstrKind = types.InstrKind;
const Reg = types.Reg;
const Operand = types.Operand;
const OperandKind = types.OperandKind;

pub fn analyzeTarget(allocator: Allocator, path: []const u8, max_bytes: usize, verbose: bool) !Analysis {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
    errdefer allocator.free(bytes);

    var hash: [32]u8 = undefined;
    Sha256.hash(bytes, &hash, .{});

    var image = try parser.parseBinary(allocator, bytes);
    errdefer image.deinit(allocator);
    if (verbose) {
        try std.io.getStdErr().writer().print("[IntegrityGap] {s}: {s}/{s}, imports={}, exec_sections={}, relocations={}\n", .{
            path, @tagName(image.format), @tagName(image.arch),
            image.imports.len, parser.countExecSections(image), image.relocations_count,
        });
    }

    const instructions = try decoder.decodeAll(allocator, bytes, image);
    errdefer allocator.free(instructions);
    const functions = try decoder.detectFunctions(allocator, instructions, image);
    errdefer allocator.free(functions);
    const call_edges = try decoder.buildCallEdges(allocator, instructions, functions);
    errdefer allocator.free(call_edges);

    const logging_present = signatures.detectLoggingPresent(bytes, image.imports);
    var evidence = std.ArrayList(Evidence).init(allocator);
    errdefer evidence.deinit();

    var profiles = try allocator.alloc(FunctionProfile, functions.len);
    var initialized_profiles: usize = 0;
    errdefer {
        for (profiles[0..initialized_profiles]) |profile| allocator.free(profile.calls);
        allocator.free(profiles);
    }

    for (functions, 0..) |span, idx| {
        profiles[idx] = try profileFunction(allocator, bytes, image, instructions, span, logging_present, &evidence);
        initialized_profiles += 1;
    }

    const pdb_path = "";
    const has_pdb = false;
    _ = pdb_path;
    _ = has_pdb;

    try detectSuspiciousPatterns(image, &evidence, allocator);
    try detectAntiDebuggingPatterns(instructions, image, &evidence, allocator);
    try detectResourceLeakPatterns(instructions, image, functions, &evidence, allocator);
    try detectApiMisusage(instructions, image, functions, &evidence, allocator);
    try detectExportObfuscation(bytes, image, &evidence, allocator);
    try inlineAnalysis(bytes, image, instructions, functions, &evidence, allocator);

    applyLocalNorm(profiles);
    const summary = buildSummary(profiles);

    return .{
        .target_path = path,
        .bytes = bytes,
        .sha256 = hash,
        .image = image,
        .instructions = instructions,
        .functions = functions,
        .profiles = profiles,
        .evidence = try evidence.toOwnedSlice(),
        .summary = summary,
        .call_edges = call_edges,
        .logging_present = logging_present,
        .has_pdb_info = false,
        .pdb_path = "",
    };
}

fn profileFunction(
    allocator: Allocator,
    bytes: []const u8,
    image: BinaryImage,
    instrs: []const Decoded,
    span: FunctionSpan,
    logging_present: bool,
    evidence: *std.ArrayList(Evidence),
) !FunctionProfile {
    var calls = std.ArrayList(ResolvedCall).init(allocator);
    errdefer calls.deinit();
    const evidence_start = evidence.items.len;

    var critical: usize = 0;
    var unchecked_critical: usize = 0;
    var acquire: usize = 0;
    var release: usize = 0;
    var high_risk: usize = 0;
    var logging_calls: usize = 0;
    var crypto_init: usize = 0;
    var crypto_op: usize = 0;
    var crypto_final: usize = 0;
    var crypto_destroy: usize = 0;
    var crypto_calls_seen: usize = 0;
    var synch_acquire: usize = 0;
    var synch_release: usize = 0;

    var first_arg_deref: ?usize = null;
    var first_validation: ?usize = null;
    var memcpy_like: usize = 0;
    var bounds_checks: usize = 0;
    var has_stack_canary = false;
    var has_alloca = false;
    var has_setjmp = false;
    const has_vla = false;
    var frame_size: usize = 0;

    for (instrs[span.instr_start..span.instr_end], 0..) |instr, local_idx| {
        if (first_validation == null and isValidationInstr(instr, image)) first_validation = local_idx;
        if (first_arg_deref == null and dereferencesArgumentPointer(instr, image)) first_arg_deref = local_idx;
        if (isBoundsCheck(instr, image)) bounds_checks += 1;

        if (instr.kind == .sub and instr.op_count >= 2) {
            const dst = instr.operand(0);
            const src = instr.operand(1);
            if (dst.kind == .reg and dst.reg == .rsp and src.kind == .imm) {
                frame_size = @intCast(src.imm);
            }
        }

        if (instr.kind == .mov and instr.op_count >= 2) {
            const dst = instr.operand(0);
            if (dst.kind == .reg and dst.reg == .rax) {
                if (local_idx + 1 < span.instr_end - span.instr_start) {
                    const next = instrs[span.instr_start + local_idx + 1];
                    if (next.kind == .cmp or next.kind == .test_) {
                    }
                }
            }
        }

        if (instr.kind == .test_ or instr.kind == .cmp) {
            for (0..instr.op_count) |opi| {
                const op = instr.operand(opi);
                if (op.kind == .reg and (op.reg == .rax or op.reg == .eax)) {
                    has_stack_canary = true;
                }
            }
        }

        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            const name = resolved.name;
            const category = if (resolved.external) signatures.categorizeCall(name) else .generic;
            const role = if (resolved.external) signatures.callRole(name, category) else .neutral;
            const checked = decoder.callReturnChecked(instrs, span, span.instr_start + local_idx);
            const risk = signatures.isHighRiskCategory(category);

            if (category == .logging) logging_calls += 1;
            if (risk) high_risk += 1;
            if (role == .acquire) acquire += 1;
            if (role == .release) release += 1;
            if (role == .crypto_init) crypto_init += 1;
            if (role == .crypto_op) crypto_op += 1;
            if (role == .crypto_final) crypto_final += 1;
            if (role == .crypto_destroy) crypto_destroy += 1;
            if (role == .lock_acquire) synch_acquire += 1;
            if (role == .lock_release) synch_release += 1;
            if (category == .crypto) crypto_calls_seen += 1;

            if (utils.asciiContainsIgnoreCase(name, "alloca")) has_alloca = true;
            if (utils.asciiContainsIgnoreCase(name, "setjmp") or utils.asciiContainsIgnoreCase(name, "setjmpex")) has_setjmp = true;
            if (utils.asciiContainsIgnoreCase(name, "_alloca")) has_alloca = true;

            if (signatures.isCriticalReturnCall(category, role)) {
                critical += 1;
                if (!checked) {
                    unchecked_critical += 1;
                    try evidence.append(.{ .function_va = span.start, .address = instr.va, .category = "error_handling", .message = "Critical call without return check before next relevant operation", .severity = 75 });
                }
            }
            if (signatures.isCopyLike(name)) memcpy_like += 1;
            try calls.append(.{ .va = instr.va, .target = instr.target, .name = name, .category = category, .role = role, .checked = checked, .high_risk = risk });
        }

        if (instr.kind == .syscall or instr.kind == .sysenter) {
            critical += 1;
            unchecked_critical += 1;
            try evidence.append(.{ .function_va = span.start, .address = instr.va, .category = "error_handling", .message = "Syscall/sysenter without visible return validation", .severity = 80 });
        }
    }

    const pointer_gap = if (first_arg_deref) |deref_idx| blk: {
        if (first_validation) |valid_idx| break :blk valid_idx > deref_idx;
        break :blk true;
    } else false;
    if (pointer_gap) {
        try evidence.append(.{ .function_va = span.start, .address = instrs[span.instr_start].va, .category = "input_validation", .message = "Argument pointer deref before observable local validation", .severity = 55 });
    }

    var scores = CategoryScores{};
    scores.error_handling = if (critical == 0) 0 else utils.clamp100(@as(f64, @floatFromInt(unchecked_critical)) * 100.0 / @as(f64, @floatFromInt(critical)));
    scores.resource_lifecycle = if (acquire == 0) 0 else utils.clamp100(@as(f64, @floatFromInt(acquire - @min(acquire, release))) * 100.0 / @as(f64, @floatFromInt(acquire)));
    scores.input_validation = inputValidationScore(pointer_gap, memcpy_like, bounds_checks, high_risk);
    const fixed_iv = crypto_calls_seen > 0 and detectFixedIv(bytes);
    scores.cryptographic = cryptoScore(crypto_init, crypto_op, crypto_final, crypto_destroy, calls.items, fixed_iv);
    scores.logging_auditability = if (!logging_present or high_risk == 0) 0 else utils.clamp100(@as(f64, @floatFromInt(high_risk - @min(high_risk, logging_calls))) * 100.0 / @as(f64, @floatFromInt(high_risk)));
    const cleanup_stats = cleanupPathStats(instrs[span.instr_start..span.instr_end], calls.items, acquire, release);
    scores.cleanup = cleanup_stats.score(acquire, release);
    scores.concurrency = if (synch_acquire == 0) 0 else utils.clamp100(@as(f64, @floatFromInt(synch_acquire - @min(synch_acquire, synch_release))) * 100.0 / @as(f64, @floatFromInt(synch_acquire)));

    if (scores.resource_lifecycle > 50 and acquire > release) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "resource_lifecycle", .message = "Resource acquisitions exceed observable releases", .severity = 70 });
    }
    if (cleanup_stats.error_dirty_paths > 0) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cleanup", .message = "Error path exits with acquired resource without observable release", .severity = 85 });
    } else if (cleanup_stats.dirty_exit_paths > 0 and cleanup_stats.clean_release_exit_paths > 0) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cleanup", .message = "Cleanup appears on some exit paths but missing on others", .severity = 70 });
    }
    if (scores.cryptographic > 40) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cryptographic", .message = "Incomplete crypto sequence or missing destroy/verification", .severity = 80 });
    }
    if (fixed_iv) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cryptographic", .message = "Pattern consistent with hardcoded IV detected in binary", .severity = 85 });
    }
    if (scores.logging_auditability > 50) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "logging", .message = "High-risk operations without logging in a binary that contains logging", .severity = 60 });
    }
    if (scores.concurrency > 50) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "concurrency", .message = "Lock acquire/release imbalance in synchronization operations", .severity = 65 });
    }
    if (has_alloca and frame_size > 0) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "memory_safety", .message = "Function uses alloca with non-zero frame size - potential stack overflow", .severity = 50 });
    }

    const aggregate = scores.aggregate();
    const specificity: f64 = if (high_risk > 0) 1.15 else 0.85;
    const confidence = utils.clamp100(aggregate * specificity);

    return .{
        .span = span,
        .calls = try calls.toOwnedSlice(),
        .scores = scores,
        .confidence = confidence,
        .aggregate_gap = aggregate,
        .evidence_start = evidence_start,
        .evidence_count = evidence.items.len - evidence_start,
        .critical_calls = critical,
        .unchecked_critical_calls = unchecked_critical,
        .acquire_calls = acquire,
        .release_calls = release,
        .high_risk_calls = high_risk,
        .logging_calls = logging_calls,
        .cleanup_exit_paths = cleanup_stats.exit_paths,
        .cleanup_dirty_exit_paths = cleanup_stats.dirty_exit_paths,
        .cleanup_error_dirty_paths = cleanup_stats.error_dirty_paths,
        .pointer_deref_before_validation = pointer_gap,
        .has_stack_canary = has_stack_canary,
        .frame_size = frame_size,
        .uses_alloca = has_alloca,
        .uses_setjmp = has_setjmp,
        .has_vla = has_vla,
    };
}

fn detectSuspiciousPatterns(image: BinaryImage, evidence: *std.ArrayList(Evidence), allocator: Allocator) !void {
    for (signatures.known_suspicious_patterns) |pattern| {
        for (image.imports) |imp| {
            if (utils.asciiContainsIgnoreCase(imp.name, pattern.name)) {
                try evidence.append(.{
                    .function_va = 0,
                    .address = imp.iat_va,
                    .category = "suspicious_pattern",
                    .message = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ pattern.description, imp.name }),
                    .severity = pattern.severity,
                    .cwe_id = pattern.cwe,
                });
            }
        }
    }
}

fn detectAntiDebuggingPatterns(instrs: []const Decoded, image: BinaryImage, evidence: *std.ArrayList(Evidence), allocator: Allocator) !void {
    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (utils.containsAny(resolved.name, &.{ "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString", "CloseHandle", "GetTickCount", "QueryPerformanceCounter" })) {
                try evidence.append(.{
                    .function_va = 0,
                    .address = instr.va,
                    .category = "anti_debug",
                    .message = try std.fmt.allocPrint(allocator, "Anti-debugging API: {s}", .{resolved.name}),
                    .severity = 40,
                });
            }
        }
        if (instr.kind == .rdtsc) {
            try evidence.append(.{
                .function_va = 0,
                .address = instr.va,
                .category = "anti_debug",
                .message = "RDTSC instruction - timing-based anti-debug check",
                .severity = 50,
            });
        }
    }
}

fn detectResourceLeakPatterns(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan, evidence: *std.ArrayList(Evidence), _: Allocator) !void {
    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        var handles_opened: usize = 0;
        var handles_closed: usize = 0;
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                if (utils.containsAny(resolved.name, &.{ "CreateFile", "OpenFile", "socket", "accept", "RegOpenKey", "HeapAlloc", "VirtualAlloc", "malloc", "calloc", "fopen" })) handles_opened += 1;
                if (utils.containsAny(resolved.name, &.{ "CloseHandle", "closesocket", "RegCloseKey", "HeapFree", "VirtualFree", "free", "fclose" })) handles_closed += 1;
            }
        }
        if (handles_opened > 0 and handles_closed < handles_opened and handles_opened > 2) {
            try evidence.append(.{
                .function_va = function.start,
                .address = function.start,
                .category = "resource_leak",
                .message = "Potential resource leak: unbalanced open/close in function",
                .severity = 65,
            });
        }
    }
}

fn detectApiMisusage(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan, evidence: *std.ArrayList(Evidence), _: Allocator) !void {
    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        var found_createthread = false;
        var found_resumethread = false;
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                if (utils.containsAny(resolved.name, &.{ "CreateThread", "CreateRemoteThread" })) found_createthread = true;
                if (utils.containsAny(resolved.name, &.{ "ResumeThread" })) found_resumethread = true;
            }
        }
        if (found_createthread and !found_resumethread) {
            try evidence.append(.{
                .function_va = function.start,
                .address = function.start,
                .category = "api_misuse",
                .message = "CreateThread without ResumeThread - thread may not start properly",
                .severity = 45,
            });
        }

    }
}

fn detectExportObfuscation(bytes: []const u8, _: BinaryImage, evidence: *std.ArrayList(Evidence), _: Allocator) !void {
    const packed_indicators = [_][]const u8{
        "UPX", "UPX!", "UPX0", "UPX1", "UPX2", "aspack", "PEtite",
        "Themida", "Enigma", "VMProtect", "Obsidium",
    };
    for (packed_indicators) |indicator| {
        if (std.mem.indexOf(u8, bytes, indicator) != null) {
            try evidence.append(.{
                .function_va = 0,
                .address = 0,
                .category = "packed_binary",
                .message = "Packer/obfuscator signature detected",
                .severity = 60,
            });
            break;
        }
    }
}

fn inlineAnalysis(bytes: []const u8, image: BinaryImage, instrs: []const Decoded, functions: []const FunctionSpan, evidence: *std.ArrayList(Evidence), _: Allocator) !void {
    for (functions) |func| {
        const func_instrs = instrs[func.instr_start..func.instr_end];
        var inline_syscall_count: usize = 0;
        var has_syscall_directive = false;
        for (func_instrs) |instr| {
            if (instr.kind == .syscall or instr.kind == .sysenter) {
                inline_syscall_count += 1;
                if (inline_syscall_count >= 2) {
                    try evidence.append(.{
                        .function_va = func.start, .address = instr.va,
                        .category = "inline_syscall",
                        .message = "Multiple syscall/sysenter instructions in function without standard library wrappers - possible shellcode",
                        .severity = 70,
                    });
                    break;
                }
            }
            if (instr.kind == .int3 and func_instrs.len <= 8) {
                has_syscall_directive = true;
            }
        }
        if (inline_syscall_count >= 1 and has_syscall_directive) {
            try evidence.append(.{
                .function_va = func.start, .address = func.start,
                .category = "inline_assembly",
                .message = "Inline assembly detected with syscall - possible shellcode or manual syscall invocation",
                .severity = 65,
            });
        }
        for (func_instrs) |instr| {
            if (instr.kind == .mov and instr.mem_write and instr.mem_read) {
                if (instr.op_count >= 2 and
                    instr.operand(0).kind == .mem and instr.operand(1).kind == .imm and
                    instr.operand(1).imm >= 0x1000)
                {
                    try evidence.append(.{
                        .function_va = func.start, .address = instr.va,
                        .category = "inline_constant",
                        .message = "Large constant written directly to memory - possible hardcoded offset",
                        .severity = 40,
                    });
                }
            }
        }
        for (func_instrs) |instr| {
            if (instr.kind == .call and instr.indirect and
                instr.op_count > 0 and instr.operand(0).kind == .imm)
            {
                try evidence.append(.{
                    .function_va = func.start, .address = instr.va,
                    .category = "inline_indirect",
                    .message = "Indirect call with immediate-type operand - unusual calling pattern",
                    .severity = 50,
                });
            }
        }
    }
    for (image.sections) |section| {
        if (section.va >= image.image_base + 0x10000000) continue;
        if (!section.executable) continue;
        const sect_bytes = sectionBytes(image.sections, section, bytes);
        var consecutive_nop: usize = 0;
        for (sect_bytes) |b| {
            if (b == 0x90) { consecutive_nop += 1; } else { consecutive_nop = 0; }
            if (consecutive_nop >= 16) {
                try evidence.append(.{
                    .function_va = section.va, .address = section.va,
                    .category = "inline_nop_sled",
                    .message = "Large NOP sled detected in executable section - possible shellcode padding",
                    .severity = 75,
                });
                break;
            }
        }
    }
}

fn sectionBytes(_: []const types.Section, section: types.Section, bytes: []const u8) []const u8 {
    if (section.file_offset >= bytes.len) return "";
    const end = @min(bytes.len, section.file_offset + section.size);
    return bytes[section.file_offset..end];
}

fn applyLocalNorm(profiles: []FunctionProfile) void {
    if (profiles.len < 4) return;
    var avg = CategoryScores{};
    for (profiles) |p| {
        avg.error_handling += p.scores.error_handling;
        avg.resource_lifecycle += p.scores.resource_lifecycle;
        avg.input_validation += p.scores.input_validation;
        avg.cryptographic += p.scores.cryptographic;
        avg.logging_auditability += p.scores.logging_auditability;
        avg.cleanup += p.scores.cleanup;
        avg.concurrency += p.scores.concurrency;
    }
    const inv = 1.0 / @as(f64, @floatFromInt(profiles.len));
    avg.error_handling *= inv;
    avg.resource_lifecycle *= inv;
    avg.input_validation *= inv;
    avg.cryptographic *= inv;
    avg.logging_auditability *= inv;
    avg.cleanup *= inv;
    avg.concurrency *= inv;
    var variance = CategoryScores{};
    for (profiles) |p| {
        variance.error_handling += utils.squared(p.scores.error_handling - avg.error_handling);
        variance.resource_lifecycle += utils.squared(p.scores.resource_lifecycle - avg.resource_lifecycle);
        variance.input_validation += utils.squared(p.scores.input_validation - avg.input_validation);
        variance.cryptographic += utils.squared(p.scores.cryptographic - avg.cryptographic);
        variance.logging_auditability += utils.squared(p.scores.logging_auditability - avg.logging_auditability);
        variance.cleanup += utils.squared(p.scores.cleanup - avg.cleanup);
        variance.concurrency += utils.squared(p.scores.concurrency - avg.concurrency);
    }
    const stddev = CategoryScores{
        .error_handling = @sqrt(variance.error_handling * inv),
        .resource_lifecycle = @sqrt(variance.resource_lifecycle * inv),
        .input_validation = @sqrt(variance.input_validation * inv),
        .cryptographic = @sqrt(variance.cryptographic * inv),
        .logging_auditability = @sqrt(variance.logging_auditability * inv),
        .cleanup = @sqrt(variance.cleanup * inv),
        .concurrency = @sqrt(variance.concurrency * inv),
    };
    for (profiles) |*p| {
        p.scores.error_handling = normalizeAgainstLocalNorm(p.scores.error_handling, avg.error_handling, stddev.error_handling);
        p.scores.resource_lifecycle = normalizeAgainstLocalNorm(p.scores.resource_lifecycle, avg.resource_lifecycle, stddev.resource_lifecycle);
        p.scores.input_validation = normalizeAgainstLocalNorm(p.scores.input_validation, avg.input_validation, stddev.input_validation);
        p.scores.cryptographic = normalizeAgainstLocalNorm(p.scores.cryptographic, avg.cryptographic, stddev.cryptographic);
        p.scores.logging_auditability = normalizeAgainstLocalNorm(p.scores.logging_auditability, avg.logging_auditability, stddev.logging_auditability);
        p.scores.cleanup = normalizeAgainstLocalNorm(p.scores.cleanup, avg.cleanup, stddev.cleanup);
        p.scores.concurrency = normalizeAgainstLocalNorm(p.scores.concurrency, avg.concurrency, stddev.concurrency);
        p.aggregate_gap = p.scores.aggregate();
        const local_delta = @max(0.0, p.aggregate_gap - normalizeAgainstLocalNorm(p.aggregate_gap, avg.aggregate(), stddev.aggregate()));
        p.confidence = utils.clamp100(p.confidence + local_delta * 0.25);
    }
}

fn normalizeAgainstLocalNorm(raw: f64, avg: f64, stddev: f64) f64 {
    if (avg < 12.0) return raw;
    const spread = @max(stddev, 8.0);
    if (raw <= avg) return utils.clamp100(raw * 0.35);
    const z = (raw - avg) / spread;
    const local_excess = utils.clamp100(z * 22.0);
    const retained_absolute = raw * 0.28;
    return utils.clamp100(retained_absolute + local_excess);
}

fn buildSummary(profiles: []const FunctionProfile) Summary {
    var scores = CategoryScores{};
    if (profiles.len == 0) return .{ .threat = .No_Material_Gap, .aggregate_gap = 0, .anomaly_confidence = 0, .scores = scores };
    var max_conf: f64 = 0;
    var material_profiles: usize = 0;
    for (profiles) |p| {
        scores.error_handling += p.scores.error_handling;
        scores.resource_lifecycle += p.scores.resource_lifecycle;
        scores.input_validation += p.scores.input_validation;
        scores.cryptographic += p.scores.cryptographic;
        scores.logging_auditability += p.scores.logging_auditability;
        scores.cleanup += p.scores.cleanup;
        scores.concurrency += p.scores.concurrency;
        if (p.confidence > max_conf) max_conf = p.confidence;
        if (p.aggregate_gap >= 45 or p.confidence >= 65) material_profiles += 1;
    }
    const inv = 1.0 / @as(f64, @floatFromInt(profiles.len));
    scores.error_handling *= inv;
    scores.resource_lifecycle *= inv;
    scores.input_validation *= inv;
    scores.cryptographic *= inv;
    scores.logging_auditability *= inv;
    scores.cleanup *= inv;
    scores.concurrency *= inv;
    const aggregate = scores.aggregate();
    const material_ratio = @as(f64, @floatFromInt(material_profiles)) / @as(f64, @floatFromInt(profiles.len));
    const threat = classifyThreat(scores, aggregate, max_conf, profiles.len, material_ratio);
    const confidence_base = utils.clamp100(aggregate * 1.25);
    return .{ .threat = threat, .aggregate_gap = aggregate, .anomaly_confidence = confidence_base, .scores = scores };
}

pub fn recalculateThreat(summary: *Summary, profiles: []const FunctionProfile) void {
    var max_conf: f64 = 0;
    var material_profiles: usize = 0;
    for (profiles) |p| {
        if (p.confidence > max_conf) max_conf = p.confidence;
        if (p.aggregate_gap >= 45 or p.confidence >= 65) material_profiles += 1;
    }
    const material_ratio = if (profiles.len > 0)
        @as(f64, @floatFromInt(material_profiles)) / @as(f64, @floatFromInt(profiles.len))
    else
        0;
    summary.threat = classifyThreat(summary.scores, summary.aggregate_gap, max_conf, profiles.len, material_ratio);
}

pub fn classifyThreat(scores: CategoryScores, aggregate: f64, max_conf: f64, function_count: usize, material_ratio: f64) ThreatClass {
    const size_scale = adaptiveThreatScale(function_count);
    const systemic_boost: f64 = if (material_ratio >= 0.25) 0.75 else if (material_ratio >= 0.12) 0.88 else 1.0;
    const scale = size_scale * systemic_boost;
    if (aggregate < 15.0 * scale and max_conf < 35.0 * scale and material_ratio < 0.03) return .No_Material_Gap;
    if (function_count > 1000 and aggregate < 5.0 and material_ratio < 0.01) return .No_Material_Gap;
    if (scores.cryptographic > 40.0 * scale and scores.resource_lifecycle > 30.0 * scale and scores.error_handling > 25.0 * scale) return .Ransomware;
    if (scores.logging_auditability > 40.0 * scale and scores.error_handling > 40.0 * scale) return .RAT;
    if (scores.resource_lifecycle > 50.0 * scale and scores.error_handling < 35.0 * scale) return .Dropper;
    if (max_conf > 70.0 * scale and aggregate < 35.0 * scale and material_ratio < 0.06) return .Implant;
    if (scores.supply_chain > 50.0 * scale and scores.configuration > 30.0 * scale) return .Supply_Chain_Compromise;
    if (scores.memory_safety > 45.0 * scale and scores.configuration > 35.0 * scale and scores.resource_lifecycle > 20.0 * scale) return .Firmware_Backdoor;
    if (scores.cryptographic > 55.0 * scale and scores.input_validation > 30.0 * scale) return .Crypto_Malware;
    if (scores.memory_safety > 50.0 * scale and scores.logging_auditability < 20.0 * scale and scores.error_handling > 30.0 * scale) return .Rootkit;
    if (scores.configuration > 50.0 * scale and scores.memory_safety > 40.0 * scale and scores.input_validation > 25.0 * scale) return .Bootkit;
    if (scores.logging_auditability > 35.0 * scale and scores.input_validation > 30.0 * scale and scores.cryptographic > 20.0 * scale) return .InfoStealer;
    if (scores.input_validation > 45.0 * scale and scores.resource_lifecycle > 35.0 * scale and scores.error_handling < 30.0 * scale) return .Loader;
    if (scores.input_validation > 40.0 * scale and scores.resource_lifecycle > 25.0 * scale) return .Downloader;
    if (scores.logging_auditability > 30.0 * scale and scores.input_validation > 35.0 * scale and scores.cryptographic > 15.0 * scale) return .KeyLogger;
    if (scores.concurrency > 40.0 * scale and scores.resource_lifecycle > 30.0 * scale and scores.error_handling > 20.0 * scale) return .Worm;
    if (aggregate < 10.0 and max_conf < 50.0) return .No_Material_Gap;
    return .Legitimate_Anomalous;
}

fn adaptiveThreatScale(function_count: usize) f64 {
    if (function_count < 8) return 1.45;
    if (function_count < 32) return 1.25;
    if (function_count < 128) return 1.10;
    if (function_count > 5000) return 0.78;
    if (function_count > 1000) return 0.88;
    return 1.0;
}

fn inputValidationScore(pointer_gap: bool, memcpy_like: usize, bounds_checks: usize, high_risk: usize) f64 {
    var score: f64 = 0;
    if (pointer_gap) score += 55;
    if (memcpy_like > 0 and bounds_checks == 0) score += 35;
    if (high_risk > 0 and pointer_gap) score += 10;
    return utils.clamp100(score);
}

fn cryptoScore(crypto_init: usize, crypto_op: usize, crypto_final: usize, crypto_destroy: usize, calls: []const ResolvedCall, fixed_iv: bool) f64 {
    if (crypto_init + crypto_op + crypto_final + crypto_destroy == 0) return 0;
    var score: f64 = 0;
    if (crypto_op > 0 and crypto_init == 0) score += 25;
    if (crypto_op > 0 and crypto_final == 0) score += 25;
    if ((crypto_init + crypto_op) > 0 and crypto_destroy == 0) score += 20;
    if (fixed_iv) score += 35;
    var unchecked: usize = 0;
    var crypto_calls: usize = 0;
    for (calls) |call| {
        if (call.category == .crypto) {
            crypto_calls += 1;
            if (!call.checked) unchecked += 1;
        }
    }
    if (crypto_calls > 0) score += @as(f64, @floatFromInt(unchecked)) * 30.0 / @as(f64, @floatFromInt(crypto_calls));
    return utils.clamp100(score);
}

fn detectFixedIv(bytes: []const u8) bool {
    const fixed_strings = [_][]const u8{
        "0123456789abcdef",
        "0000000000000000",
        "abcdefghijklmnop",
        "AAAAAAAAAAAAAAAA",
        "1234567890abcdef",
        "0001020304050607",
        "deadbeefdeadbeef",
    };
    for (fixed_strings) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern) != null) return true;
    }
    if (bytes.len < 16) return false;
    var off: usize = 0;
    while (off + 16 <= bytes.len) : (off += 1) {
        const slice = bytes[off..off + 16];
        var all_zero = true;
        var all_same = true;
        const first = slice[0];
        for (slice, 0..) |byte, j| {
            if (byte != 0) all_zero = false;
            if (j > 0 and byte != first) all_same = false;
        }
        if (all_zero or all_same) {
            return true;
        }
    }
    return false;
}

fn cleanupPathStats(instrs: []const Decoded, calls: []const ResolvedCall, acquire: usize, release: usize) CleanupPathStats {
    if (acquire == 0) return .{};
    if (instrs.len == 0) return .{ .exit_paths = 1, .dirty_exit_paths = if (acquire > release) 1 else 0 };
    if (instrs.len > types.max_cleanup_cfg_instrs) return cleanupPathStatsLinear(instrs, calls, acquire, release);

    var stats = CleanupPathStats{};
    var visited = std.StaticBitSet(types.max_cleanup_cfg_instrs * types.cleanup_state_variants).initEmpty();
    var stack: [types.max_cleanup_cfg_instrs * types.cleanup_state_variants]CleanupState = undefined;
    var stack_len: usize = 1;
    stack[0] = .{ .idx = 0, .outstanding = false, .release_seen = false, .error_like = false };

    while (stack_len > 0) {
        stack_len -= 1;
        var state = stack[stack_len];
        if (state.idx >= instrs.len) {
            recordCleanupExit(&stats, state);
            continue;
        }

        const visit_idx = cleanupVisitIndex(state);
        if (visited.isSet(visit_idx)) continue;
        visited.set(visit_idx);

        const instr = instrs[state.idx];
        if (instr.kind == .call) {
            if (acquireCallAt(calls, instr.va)) state.outstanding = true;
            if (releaseCallAt(calls, instr.va)) {
                state.outstanding = false;
                state.release_seen = true;
            }
        }

        switch (instr.kind) {
            .ret => recordCleanupExit(&stats, state),
            .jmp => {
                if (instr.target) |target| {
                    if (localIndexByVa(instrs, target)) |next_idx| {
                        pushCleanupState(&stack, &stack_len, .{ .idx = next_idx, .outstanding = state.outstanding, .release_seen = state.release_seen, .error_like = state.error_like }, &stats);
                    } else {
                        recordCleanupExit(&stats, state);
                    }
                } else {
                    recordCleanupExit(&stats, state);
                }
            },
            .jcc => {
                const taken_error = state.error_like or isLikelyErrorBranch(instrs, state.idx);
                if (instr.target) |target| {
                    if (localIndexByVa(instrs, target)) |target_idx| {
                        pushCleanupState(&stack, &stack_len, .{ .idx = target_idx, .outstanding = state.outstanding, .release_seen = state.release_seen, .error_like = taken_error }, &stats);
                    }
                }
                pushCleanupState(&stack, &stack_len, .{ .idx = state.idx + 1, .outstanding = state.outstanding, .release_seen = state.release_seen, .error_like = state.error_like }, &stats);
            },
            else => pushCleanupState(&stack, &stack_len, .{ .idx = state.idx + 1, .outstanding = state.outstanding, .release_seen = state.release_seen, .error_like = state.error_like }, &stats),
        }
    }
    if (stats.exit_paths == 0) stats.truncated = true;
    return stats;
}

fn cleanupPathStatsLinear(instrs: []const Decoded, calls: []const ResolvedCall, acquire: usize, release: usize) CleanupPathStats {
    var stats = CleanupPathStats{ .truncated = true };
    var state = CleanupState{ .idx = 0, .outstanding = false, .release_seen = false, .error_like = false };
    for (instrs, 0..) |instr, idx| {
        state.idx = idx;
        if (instr.kind == .call and acquireCallAt(calls, instr.va)) state.outstanding = true;
        if (instr.kind == .call and releaseCallAt(calls, instr.va)) {
            state.outstanding = false;
            state.release_seen = true;
        }
        if (instr.kind == .jcc and state.outstanding and isLikelyErrorBranch(instrs, idx)) stats.error_dirty_paths += 1;
        if (instr.kind == .ret or instr.kind == .jmp) recordCleanupExit(&stats, state);
    }
    if (stats.exit_paths == 0 and acquire > release) {
        stats.exit_paths = 1;
        stats.dirty_exit_paths = 1;
    }
    return stats;
}

fn cleanupVisitIndex(state: CleanupState) usize {
    var variant: usize = 0;
    if (state.outstanding) variant |= 1;
    if (state.release_seen) variant |= 2;
    if (state.error_like) variant |= 4;
    return state.idx * types.cleanup_state_variants + variant;
}

fn pushCleanupState(stack: *[types.max_cleanup_cfg_instrs * types.cleanup_state_variants]CleanupState, stack_len: *usize, state: CleanupState, stats: *CleanupPathStats) void {
    if (state.idx >= types.max_cleanup_cfg_instrs) {
        stats.truncated = true;
        recordCleanupExit(stats, state);
        return;
    }
    if (stack_len.* >= stack.len) {
        stats.truncated = true;
        recordCleanupExit(stats, state);
        return;
    }
    stack[stack_len.*] = state;
    stack_len.* += 1;
}

fn recordCleanupExit(stats: *CleanupPathStats, state: CleanupState) void {
    stats.exit_paths += 1;
    if (state.outstanding) {
        stats.dirty_exit_paths += 1;
        if (state.error_like) stats.error_dirty_paths += 1;
    } else if (state.release_seen) {
        stats.clean_release_exit_paths += 1;
    }
}

fn localIndexByVa(instrs: []const Decoded, va: u64) ?usize {
    for (instrs, 0..) |instr, idx| {
        if (instr.va == va) return idx;
    }
    return null;
}

fn isLikelyErrorBranch(instrs: []const Decoded, idx: usize) bool {
    if (idx == 0 or instrs[idx].kind != .jcc) return false;
    const prev = instrs[idx - 1];
    if ((prev.kind == .cmp or prev.kind == .test_) and (operandTouchesReg(prev, .rax) or operandHasZeroImmediate(prev))) return true;
    if (idx >= 2) {
        const prev2 = instrs[idx - 2];
        if ((prev2.kind == .cmp or prev2.kind == .test_) and (operandTouchesReg(prev2, .rax) or operandHasZeroImmediate(prev2))) return true;
    }
    return false;
}

fn operandHasZeroImmediate(instr: Decoded) bool {
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .imm and op.imm == 0) return true;
    }
    return false;
}

fn acquireCallAt(calls: []const ResolvedCall, va: u64) bool {
    for (calls) |call| {
        if (call.va == va and call.role == .acquire) return true;
    }
    return false;
}

fn releaseCallAt(calls: []const ResolvedCall, va: u64) bool {
    for (calls) |call| {
        if (call.va == va and call.role == .release) return true;
    }
    return false;
}

fn isValidationInstr(instr: Decoded, image: BinaryImage) bool {
    if (instr.kind != .cmp and instr.kind != .test_) return false;
    var saw_arg = false;
    var saw_zero = false;
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .reg and isArgumentRegForImage(image, op.reg)) saw_arg = true;
        if (op.kind == .mem and isArgumentMemoryForImage(image, op)) saw_arg = true;
        if (op.kind == .imm and op.imm == 0) saw_zero = true;
    }
    return saw_arg or saw_zero;
}

fn dereferencesArgumentPointer(instr: Decoded, image: BinaryImage) bool {
    if (!instr.mem_read and !instr.mem_write) return false;
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .mem and isArgumentMemoryForImage(image, op)) return true;
    }
    return false;
}

fn isBoundsCheck(instr: Decoded, image: BinaryImage) bool {
    if (instr.kind != .cmp and instr.kind != .test_ and instr.kind != .sub) return false;
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .reg and isArgumentRegForImage(image, op.reg)) return true;
        if (op.kind == .mem and isArgumentMemoryForImage(image, op)) return true;
        if (op.kind == .imm and op.imm > 0 and op.imm < 0x100000) return true;
    }
    return false;
}

fn isArgumentRegForImage(image: BinaryImage, reg: Reg) bool {
    const family = decoder.regFamily(reg);
    if (image.arch == .x86) return false;
    if (image.format == .pe64) {
        return switch (family) {
            .rcx, .rdx, .r8, .r9 => true,
            else => false,
        };
    }
    return switch (family) {
        .rdi, .rsi, .rdx, .rcx, .r8, .r9 => true,
        else => false,
    };
}

fn isArgumentMemoryForImage(image: BinaryImage, op: Operand) bool {
    if (op.kind != .mem) return false;
    if (image.arch == .x86) {
        return (op.base == .rsp and op.disp >= 4) or (op.base == .rbp and op.disp >= 8);
    }
    if (isArgumentRegForImage(image, op.base)) return true;
    if (image.format == .pe64 and op.base == .rsp and op.disp >= 32 and op.disp <= 96) return true;
    return false;
}

fn operandTouchesReg(instr: Decoded, reg: Reg) bool {
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .reg and decoder.regFamily(op.reg) == decoder.regFamily(reg)) return true;
    }
    return false;
}
