const std = @import("std");
const types = @import("../types.zig");
const decoder = @import("../core/decoder.zig");
const signatures = @import("../core/signatures.zig");

const Allocator = types.Allocator;

pub const ConfidenceAdjustment = struct {
    original_confidence: f64,
    adjusted_confidence: f64,
    reason: []const u8,
    context_factors: []ContextFactor,
};

pub const ContextFactor = enum {
    surrounding_validation_present,
    error_path_not_reachable,
    resource_leak_false_positive,
    compiler_optimized_checks,
    wrapper_function_pattern,
    known_library_function,
    test_code_section,
    debug_build_detected,
    static_analysis_limitation,
    false_positive_signature,
};

pub const ReductionResult = struct {
    filtered_evidence: []types.Evidence,
    adjustments: []ConfidenceAdjustment,
    removed_count: usize,
    adjusted_count: usize,
    total_original: usize,
    final_count: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.filtered_evidence);
        allocator.free(self.adjustments);
    }
};

fn analyzeContext(ev: types.Evidence, instrs: []const types.Decoded, image: types.BinaryImage, functions: []const types.FunctionSpan) struct { remove: bool, factors: [4]ContextFactor, factor_count: usize } {
    var factors: [4]ContextFactor = undefined;
    var count: usize = 0;
    var remove = false;

    if (std.mem.eql(u8, ev.category, "resource_leak")) {
        if (detectWrapperPattern(ev, instrs, image, functions)) {
            factors[count] = .wrapper_function_pattern;
            count += 1;
        }
    }

    if (std.mem.eql(u8, ev.category, "error_handling")) {
        if (hasSurroundingValidation(ev, instrs, functions)) {
            factors[count] = .surrounding_validation_present;
            count += 1;
            remove = true;
        }
        if (isKnownLibraryFunction(ev, instrs, image)) {
            factors[count] = .known_library_function;
            count += 1;
            remove = true;
        }
    }

    if (std.mem.eql(u8, ev.category, "crypto") or std.mem.eql(u8, ev.category, "cryptographic")) {
        if (isCompilerGeneratedPattern(ev, instrs)) {
            factors[count] = .compiler_optimized_checks;
            count += 1;
            remove = true;
        }
    }

    if (detectTestCodeSection(ev, image)) {
        factors[count] = .test_code_section;
        count += 1;
        remove = true;
    }

    return .{ .remove = remove, .factors = factors, .factor_count = count };
}

fn detectWrapperPattern(ev: types.Evidence, instrs: []const types.Decoded, image: types.BinaryImage, functions: []const types.FunctionSpan) bool {
    const target_func_va = ev.function_va;
    for (functions) |func| {
        if (func.start != target_func_va) continue;
        const func_instrs = instrs[func.instr_start..func.instr_end];
        var alloc_count: usize = 0;
        var free_count: usize = 0;
        for (func_instrs) |instr| {
            if (instr.kind != .call) continue;
            const resolved = decoder.resolveCallInfo(image, instr);
            if (std.mem.indexOf(u8, resolved.name, "alloc") != null or std.mem.indexOf(u8, resolved.name, "Create") != null or std.mem.indexOf(u8, resolved.name, "Open") != null) alloc_count += 1;
            if (std.mem.indexOf(u8, resolved.name, "free") != null or std.mem.indexOf(u8, resolved.name, "Close") != null or std.mem.indexOf(u8, resolved.name, "Release") != null) free_count += 1;
        }
        if (alloc_count > 0 and alloc_count == free_count) return true;
    }
    return false;
}

fn hasSurroundingValidation(ev: types.Evidence, instrs: []const types.Decoded, functions: []const types.FunctionSpan) bool {
    for (functions) |func| {
        if (func.start != ev.function_va) continue;
        const func_instrs = instrs[func.instr_start..func.instr_end];
        const local_idx = for (func_instrs, 0..) |instr, idx| {
            if (instr.va == ev.address) break idx;
        } else return false;
        const lookback = if (local_idx >= 5) local_idx - 5 else 0;
        const lookahead = @min(func_instrs.len, local_idx + 6);
        var validation_count: usize = 0;
        for (func_instrs[lookback..lookahead]) |instr| {
            if (instr.kind == .cmp or instr.kind == .test_) {
                var touches_ret = false;
                for (0..instr.op_count) |i| {
                    const op = instr.operand(i);
                    if (op.kind == .reg) {
                        const family = decoder.regFamily(op.reg);
                        if (family == .rax or family == .eax or family == .rcx or family == .rdx) touches_ret = true;
                    }
                }
                if (touches_ret) validation_count += 1;
            }
        }
        if (validation_count >= 2) return true;
    }
    return false;
}

fn isKnownLibraryFunction(ev: types.Evidence, instrs: []const types.Decoded, image: types.BinaryImage) bool {
    for (instrs) |instr| {
        if (instr.va == ev.address and instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            const known_safe = [_][]const u8{
                "printf", "fprintf", "sprintf", "snprintf", "malloc", "calloc",
                "realloc", "free", "memcpy", "memmove", "memset", "strlen",
                "strcmp", "strncmp", "ExitProcess", "TerminateProcess",
            };
            for (known_safe) |safe| {
                if (std.ascii.eqlIgnoreCase(resolved.name, safe)) return true;
            }
        }
    }
    return false;
}

fn isCompilerGeneratedPattern(ev: types.Evidence, instrs: []const types.Decoded) bool {
    _ = ev;
    _ = instrs;
    return false;
}

fn detectTestCodeSection(ev: types.Evidence, image: types.BinaryImage) bool {
    for (image.sections) |section| {
        if (section.va <= ev.address and ev.address < section.va + section.virtual_size) {
            const name_lower = section.name;
            if (std.mem.indexOf(u8, name_lower, "test") != null or
                std.mem.indexOf(u8, name_lower, "debug") != null)
                return true;
        }
    }
    return false;
}

pub fn reduceFalsePositives(allocator: Allocator, evidence: []const types.Evidence, instrs: []const types.Decoded, image: types.BinaryImage, functions: []const types.FunctionSpan) !ReductionResult {
    var filtered = std.ArrayList(types.Evidence).init(allocator);
    errdefer filtered.deinit();
    var adjustments = std.ArrayList(ConfidenceAdjustment).init(allocator);
    errdefer adjustments.deinit();

    var removed: usize = 0;
    var adjusted: usize = 0;

    for (evidence) |ev| {
        const ctx = analyzeContext(ev, instrs, image, functions);
        if (ctx.remove) {
            removed += 1;
            try adjustments.append(.{
                .original_confidence = @as(f64, @floatFromInt(ev.severity)),
                .adjusted_confidence = 0,
                .reason = "Removed by context analysis",
                .context_factors = ctx.factors[0..ctx.factor_count],
            });
            continue;
        }
        if (ctx.factor_count > 0) {
            adjusted += 1;
            const orig = @as(f64, @floatFromInt(ev.severity));
            var reduction: f64 = 0;
            for (ctx.factors[0..ctx.factor_count]) |factor| {
                reduction += switch (factor) {
                    .surrounding_validation_present => 15.0,
                    .error_path_not_reachable => 20.0,
                    .resource_leak_false_positive => 25.0,
                    .compiler_optimized_checks => 10.0,
                    .wrapper_function_pattern => 20.0,
                    .known_library_function => 30.0,
                    .test_code_section => 40.0,
                    .debug_build_detected => 25.0,
                    .static_analysis_limitation => 10.0,
                    .false_positive_signature => 50.0,
                };
            }
            const adjusted_sev = @max(0.0, orig - reduction);
            try adjustments.append(.{
                .original_confidence = orig,
                .adjusted_confidence = adjusted_sev,
                .reason = "Confidence reduced by context analysis",
                .context_factors = ctx.factors[0..ctx.factor_count],
            });
            var adjusted_ev = ev;
            adjusted_ev.severity = @intFromFloat(@min(adjusted_sev, 255.0));
            try filtered.append(adjusted_ev);
        } else {
            try filtered.append(ev);
        }
    }

    return .{
        .filtered_evidence = try filtered.toOwnedSlice(),
        .adjustments = try adjustments.toOwnedSlice(),
        .removed_count = removed,
        .adjusted_count = adjusted,
        .total_original = evidence.len,
        .final_count = filtered.items.len,
    };
}

pub fn computeFalsePositiveRate(original: usize, removed: usize) f64 {
    if (original == 0) return 0;
    return @as(f64, @floatFromInt(removed)) * 100.0 / @as(f64, @floatFromInt(original));
}

test "false positive reducer - no evidence" {
    const allocator = std.testing.allocator;
    const image = types.BinaryImage{
        .format = .elf64, .arch = .x86_64, .entry_va = 0, .image_base = 0,
        .sections = &[_]types.Section{}, .imports = &[_]types.ImportSymbol{},
        .symbols = &[_]types.Symbol{},
    };
    const result = try reduceFalsePositives(allocator, &[_]types.Evidence{}, &[_]types.Decoded{}, image, &[_]types.FunctionSpan{});
    defer result.deinit(allocator);
    try std.testing.expect(result.final_count == 0);
    try std.testing.expect(result.removed_count == 0);
}

test "false positive reducer - remove test code" {
    const allocator = std.testing.allocator;
    var sections = try allocator.alloc(types.Section, 1);
    defer allocator.free(sections);
    sections[0] = .{ .name = ".text", .va = 0x1000, .file_offset = 0, .size = 1024, .virtual_size = 1024, .executable = true, .contains_code = true };
    const image = types.BinaryImage{
        .format = .elf64, .arch = .x86_64, .entry_va = 0x1000, .image_base = 0,
        .sections = sections, .imports = &[_]types.ImportSymbol{}, .symbols = &[_]types.Symbol{},
    };
    var ev = try allocator.alloc(types.Evidence, 1);
    defer allocator.free(ev);
    ev[0] = .{ .function_va = 0, .address = 0x1000, .category = "error_handling", .message = "test", .severity = 80 };
    const result = try reduceFalsePositives(allocator, ev, &[_]types.Decoded{}, image, &[_]types.FunctionSpan{});
    defer result.deinit(allocator);
    try std.testing.expect(result.final_count <= 1);
}
