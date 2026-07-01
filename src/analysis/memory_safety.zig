const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const decoder = @import("../core/decoder.zig");

const Allocator = types.Allocator;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const FunctionSpan = types.FunctionSpan;
const InstrKind = types.InstrKind;
const Reg = types.Reg;
const Operand = types.Operand;
const OperandKind = types.OperandKind;

pub const UnsafePattern = enum {
    unbounded_copy,
    format_string_vulnerability,
    use_after_free,
    double_free,
    null_pointer_dereference,
    buffer_overflow,
    integer_overflow,
    integer_underflow,
    signedness_error,
    uninitialized_variable,
    memory_leak,
    stack_buffer_overflow,
    heap_buffer_overflow,
    type_confusion,
    unsafe_untrusted_data,
    race_on_memory,
};

pub const MemoryOperation = struct {
    address: u64,
    function_va: u64,
    operation_type: MemoryOpType,
    size: usize,
    source_reg: Reg,
    dest_reg: Reg,
    is_unsafe: bool,
    severity: u8,
};

pub const MemoryOpType = enum {
    allocation,
    deallocation,
    copy,
    move,
    compare,
    set,
    resize,
    bind,
    map,
    unmap,
    protect,
};

pub const SafetyFinding = struct {
    address: u64,
    function_va: u64,
    pattern: UnsafePattern,
    severity: u8,
    description: []const u8 = "",
    recommendation: []const u8 = "",
    cwe_id: u32 = 0,
};

pub const StackFrame = struct {
    function_va: u64,
    frame_size: usize,
    saved_regs: usize,
    local_vars: usize,
    has_canary: bool,
    has_safebuffer: bool,
    stack_protector_level: StackProtectorLevel,
};

pub const StackProtectorLevel = enum {
    none,
    partial,
    full,
    strong,
};

pub const BinarySafetyAnalysis = struct {
    operations: []MemoryOperation,
    findings: []SafetyFinding,
    stack_frames: []StackFrame,
    unsafe_copy_count: usize,
    format_string_count: usize,
    memory_leak_count: usize,
    use_after_free_count: usize,
    buffer_overflow_count: usize,
    null_deref_count: usize,
    total_allocation_sites: usize,
    safety_gap_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.operations);
        allocator.free(self.findings);
        allocator.free(self.stack_frames);
    }
};

const unsafe_copy_functions = [_][]const u8{
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "wcscpy", "wcscat", "swprintf", "memcpy", "memmove",
};

const format_string_functions = [_][]const u8{
    "printf", "fprintf", "sprintf", "snprintf", "vprintf",
    "vfprintf", "vsprintf", "vsnprintf", "syslog",
};

const allocation_functions = [_][]const u8{
    "malloc", "calloc", "realloc", "free", "new", "delete",
    "HeapAlloc", "HeapFree", "HeapReAlloc",
    "VirtualAlloc", "VirtualFree", "VirtualAllocEx",
    "mmap", "munmap", "brk", "sbrk",
    "LocalAlloc", "LocalFree", "GlobalAlloc", "GlobalFree",
    "CoTaskMemAlloc", "CoTaskMemFree",
};

fn isUnsafeCopy(name: []const u8) bool {
    return utils.containsAny(name, &unsafe_copy_functions) and
        !utils.containsAny(name, &.{ "strncpy", "strncat", "snprintf", "strlcpy", "strlcat", "memcpy_s", "memmove_s", "strcpy_s", "strcat_s" });
}

fn isFormatStringWithArgs(name: []const u8) bool {
    return utils.containsAny(name, &.{ "printf", "fprintf", "sprintf", "vprintf", "vfprintf", "vsprintf" }) and
        !utils.containsAny(name, &.{ "snprintf", "vsnprintf", "wsprintf" });
}

fn isAllocationFunction(name: []const u8) bool {
    return utils.containsAny(name, &.{ "malloc", "calloc", "realloc", "free", "HeapAlloc", "HeapFree", "VirtualAlloc", "VirtualFree", "mmap", "munmap", "new", "delete", "LocalAlloc", "GlobalAlloc" });
}

fn isDeallocationFunction(name: []const u8) bool {
    return utils.containsAny(name, &.{ "free", "HeapFree", "VirtualFree", "munmap", "delete", "LocalFree", "GlobalFree", "CoTaskMemFree" });
}

pub fn analyzeMemorySafety(allocator: Allocator, _: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !BinarySafetyAnalysis {
    var operations = std.ArrayList(MemoryOperation).init(allocator);
    errdefer operations.deinit();
    var findings = std.ArrayList(SafetyFinding).init(allocator);
    errdefer findings.deinit();
    var stack_frames = std.ArrayList(StackFrame).init(allocator);
    errdefer stack_frames.deinit();

    var unsafe_copy_count: usize = 0;
    var fmt_string_count: usize = 0;
    var alloc_count: usize = 0;
    var free_count: usize = 0;
    const use_after_free_count: usize = 0;
    const buf_overflow_count: usize = 0;
    var null_deref_count: usize = 0;

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];

        const frame = analyzeStackFrame(func_instrs, function);
        try stack_frames.append(frame);

        var alloc_map = std.AutoHashMap(u64, u64).init(allocator);
        defer alloc_map.deinit();
        var freed_set = std.AutoHashMap(u64, void).init(allocator);
        defer freed_set.deinit();

        for (func_instrs, 0..) |instr, local_idx| {
            if (instr.kind != .call) {
                if (instr.kind == .mov and instr.op_count >= 2) {
                    const dst = instr.operand(0);
                    const src = instr.operand(1);
                    if (dst.kind == .reg and src.kind == .imm and src.imm == 0) {
                        if (frame.stack_protector_level == .none and frame.frame_size > 0) {
                            try findings.append(.{
                                .address = instr.va,
                                .function_va = function.start,
                                .pattern = .null_pointer_dereference,
                                .severity = 55,
                                .description = "Potential null pointer assignment",
                                .recommendation = "Add null check after allocation",
                                .cwe_id = 476,
                            });
                            null_deref_count += 1;
                        }
                    }
                }
                continue;
            }

            const resolved = decoder.resolveCallInfo(image, instr);
            const name = resolved.name;

            if (isUnsafeCopy(name)) {
                unsafe_copy_count += 1;
                try operations.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .operation_type = .copy,
                    .size = 0,
                    .source_reg = .none,
                    .dest_reg = .none,
                    .is_unsafe = true,
                    .severity = 80,
                });
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .pattern = .unbounded_copy,
                    .severity = 80,
                    .description = try std.fmt.allocPrint(allocator, "Unbounded string copy: {s}", .{name}),
                    .recommendation = "Replace with strncpy, strlcpy, or snprintf with length limit",
                    .cwe_id = 120,
                });
            }

            if (isFormatStringWithArgs(name)) {
                fmt_string_count += 1;
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .pattern = .format_string_vulnerability,
                    .severity = 90,
                    .description = try std.fmt.allocPrint(allocator, "Format string function: {s}", .{name}),
                    .recommendation = "Use fixed format strings, never pass user input as format",
                    .cwe_id = 134,
                });
            }

            if (isAllocationFunction(name) and !isDeallocationFunction(name)) {
                alloc_count += 1;
                try operations.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .operation_type = .allocation,
                    .size = 0,
                    .source_reg = .none,
                    .dest_reg = .rax,
                    .is_unsafe = false,
                    .severity = 20,
                });
                try alloc_map.put(instr.va, function.start);
            }

            if (isDeallocationFunction(name)) {
                free_count += 1;
                try freed_set.put(instr.va, {});
                try operations.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .operation_type = .deallocation,
                    .size = 0,
                    .source_reg = .none,
                    .dest_reg = .none,
                    .is_unsafe = false,
                    .severity = 20,
                });

                if (detectPotentialDoubleFree(func_instrs, local_idx, name, image)) {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .pattern = .double_free,
                        .severity = 95,
                        .description = "Potential double-free detected",
                        .recommendation = "Set pointer to NULL after free and check before freeing",
                        .cwe_id = 415,
                    });
                }
            }
        }

        if (alloc_count > 0 and free_count == 0 and func_instrs.len > 3) {
            try findings.append(.{
                .address = function.start,
                .function_va = function.start,
                .pattern = .memory_leak,
                .severity = 70,
                .description = "Function allocates memory without deallocation",
                .recommendation = "Ensure every allocation has matching deallocation",
                .cwe_id = 401,
            });
        }

        if (frame.stack_protector_level == .none and frame.frame_size > 512) {
            try findings.append(.{
                .address = function.start,
                .function_va = function.start,
                .pattern = .stack_buffer_overflow,
                .severity = 65,
                .description = try std.fmt.allocPrint(allocator, "Large stack frame ({d} bytes) without stack protector", .{frame.frame_size}),
                .recommendation = "Compile with -fstack-protector-strong or reduce stack frame size",
                .cwe_id = 121,
            });
        }
    }

    const score = computeSafetyScore(
        unsafe_copy_count,
        fmt_string_count,
        buf_overflow_count,
        null_deref_count,
        use_after_free_count,
        findings.items.len,
    );

    return .{
        .operations = try operations.toOwnedSlice(),
        .findings = try findings.toOwnedSlice(),
        .stack_frames = try stack_frames.toOwnedSlice(),
        .unsafe_copy_count = unsafe_copy_count,
        .format_string_count = fmt_string_count,
        .memory_leak_count = alloc_count -| free_count,
        .use_after_free_count = use_after_free_count,
        .buffer_overflow_count = buf_overflow_count,
        .null_deref_count = null_deref_count,
        .total_allocation_sites = alloc_count,
        .safety_gap_score = score,
    };
}

fn analyzeStackFrame(instrs: []const Decoded, function: FunctionSpan) StackFrame {
    var frame_size: usize = 0;
    var saved_regs: usize = 0;
    var has_canary = false;
    const has_safebuffer = false;

    if (instrs.len == 0) return .{
        .function_va = function.start,
        .frame_size = 0,
        .saved_regs = 0,
        .local_vars = 0,
        .has_canary = false,
        .has_safebuffer = false,
        .stack_protector_level = .none,
    };

    for (instrs[0..@min(instrs.len, 16)]) |instr| {
        if (instr.kind == .sub and instr.op_count >= 2) {
            const dst = instr.operand(0);
            const src = instr.operand(1);
            if (dst.kind == .reg and dst.reg == .rsp and src.kind == .imm) {
                frame_size = @intCast(src.imm);
            }
        }
        if (instr.kind == .push) saved_regs += 1;
        if (instr.kind == .mov and instr.op_count >= 2) {
            const dst = instr.operand(0);
            const src = instr.operand(1);
            if (dst.kind == .reg and dst.reg == .rsp) saved_regs += 1;
            _ = src;
        }
        if (instr.kind == .test_ or instr.kind == .cmp) {
            for (0..instr.op_count) |i| {
                const op = instr.operand(i);
                if (op.kind == .reg and op.reg == .rax) has_canary = true;
            }
        }
    }

    const protector: StackProtectorLevel = if (has_safebuffer) .full else if (has_canary) .strong else .none;

    return .{
        .function_va = function.start,
        .frame_size = frame_size,
        .saved_regs = saved_regs,
        .local_vars = if (frame_size > 0) @max(0, frame_size -| (saved_regs *| 8)) else 0,
        .has_canary = has_canary,
        .has_safebuffer = has_safebuffer,
        .stack_protector_level = protector,
    };
}

fn detectPotentialDoubleFree(func_instrs: []const Decoded, free_idx: usize, _: []const u8, image: BinaryImage) bool {
    if (free_idx + 1 < func_instrs.len) {
        const next = func_instrs[free_idx + 1];
        if (next.kind == .call) {
            const resolved_next = decoder.resolveCallInfo(image, next);
            if (isDeallocationFunction(resolved_next.name)) return true;
        }
    }
    return false;
}

fn detectNullDerefAfterAlloc(alloc_va: u64, func_instrs: []const Decoded, instr_idx: usize, image: BinaryImage) bool {
    _ = alloc_va;
    if (instr_idx + 2 >= func_instrs.len) return true;
    const next = func_instrs[instr_idx + 1];
    if (next.kind == .mov and next.op_count >= 2) {
        const src = next.operand(1);
        if (src.kind == .imm and src.imm == 0) return true;
    }
    _ = image;
    return false;
}

fn detectUseAfterFree(free_va: u64, func_instrs: []const Decoded, free_idx: usize) bool {
    _ = free_va;
    const check_end = @min(func_instrs.len, free_idx + 10);
    var i = free_idx + 1;
    while (i < check_end) : (i += 1) {
        const instr = func_instrs[i];
        if (instr.mem_read or instr.mem_write) return true;
        if (instr.kind == .call or instr.kind == .ret) break;
    }
    return false;
}

fn computeSafetyScore(unsafe_copy: usize, fmt_string: usize, buf_overflow: usize, null_deref: usize, uaf: usize, total_findings: usize) f64 {
    var score: f64 = 0;
    score += @as(f64, @floatFromInt(unsafe_copy)) * 15.0;
    score += @as(f64, @floatFromInt(fmt_string)) * 25.0;
    score += @as(f64, @floatFromInt(buf_overflow)) * 20.0;
    score += @as(f64, @floatFromInt(null_deref)) * 10.0;
    score += @as(f64, @floatFromInt(uaf)) * 30.0;
    if (total_findings == 0) return 0;
    return utils.clamp100(score);
}

pub fn detectIntegerOverflow(allocator: Allocator, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ![]SafetyFinding {
    var findings = std.ArrayList(SafetyFinding).init(allocator);
    errdefer findings.deinit();

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                if (utils.containsAny(resolved.name, &.{ "malloc", "calloc", "realloc", "VirtualAlloc", "HeapAlloc" })) {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .pattern = .integer_overflow,
                        .severity = 70,
                        .description = "Memory allocation size not checked for overflow",
                        .recommendation = "Validate allocation size against maximum before calling",
                        .cwe_id = 190,
                    });
                }
            }
        }
    }

    return findings.toOwnedSlice();
}
