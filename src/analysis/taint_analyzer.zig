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
const ResolvedCall = types.ResolvedCall;
const CallEdge = types.CallEdge;

pub const TaintSource = enum {
    network_input,
    file_input,
    user_input,
    environment_variable,
    registry_input,
    shared_memory,
    pipe_input,
    socket_input,
    cmdline_argument,
    untrusted_pointer,
    stdin,
};

pub const TaintSink = enum {
    code_execution,
    command_injection,
    sql_query,
    buffer_write,
    format_string,
    file_write,
    network_send,
    privilege_elevation,
    registry_write,
    memory_allocation,
    return_value,
    jump_target,
};

pub const TaintSeverity = enum(u8) {
    none = 0,
    low = 25,
    medium = 50,
    high = 75,
    critical = 100,
};

pub const TaintPropagation = struct {
    source_va: u64,
    sink_va: u64,
    source_type: TaintSource,
    sink_type: TaintSink,
    path_length: usize,
    function_vas: []u64,
    severity: TaintSeverity,
    sanitized: bool,
    sanitization_type: []const u8 = "",
    description: []const u8 = "",

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.function_vas);
    }
};

pub const DataFlowSource = struct {
    va: u64,
    function_va: u64,
    source_type: TaintSource,
    reg: Reg,
    description: []const u8,
};

pub const DataFlowSink = struct {
    va: u64,
    function_va: u64,
    sink_type: TaintSink,
    reg: Reg,
    description: []const u8,
};

pub const TaintAnalysis = struct {
    sources: []DataFlowSource,
    sinks: []DataFlowSink,
    propagations: []TaintPropagation,
    unvalidated_paths: usize,
    total_paths: usize,
    taint_gap_score: f64,
    high_severity_count: usize,
    critical_severity_count: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.sources);
        allocator.free(self.sinks);
        for (self.propagations) |*p| p.deinit(allocator);
        allocator.free(self.propagations);
    }
};

const source_function_patterns = [_]struct { pattern: []const u8, source: TaintSource }{
    .{ .pattern = "recv", .source = .network_input },
    .{ .pattern = "recvfrom", .source = .network_input },
    .{ .pattern = "WSARecv", .source = .network_input },
    .{ .pattern = "read", .source = .file_input },
    .{ .pattern = "fread", .source = .file_input },
    .{ .pattern = "fgetc", .source = .file_input },
    .{ .pattern = "fgets", .source = .file_input },
    .{ .pattern = "fscanf", .source = .file_input },
    .{ .pattern = "scanf", .source = .user_input },
    .{ .pattern = "gets", .source = .user_input },
    .{ .pattern = "getenv", .source = .environment_variable },
    .{ .pattern = "getenv_s", .source = .environment_variable },
    .{ .pattern = "RegQueryValueEx", .source = .registry_input },
    .{ .pattern = "RegGetValue", .source = .registry_input },
    .{ .pattern = "GetCommandLineA", .source = .cmdline_argument },
    .{ .pattern = "argv", .source = .cmdline_argument },
    .{ .pattern = "stdin", .source = .stdin },
    .{ .pattern = "cin", .source = .user_input },
    .{ .pattern = "getchar", .source = .user_input },
    .{ .pattern = "readfile", .source = .file_input },
    .{ .pattern = "mapviewoffile", .source = .file_input },
};

const sink_function_patterns = [_]struct { pattern: []const u8, sink: TaintSink }{
    .{ .pattern = "system", .sink = .code_execution },
    .{ .pattern = "exec", .sink = .code_execution },
    .{ .pattern = "popen", .sink = .code_execution },
    .{ .pattern = "_wsystem", .sink = .code_execution },
    .{ .pattern = "CreateProcess", .sink = .code_execution },
    .{ .pattern = "WinExec", .sink = .code_execution },
    .{ .pattern = "ShellExecute", .sink = .code_execution },
    .{ .pattern = "sprintf", .sink = .format_string },
    .{ .pattern = "snprintf", .sink = .format_string },
    .{ .pattern = "vsprintf", .sink = .format_string },
    .{ .pattern = "strcpy", .sink = .buffer_write },
    .{ .pattern = "strcat", .sink = .buffer_write },
    .{ .pattern = "memcpy", .sink = .buffer_write },
    .{ .pattern = "memmove", .sink = .buffer_write },
    .{ .pattern = "wcscpy", .sink = .buffer_write },
    .{ .pattern = "send", .sink = .network_send },
    .{ .pattern = "sendto", .sink = .network_send },
    .{ .pattern = "WSASend", .sink = .network_send },
    .{ .pattern = "fwrite", .sink = .file_write },
    .{ .pattern = "WriteFile", .sink = .file_write },
    .{ .pattern = "RegSetValueEx", .sink = .registry_write },
    .{ .pattern = "malloc", .sink = .memory_allocation },
    .{ .pattern = "calloc", .sink = .memory_allocation },
    .{ .pattern = "realloc", .sink = .memory_allocation },
    .{ .pattern = "VirtualAlloc", .sink = .memory_allocation },
    .{ .pattern = "HeapAlloc", .sink = .memory_allocation },
    .{ .pattern = "LocalAlloc", .sink = .memory_allocation },
};

fn classifySource(name: []const u8) ?TaintSource {
    for (source_function_patterns) |entry| {
        if (utils.asciiContainsIgnoreCase(name, entry.pattern)) return entry.source;
    }
    return null;
}

fn classifySink(name: []const u8) ?TaintSink {
    for (sink_function_patterns) |entry| {
        if (utils.asciiContainsIgnoreCase(name, entry.pattern)) return entry.sink;
    }
    return null;
}

fn isSanitizationFunction(name: []const u8) ?[]const u8 {
    if (utils.containsAny(name, &.{ "sanitize", "validate", "escape", "clean" })) return "generic_sanitizer";
    if (utils.containsAny(name, &.{ "IsBadReadPtr", "IsBadWritePtr", "SafeLength" })) return "pointer_validation";
    if (utils.containsAny(name, &.{ "strlen", "wcslen", "strnlen", "tcslen" })) return "length_check";
    if (utils.containsAny(name, &.{ "nCount", "cbSize", "dwSize", "GetFileSize" })) return "size_limit";
    return null;
}

pub fn analyzeTaint(allocator: Allocator, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan, call_edges: []const CallEdge) !TaintAnalysis {
    var sources = std.ArrayList(DataFlowSource).init(allocator);
    errdefer sources.deinit();
    var sinks = std.ArrayList(DataFlowSink).init(allocator);
    errdefer sinks.deinit();
    var propagations = std.ArrayList(TaintPropagation).init(allocator);
    errdefer {
        for (propagations.items) |*p| p.deinit(allocator);
        propagations.deinit();
    }

    var source_map = std.AutoHashMap(u64, DataFlowSource).init(allocator);
    defer source_map.deinit();
    var sink_map = std.AutoHashMap(u64, DataFlowSink).init(allocator);
    defer sink_map.deinit();

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                const name = resolved.name;

                if (classifySource(name)) |source| {
                    try sources.append(.{
                        .va = instr.va,
                        .function_va = function.start,
                        .source_type = source,
                        .reg = .rax,
                        .description = name,
                    });
                    try source_map.put(instr.va, sources.items[sources.items.len - 1]);
                }

                if (classifySink(name)) |sink| {
                    try sinks.append(.{
                        .va = instr.va,
                        .function_va = function.start,
                        .sink_type = sink,
                        .reg = .rax,
                        .description = name,
                    });
                    try sink_map.put(instr.va, sinks.items[sinks.items.len - 1]);
                }
            }
        }
    }

    var interprocedural_sources = std.ArrayList(DataFlowSource).init(allocator);
    defer interprocedural_sources.deinit();
    try interprocedural_sources.appendSlice(sources.items);

    for (call_edges) |edge| {
        for (sources.items) |src| {
            if (src.function_va == edge.from) {
                for (functions) |fn_dst| {
                    if (fn_dst.start == edge.to) {
                        try interprocedural_sources.append(.{
                            .va = fn_dst.start,
                            .function_va = fn_dst.start,
                            .source_type = src.source_type,
                            .reg = .rax,
                            .description = src.description,
                        });
                    }
                }
            }
        }
    }

    for (interprocedural_sources.items) |src| {
        if (source_map.get(src.va) == null) {
            try sources.append(src);
            try source_map.put(src.va, src);
        }
    }

    var total_paths: usize = 0;
    var unvalidated_paths: usize = 0;
    var high_severity: usize = 0;
    var critical_severity: usize = 0;

    for (sources.items) |source| {
        for (sinks.items) |sink| {
            total_paths += 1;
            const path = try traceTaintPath(allocator, instrs, functions, call_edges, source, sink, image);
            if (path) |_| {
                var p = path.?;
                if (p.sanitized) {
                    p.deinit(allocator);
                    continue;
                }
                if (@intFromEnum(p.severity) >= @intFromEnum(TaintSeverity.high)) high_severity += 1;
                if (@intFromEnum(p.severity) >= @intFromEnum(TaintSeverity.critical)) critical_severity += 1;
                unvalidated_paths += 1;
                try propagations.append(p);
            }
        }
    }

    const taint_score = computeTaintScore(propagations.items, total_paths, unvalidated_paths);

    return .{
        .sources = try sources.toOwnedSlice(),
        .sinks = try sinks.toOwnedSlice(),
        .propagations = try propagations.toOwnedSlice(),
        .unvalidated_paths = unvalidated_paths,
        .total_paths = total_paths,
        .taint_gap_score = taint_score,
        .high_severity_count = high_severity,
        .critical_severity_count = critical_severity,
    };
}

fn traceTaintPath(allocator: Allocator, instrs: []const Decoded, functions: []const FunctionSpan, call_edges: []const CallEdge, source: DataFlowSource, sink: DataFlowSink, image: BinaryImage) !?TaintPropagation {
    var visited = std.AutoHashMap(u64, void).init(allocator);
    defer visited.deinit();

    var path_funcs = std.ArrayList(u64).init(allocator);
    errdefer path_funcs.deinit();

    const queue_size = 4096;
    var queue: [queue_size]struct { func_va: u64, depth: usize } = undefined;
    var head: usize = 0;
    var tail: usize = 0;

    try visited.put(source.function_va, {});
    if (tail < queue_size) {
        queue[tail] = .{ .func_va = source.function_va, .depth = 0 };
        tail += 1;
    }

    var found = false;
    var found_depth: usize = undefined;

    while (head < tail and !found) {
        const current = queue[head];
        head += 1;

        if (current.func_va == sink.function_va) {
            found = true;
            found_depth = current.depth;
            break;
        }

        if (current.depth >= 20) break;

        for (call_edges) |edge| {
            if (edge.from == current.func_va) {
                if (!visited.contains(edge.to) and tail < queue_size) {
                    try visited.put(edge.to, {});
                    queue[tail] = .{ .func_va = edge.to, .depth = current.depth + 1 };
                    tail += 1;
                }
            }
        }
    }

    if (!found) return null;

    try path_funcs.ensureTotalCapacity(found_depth + 2);
    var reverse_path: [256]u64 = undefined;
    var rp_len: usize = 0;
    var current_search = sink.function_va;
    var depth = found_depth;

    while (depth > 0) {
        reverse_path[rp_len] = current_search;
        rp_len += 1;
        for (call_edges) |edge| {
            if (edge.to == current_search) {
                current_search = edge.from;
                break;
            }
        }
        depth -= 1;
    }
    reverse_path[rp_len] = current_search;
    rp_len += 1;

    var i: usize = rp_len;
    while (i > 0) {
        i -= 1;
        path_funcs.appendAssumeCapacity(reverse_path[i]);
    }

    var sanitized = false;
    var sanitization: []const u8 = "";
    for (path_funcs.items) |func_va| {
        for (functions) |func| {
            if (func.start == func_va) {
                const func_instrs = instrs[func.instr_start..func.instr_end];
                for (func_instrs) |instr| {
                    if (instr.kind == .call) {
                        const resolved = decoder.resolveCallInfo(image, instr);
                        if (isSanitizationFunction(resolved.name)) |stype| {
                            sanitized = true;
                            sanitization = stype;
                        }
                    }
                }
            }
        }
    }

    const severity = classifyTaintSeverity(source.source_type, sink.sink_type, sanitized);

    const owned_funcs = try path_funcs.toOwnedSlice();
    return TaintPropagation{
        .source_va = source.va,
        .sink_va = sink.va,
        .source_type = source.source_type,
        .sink_type = sink.sink_type,
        .path_length = found_depth + 1,
        .function_vas = owned_funcs,
        .severity = severity,
        .sanitized = sanitized,
        .sanitization_type = sanitization,
        .description = try buildTaintDescription(allocator, source, sink, sanitized),
    };
}

fn buildTaintDescription(allocator: Allocator, source: DataFlowSource, sink: DataFlowSink, sanitized: bool) ![]const u8 {
    const sname = @tagName(source.source_type);
    const snkname = @tagName(sink.sink_type);
    const prefix = if (sanitized) "Sanitized taint: " else "Unvalidated taint: ";
    const text = try std.fmt.allocPrint(allocator, "{s}{s} -> {s} via {s}", .{ prefix, sname, snkname, source.description });
    return text;
}

fn classifyTaintSeverity(_: TaintSource, sink: TaintSink, sanitized: bool) TaintSeverity {
    if (sanitized) return .low;
    const critical_sinks = [_]TaintSink{ .code_execution, .command_injection, .privilege_elevation };
    for (critical_sinks) |cs| {
        if (sink == cs) return .critical;
    }
    const high_sinks = [_]TaintSink{ .sql_query, .format_string, .jump_target };
    for (high_sinks) |hs| {
        if (sink == hs) return .high;
    }
    if (sink == .buffer_write or sink == .memory_allocation) return .high;
    return .medium;
}

fn computeTaintScore(propagations: []const TaintPropagation, total_paths: usize, unvalidated: usize) f64 {
    if (total_paths == 0) return 0;
    var score: f64 = 0;
    score += @as(f64, @floatFromInt(unvalidated)) * 25.0 / @max(@as(f64, @floatFromInt(total_paths)), 1.0);
    var critical_count: usize = 0;
    var high_count: usize = 0;
    for (propagations) |p| {
        if (p.severity == .critical) critical_count += 1;
        if (p.severity == .high) high_count += 1;
    }
    score += @as(f64, @floatFromInt(critical_count)) * 20.0;
    score += @as(f64, @floatFromInt(high_count)) * 10.0;
    return utils.clamp100(score);
}

pub fn analyzeTaintInFunction(allocator: Allocator, instrs: []const Decoded, function: FunctionSpan, image: BinaryImage) ![]TaintPropagation {
    var results = std.ArrayList(TaintPropagation).init(allocator);
    errdefer {
        for (results.items) |*p| p.deinit(allocator);
        results.deinit();
    }

    const func_instrs = instrs[function.instr_start..function.instr_end];
    var tracked_regs: [8]struct { reg: Reg, tainted: bool, source: TaintSource, depth: usize } = undefined;
    for (&tracked_regs) |*tr| {
        tr.* = .{ .reg = .none, .tainted = false, .source = .user_input, .depth = 0 };
    }
    var tracked_count: usize = 0;

    for (func_instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (classifySource(resolved.name)) |source| {
                if (tracked_count < 8) {
                    tracked_regs[tracked_count] = .{ .reg = .rax, .tainted = true, .source = source, .depth = 0 };
                    tracked_count += 1;
                }
            }
            if (classifySink(resolved.name)) |sink| {
                for (0..tracked_count) |i| {
                    if (tracked_regs[i].tainted) {
                        const path_funcs = try allocator.alloc(u64, 1);
                        path_funcs[0] = function.start;
                        try results.append(.{
                            .source_va = 0,
                            .sink_va = instr.va,
                            .source_type = tracked_regs[i].source,
                            .sink_type = sink,
                            .path_length = 1,
                            .function_vas = path_funcs,
                            .severity = classifyTaintSeverity(tracked_regs[i].source, sink, false),
                            .sanitized = false,
                            .description = "Intra-function taint propagation detected",
                        });
                        tracked_regs[i].tainted = false;
                    }
                }
            }
        }

        if (tracked_count > 0) {
            for (0..tracked_count) |i| {
                if (!tracked_regs[i].tainted) continue;
                if (instrTouchesReg(instr, tracked_regs[i].reg)) {
                    tracked_regs[i].depth += 1;
                }
            }
        }
    }

    return results.toOwnedSlice();
}

fn instrTouchesReg(instr: Decoded, reg: Reg) bool {
    for (0..instr.op_count) |i| {
        const op = instr.operand(i);
        if (op.kind == .reg and decoder.regFamily(op.reg) == decoder.regFamily(reg)) return true;
        if (op.kind == .mem and decoder.regFamily(op.base) == decoder.regFamily(reg)) return true;
    }
    return false;
}
