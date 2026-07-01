const std = @import("std");
const types = @import("../types.zig");
const utils = @import("utils.zig");
const parser = @import("parser.zig");

const Allocator = types.Allocator;
const Arch = types.Arch;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const InstrKind = types.InstrKind;
const FunctionSpan = types.FunctionSpan;
const Reg = types.Reg;
const Operand = types.Operand;
const OperandKind = types.OperandKind;
const PrefixInfo = types.PrefixInfo;
const ModRm = types.ModRm;
const ImportSymbol = types.ImportSymbol;
const Symbol = types.Symbol;
const Section = types.Section;
const ResolvedName = types.ResolvedName;
const CallEdge = types.CallEdge;
const CallType = types.CallType;
const BasicBlock = types.BasicBlock;

pub fn decodeAll(allocator: Allocator, bytes: []const u8, image: BinaryImage) ![]Decoded {
    var out = std.ArrayList(Decoded).init(allocator);
    errdefer out.deinit();
    for (image.sections) |section| {
        if (!section.executable) continue;
        const code = parser.sectionBytes(bytes, section);
        var off: usize = 0;
        while (off < code.len) {
            const va = section.va + @as(u64, @intCast(off));
            const d = switch (image.arch) {
                .x86, .x86_64 => decodeX86(code, off, va, image.arch),
                .arm64, .arm => decodeArm64(code, off, va),
                else => decodeFallback(code, off, va),
            };
            if (d.len == 0) break;
            try out.append(d);
            off += d.len;
        }
    }
    return out.toOwnedSlice();
}

pub fn detectFunctions(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]FunctionSpan {
    var starts = std.ArrayList(u64).init(allocator);
    defer starts.deinit();
    if (instrs.len == 0) return allocator.alloc(FunctionSpan, 0);

    var index_by_va = std.AutoHashMap(u64, usize).init(allocator);
    defer index_by_va.deinit();
    try index_by_va.ensureTotalCapacity(@intCast(instrs.len));
    for (instrs, 0..) |instr, idx| {
        index_by_va.putAssumeCapacity(instr.va, idx);
    }

    try appendUniqueVa(&starts, image.entry_va);
    try appendUniqueVa(&starts, instrs[0].va);
    for (image.symbols) |sym| {
        if (sym.is_function and sym.va != 0 and index_by_va.contains(sym.va)) {
            try appendUniqueVa(&starts, sym.va);
        }
    }
    for (instrs, 0..) |instr, idx| {
        if (idx + 1 < instrs.len and isLikelyFunctionStart(instrs, idx)) try appendUniqueVa(&starts, instr.va);
        if (instr.kind == .call) {
            if (instr.target) |target| {
                if (index_by_va.contains(target)) try appendUniqueVa(&starts, target);
            }
        }
        if (idx + 1 < instrs.len and instr.kind == .ret) try appendUniqueVa(&starts, instrs[idx + 1].va);
    }
    std.mem.sort(u64, starts.items, {}, utils.u64Less);

    var funcs = std.ArrayList(FunctionSpan).init(allocator);
    errdefer funcs.deinit();

    for (starts.items, 0..) |start, si| {
        const sidx = index_by_va.get(start) orelse continue;
        const next_start = if (si + 1 < starts.items.len) starts.items[si + 1] else std.math.maxInt(u64);
        var eidx = sidx;
        while (eidx < instrs.len and instrs[eidx].va < next_start) : (eidx += 1) {}
        if (eidx == sidx) continue;
        const end_va = instrs[eidx - 1].va + instrs[eidx - 1].len;

        var call_count: usize = 0;
        var is_leaf = true;
        for (instrs[sidx..eidx]) |instr| {
            if (instr.kind == .call) {
                call_count += 1;
                is_leaf = false;
            }
        }

        const is_plt = for (image.imports) |imp| {
            if (imp.plt_va == start) break true;
        } else false;

        try funcs.append(.{
            .start = start, .end = end_va,
            .instr_start = sidx, .instr_end = eidx,
            .is_leaf = is_leaf, .is_plt = is_plt,
            .call_count = call_count,
        });
    }
    return funcs.toOwnedSlice();
}

pub fn buildCallEdges(allocator: Allocator, instrs: []const Decoded, functions: []const FunctionSpan) ![]CallEdge {
    var edges = std.ArrayList(CallEdge).init(allocator);
    errdefer edges.deinit();
    for (functions) |function| {
        for (instrs[function.instr_start..function.instr_end]) |instr| {
            if (instr.kind != .call) continue;
            const target = instr.target orelse continue;
            const dest = functionForVa(functions, target) orelse continue;
            if (dest.start == function.start) continue;
            var exists = false;
            for (edges.items) |edge| {
                if (edge.from == function.start and edge.to == dest.start) {
                    exists = true;
                    break;
                }
            }
            if (!exists) try edges.append(.{ .from = function.start, .to = dest.start, .call_type = if (instr.indirect) .indirect else .direct });
        }
    }
    return edges.toOwnedSlice();
}

pub fn buildBasicBlocks(allocator: Allocator, instrs: []const Decoded, functions: []const FunctionSpan) ![]BasicBlock {
    var blocks = std.ArrayList(BasicBlock).init(allocator);
    errdefer blocks.deinit();
    for (functions) |func| {
        var block_start = func.instr_start;
        var i = func.instr_start;
        while (i < func.instr_end) {
            const instr = instrs[i];
            if (instr.isBranch() or i == func.instr_start) {
                if (i > func.instr_start and i != block_start) {
                    try blocks.append(.{
                        .start_va = instrs[block_start].va,
                        .end_va = instrs[i - 1].va + instrs[i - 1].len,
                        .instr_start = block_start,
                        .instr_end = i,
                        .successors = &[_]u64{},
                        .predecessors = &[_]u64{},
                    });
                }
                block_start = i;
            }
            if (instr.isTerminal() or (i + 1 < func.instr_end and instrs[i + 1].isBranch() and instrs[i + 1].kind != .call)) {
                try blocks.append(.{
                    .start_va = instrs[block_start].va,
                    .end_va = instrs[i].va + instrs[i].len,
                    .instr_start = block_start,
                    .instr_end = i + 1,
                    .successors = &[_]u64{},
                    .predecessors = &[_]u64{},
                });
                block_start = i + 1;
            }
            i += 1;
        }
        if (block_start < func.instr_end) {
            try blocks.append(.{
                .start_va = instrs[block_start].va,
                .end_va = instrs[func.instr_end - 1].va + instrs[func.instr_end - 1].len,
                .instr_start = block_start,
                .instr_end = func.instr_end,
                .successors = &[_]u64{},
                .predecessors = &[_]u64{},
            });
        }
    }
    return blocks.toOwnedSlice();
}

fn functionForVa(functions: []const FunctionSpan, va: u64) ?FunctionSpan {
    var lo: usize = 0;
    var hi: usize = functions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const function = functions[mid];
        if (va < function.start) {
            hi = mid;
        } else if (va >= function.end) {
            lo = mid + 1;
        } else {
            return function;
        }
    }
    return null;
}

fn appendUniqueVa(list: *std.ArrayList(u64), va: u64) !void {
    for (list.items) |existing| {
        if (existing == va) return;
    }
    try list.append(va);
}

fn isFramePrologue(instrs: []const Decoded, idx: usize) bool {
    if (idx + 1 >= instrs.len) return false;
    const first = instrs[idx];
    const second = instrs[idx + 1];
    return first.kind == .push and first.op_count > 0 and first.operand(0).reg == .rbp and
        second.kind == .mov and second.op_count >= 2 and
        second.operand(0).kind == .reg and second.operand(0).reg == .rbp and
        second.operand(1).kind == .reg and second.operand(1).reg == .rsp;
}

fn isLikelyFunctionStart(instrs: []const Decoded, idx: usize) bool {
    if (isFramePrologue(instrs, idx)) return true;
    const first = instrs[idx];
    if (first.kind == .sub and first.op_count > 0 and first.operand(0).kind == .reg and first.operand(0).reg == .rsp) return true;
    if (first.kind != .push or first.op_count == 0 or !isCalleeSaved(first.operand(0).reg)) return false;
    const end = @min(instrs.len, idx + 5);
    var j = idx + 1;
    while (j < end) : (j += 1) {
        const instr = instrs[j];
        if (instr.kind == .push and instr.op_count > 0 and isCalleeSaved(instr.operand(0).reg)) return true;
        if (instr.kind == .sub and instr.op_count > 0 and instr.operand(0).kind == .reg and instr.operand(0).reg == .rsp) return true;
        if (instr.kind == .mov and instr.op_count >= 2 and instr.operand(0).kind == .reg and instr.operand(0).reg == .rbp and instr.operand(1).kind == .reg and instr.operand(1).reg == .rsp) return true;
        if (instr.kind == .call or instr.kind == .ret or instr.kind == .jmp) break;
    }
    return false;
}

fn isCalleeSaved(reg: Reg) bool {
    return switch (regFamily(reg)) {
        .rbx, .rbp, .r12, .r13, .r14, .r15 => true,
        else => false,
    };
}

pub fn resolveCallInfo(image: BinaryImage, instr: Decoded) ResolvedName {
    const mem_va = if (instr.op_count > 0 and instr.operand(0).kind == .mem) instr.operand(0).mem_va else null;
    for (image.imports) |imp| {
        if (mem_va != null and importAddressMatches(imp, mem_va.?)) return .{ .name = imp.name, .external = true };
        if (instr.target != null and importAddressMatches(imp, instr.target.?)) return .{ .name = imp.name, .external = true };
    }
    if (instr.target) |target| {
        if (symbolAt(image.symbols, target)) |sym| return .{ .name = sym.name, .external = sym.external };
    }
    return .{ .name = if (instr.indirect) "indirect_call" else "direct_call", .external = false };
}

fn importAddressMatches(imp: ImportSymbol, va: u64) bool {
    return (imp.iat_va != 0 and va == imp.iat_va) or
        (imp.plt_va != 0 and va == imp.plt_va) or
        (imp.got_va != 0 and va == imp.got_va);
}

fn symbolAt(symbols: []const Symbol, va: u64) ?Symbol {
    for (symbols) |sym| {
        if (sym.va == va and sym.name.len != 0) return sym;
    }
    return null;
}

pub fn callReturnChecked(instrs: []const Decoded, span: FunctionSpan, call_idx: usize) bool {
    var tracked = [_]Reg{ .none, .none, .none, .none };
    var tracked_count: usize = 1;
    tracked[0] = .rax;
    var saw_return_test = false;
    var idx = call_idx + 1;
    const end = @min(span.instr_end, call_idx + 1 + @max(types.max_following_check, @as(usize, 12)));
    while (idx < end) : (idx += 1) {
        const instr = instrs[idx];
        if (instr.kind == .mov and instr.op_count >= 2 and instr.operand(0).kind == .reg and operandTouchesTrackedReg(instr.operand(1), tracked[0..tracked_count])) {
            addTrackedReg(&tracked, &tracked_count, instr.operand(0).reg);
        }
        if ((instr.kind == .cmp or instr.kind == .test_) and instrTouchesTrackedReg(instr, tracked[0..tracked_count])) {
            if (hasZeroImmediateOperand(instr) or hasRegOperand(instr, .rax) or hasRegOperand(instr, .eax)) {
                saw_return_test = true;
            }
        }
        if (instr.kind == .jcc and saw_return_test) return true;
        if (saw_return_test and (instr.kind == .ret or instr.kind == .jmp)) return true;
        if (instr.kind == .call) {
            removeTrackedReg(&tracked, &tracked_count, .rax);
            if (tracked_count == 0) break;
        }
    }
    return saw_return_test;
}

fn hasZeroImmediateOperand(instr: Decoded) bool {
    for (0..instr.op_count) |i| {
        const op = instr.operand(i);
        if (op.kind == .imm and op.imm == 0) return true;
    }
    return false;
}

fn hasRegOperand(instr: Decoded, reg: Reg) bool {
    for (0..instr.op_count) |i| {
        const op = instr.operand(i);
        if (op.kind == .reg and regFamily(op.reg) == regFamily(reg)) return true;
    }
    return false;
}

fn operandTouchesReg(instr: Decoded, reg: Reg) bool {
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .reg and regFamily(op.reg) == regFamily(reg)) return true;
    }
    return false;
}

pub fn regFamily(reg: Reg) Reg {
    return switch (reg) {
        .eax, .ax, .al => .rax,
        .ecx, .cx, .cl => .rcx,
        .edx, .dx, .dl => .rdx,
        .ebx, .bx, .bl => .rbx,
        .esp => .rsp,
        .ebp => .rbp,
        .esi => .rsi,
        .edi => .rdi,
        .r8d, .r8w, .r8b => .r8,
        .r9d, .r9w, .r9b => .r9,
        .r10d, .r10w, .r10b => .r10,
        .r11d, .r11w, .r11b => .r11,
        .r12d, .r12w, .r12b => .r12,
        .r13d, .r13w, .r13b => .r13,
        .r14d, .r14w, .r14b => .r14,
        .r15d, .r15w, .r15b => .r15,
        else => reg,
    };
}

fn instrTouchesTrackedReg(instr: Decoded, tracked: []const Reg) bool {
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        if (operandTouchesTrackedReg(instr.operand(i), tracked)) return true;
    }
    return false;
}

fn operandTouchesTrackedReg(op: Operand, tracked: []const Reg) bool {
    if (op.kind != .reg) return false;
    for (tracked) |reg| {
        if (reg != .none and regFamily(op.reg) == regFamily(reg)) return true;
    }
    return false;
}

fn addTrackedReg(tracked: *[4]Reg, tracked_count: *usize, reg: Reg) void {
    const family = regFamily(reg);
    for (tracked[0..tracked_count.*]) |existing| {
        if (regFamily(existing) == family) return;
    }
    if (tracked_count.* < tracked.len) {
        tracked[tracked_count.*] = family;
        tracked_count.* += 1;
    }
}

fn removeTrackedReg(tracked: *[4]Reg, tracked_count: *usize, reg: Reg) void {
    const family = regFamily(reg);
    var out: usize = 0;
    for (tracked[0..tracked_count.*]) |existing| {
        if (regFamily(existing) == family) continue;
        tracked[out] = existing;
        out += 1;
    }
    const new_count = out;
    while (out < tracked_count.*) : (out += 1) tracked[out] = .none;
    tracked_count.* = new_count;
}

fn decodeArm64(code: []const u8, offset: usize, va: u64) Decoded {
    if (offset + 4 > code.len) return .{ .off = offset, .va = va, .len = 0 };
    const word = utils.readInt(code, u32, offset, .little) catch return .{ .off = offset, .va = va, .len = 4, .kind = .other };
    const opcode_top = word >> 26;
    const opcode_bits = word & 0xff000010;

    if (opcode_top == 0x25) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .call, .target = rel26TargetArm64(va, word) };
    }
    if (opcode_top == 0x05) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .jmp, .target = rel26TargetArm64(va, word) };
    }
    if (opcode_bits == 0x54000000) {
        const cond = word & 0x0f;
        _ = cond;
        return .{ .off = offset, .va = va, .len = 4, .kind = .jcc, .target = rel19TargetArm64(va, word) };
    }
    if (word == 0xd65f03c0 or word == 0xd65f03bf) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .ret };
    }
    if ((word & 0x7c000000) == 0x14000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .jmp, .target = rel26TargetArm64(va, word) };
    }
    if ((word & 0x3b000000) == 0x18000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .mov };
    }
    if ((word & 0x1f000000) == 0x0b000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .add };
    }
    if ((word & 0x1f000000) == 0x0f000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .sub };
    }
    if ((word & 0x1f800000) == 0x0a000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .and_ };
    }
    if ((word & 0x1f800000) == 0x2a000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .or_ };
    }
    if ((word & 0x1f800000) == 0x4a000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .xor_ };
    }
    if ((word & 0xff000000) == 0x91000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .lea };
    }
    if ((word & 0xff000000) == 0xf9000000 or (word & 0xff000000) == 0xb9000000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .mov, .mem_write = true };
    }
    if ((word & 0xff000000) == 0xf9400000 or (word & 0xff000000) == 0xb9400000) {
        return .{ .off = offset, .va = va, .len = 4, .kind = .mov, .mem_read = true };
    }
    return .{ .off = offset, .va = va, .len = 4 };
}

fn rel26TargetArm64(va: u64, word: u32) ?u64 {
    const imm26 = word & 0x03ff_ffff;
    var disp: i64 = @intCast(imm26);
    if ((imm26 & 0x0200_0000) != 0) disp -= @as(i64, 1) << 26;
    disp *= 4;
    return addSigned(va, disp);
}

fn rel19TargetArm64(va: u64, word: u32) ?u64 {
    const imm19 = (word >> 5) & 0x7_ffff;
    var disp: i64 = @intCast(imm19);
    if ((imm19 & 0x4_0000) != 0) disp -= @as(i64, 1) << 19;
    disp *= 4;
    return addSigned(va, disp);
}

fn decodeFallback(code: []const u8, offset: usize, va: u64) Decoded {
    if (offset >= code.len) return .{ .off = offset, .va = va, .len = 0 };
    if (offset + 4 <= code.len) {
        const word = utils.readInt(code, u32, offset, .little) catch 0;
        if ((word & 0xfc000000) == 0x94000000) {
            return .{ .off = offset, .va = va, .len = 4, .kind = .call, .target = rel26Target(va, word) };
        }
        if ((word & 0x7c000000) == 0x14000000) {
            return .{ .off = offset, .va = va, .len = 4, .kind = .jmp, .target = rel26Target(va, word) };
        }
        if ((word & 0xff000010) == 0x54000000) {
            return .{ .off = offset, .va = va, .len = 4, .kind = .jcc };
        }
        if (word == 0xd65f03c0) {
            return .{ .off = offset, .va = va, .len = 4, .kind = .ret };
        }
        return .{ .off = offset, .va = va, .len = 4 };
    }
    return .{ .off = offset, .va = va, .len = code.len - offset };
}

fn rel26Target(va: u64, word: u32) ?u64 {
    const imm26 = word & 0x03ff_ffff;
    var disp: i64 = @intCast(imm26);
    if ((imm26 & 0x0200_0000) != 0) disp -= @as(i64, 1) << 26;
    disp *= 4;
    return addSigned(va, disp);
}

fn decodeX86(code: []const u8, offset: usize, va: u64, arch: Arch) Decoded {
    if (offset >= code.len) return .{ .off = offset, .va = va, .len = 0 };
    const p = parsePrefixes(code, offset, arch);
    if (p.cursor >= code.len) return .{ .off = offset, .va = va, .len = code.len - offset };
    if (p.vex_evex) return boundedDecoded(code, offset, va, p.cursor - offset + 1, .other);

    const opcode_offset = p.cursor;
    const opcode = code[opcode_offset];
    const prefix_len = opcode_offset - offset;
    const immz: usize = if (p.operand_override) 2 else 4;

    if (opcode == 0x0f) return decodeX86TwoByte(code, offset, opcode_offset, va, arch, p, prefix_len);

    if (opcode >= 0x70 and opcode <= 0x7f) {
        var d = boundedDecoded(code, offset, va, prefix_len + 2, .jcc);
        d.target = rel8Target(code, opcode_offset + 1, va, d.len);
        return d;
    }
    if (opcode >= 0xb8 and opcode <= 0xbf) {
        const imm_bytes: usize = if (arch == .x86_64 and p.rex_w) 8 else immz;
        var d = boundedDecoded(code, offset, va, prefix_len + 1 + imm_bytes, .mov);
        d.op_count = 2;
        d.operands[0] = regOperand(regFromBits((opcode - 0xb8) & 0x7, p.rex_b));
        d.operands[1] = immOperand(readImmediate(code, opcode_offset + 1, imm_bytes));
        d.has_modrm = false;
        return d;
    }

    switch (opcode) {
        0xc3 => return boundedDecoded(code, offset, va, prefix_len + 1, .ret),
        0xc2 => return boundedDecoded(code, offset, va, prefix_len + 3, .ret),
        0xe8 => {
            var d = boundedDecoded(code, offset, va, prefix_len + 5, .call);
            d.target = rel32Target(code, opcode_offset + 1, va, d.len);
            d.op_count = 1;
            if (d.target) |target| d.operands[0] = immOperand(target);
            return d;
        },
        0xe9, 0xeb => {
            var d = boundedDecoded(code, offset, va, prefix_len + if (opcode == 0xeb) @as(usize, 2) else @as(usize, 5), .jmp);
            d.target = if (opcode == 0xeb) rel8Target(code, opcode_offset + 1, va, d.len) else rel32Target(code, opcode_offset + 1, va, d.len);
            return d;
        },
        0xe0, 0xe1, 0xe2, 0xe3 => {
            var d = boundedDecoded(code, offset, va, prefix_len + 2, .jcc);
            d.target = rel8Target(code, opcode_offset + 1, va, d.len);
            return d;
        },
        0x3c => return decodeAccumulatorImmediate(code, offset, opcode_offset, va, prefix_len, .cmp, 1),
        0x3d => return decodeAccumulatorImmediate(code, offset, opcode_offset, va, prefix_len, .cmp, immz),
        0xa8 => return decodeAccumulatorImmediate(code, offset, opcode_offset, va, prefix_len, .test_, 1),
        0xa9 => return decodeAccumulatorImmediate(code, offset, opcode_offset, va, prefix_len, .test_, immz),
        0x50...0x57 => {
            var d = boundedDecoded(code, offset, va, prefix_len + 1, .push);
            d.op_count = 1;
            d.operands[0] = regOperand(regFromBits((opcode - 0x50) & 0x7, p.rex_b));
            return d;
        },
        0x58...0x5f => {
            var d = boundedDecoded(code, offset, va, prefix_len + 1, .pop);
            d.op_count = 1;
            d.operands[0] = regOperand(regFromBits((opcode - 0x58) & 0x7, p.rex_b));
            return d;
        },
        0x68 => {
            var d = boundedDecoded(code, offset, va, prefix_len + 5, .push);
            d.op_count = 1;
            d.operands[0] = immOperand(readImmediate(code, opcode_offset + 1, 4));
            return d;
        },
        0x6a => {
            var d = boundedDecoded(code, offset, va, prefix_len + 2, .push);
            d.op_count = 1;
            d.operands[0] = immOperand(readImmediate(code, opcode_offset + 1, 1));
            return d;
        },
        0x38, 0x39, 0x3a, 0x3b => return decodeCmpRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode),
        0x84, 0x85 => return decodeTestRegMem(code, offset, opcode_offset, va, arch, p, prefix_len),
        0x88, 0x89, 0x8a, 0x8b => return decodeMovRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode),
        0x8d => return decodeLea(code, offset, opcode_offset, va, arch, p, prefix_len),
        0x31, 0x33 => return decodeBinaryRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, .xor_),
        0x21, 0x23 => return decodeBinaryRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, .and_),
        0x09, 0x0b => return decodeBinaryRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, .or_),
        0x01, 0x03 => return decodeBinaryRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, .add),
        0x29, 0x2b => return decodeBinaryRegMem(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, .sub),
        0x80, 0x81, 0x83 => return decodeGroupImmediate(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, immz),
        0xc7 => return decodeMovImmediateToRm(code, offset, opcode_offset, va, arch, p, prefix_len, immz),
        0xf6, 0xf7 => return decodeTestGroup(code, offset, opcode_offset, va, arch, p, prefix_len, opcode, immz),
        0xff => return decodeGroupFF(code, offset, opcode_offset, va, arch, p, prefix_len),
        0x90 => return boundedDecoded(code, offset, va, prefix_len + 1, .nop),
        0xf4 => return boundedDecoded(code, offset, va, 1, .other),
        0xcc, 0xcd => return boundedDecoded(code, offset, va, if (opcode == 0xcc) @as(usize, 1) else @as(usize, 2), .int3),
        else => return boundedDecoded(code, offset, va, 1, .other),
    }
}

fn parsePrefixes(code: []const u8, offset: usize, arch: Arch) PrefixInfo {
    var p = PrefixInfo{ .cursor = offset };
    while (p.cursor < code.len) : (p.cursor += 1) {
        const b = code[p.cursor];
        switch (b) {
            0xf0 => { p.lock = true; continue; },
            0xf2 => { p.repne = true; continue; },
            0xf3 => { p.rep = true; continue; },
            0x2e => { p.branch_not_taken = true; continue; },
            0x36 => { continue; },
            0x3e => { p.branch_taken = true; continue; },
            0x26 => continue,
            0x64 => continue,
            0x65 => continue,
            0x66 => { p.operand_override = true; continue; },
            0x67 => { p.address_override = true; continue; },
            0xc4, 0xc5, 0x62 => {
                if (p.cursor == offset) {
                    p.vex_evex = true;
                    p.cursor += if (b == 0xc4) @as(usize, 3) else if (b == 0xc5) @as(usize, 2) else @as(usize, 4);
                    return p;
                }
                break;
            },
            else => {
                if (arch == .x86_64 and b >= 0x40 and b <= 0x4f) {
                    p.rex_w = (b & 0x08) != 0;
                    p.rex_r = (b & 0x04) != 0;
                    p.rex_x = (b & 0x02) != 0;
                    p.rex_b = (b & 0x01) != 0;
                    continue;
                }
                break;
            },
        }
    }
    return p;
}

fn boundedDecoded(code: []const u8, offset: usize, va: u64, wanted_len: usize, kind: InstrKind) Decoded {
    const remaining = code.len - offset;
    const len = @max(@as(usize, 1), @min(wanted_len, remaining));
    return .{ .off = offset, .va = va, .len = len, .kind = kind };
}

fn decodeX86TwoByte(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize) Decoded {
    if (opcode_offset + 1 >= code.len) return .{ .off = offset, .va = va, .len = code.len - offset };
    const opcode2 = code[opcode_offset + 1];
    if (opcode2 >= 0x80 and opcode2 <= 0x8f) {
        var d = boundedDecoded(code, offset, va, prefix_len + 6, .jcc);
        d.target = rel32Target(code, opcode_offset + 2, va, d.len);
        return d;
    }
    if (opcode2 == 0x1f) {
        const modrm = parseModRm(code, opcode_offset + 2, arch, p) orelse return boundedDecoded(code, offset, va, 2, .nop);
        return boundedDecoded(code, offset, va, prefix_len + 2 + modrm.len, .nop);
    }
    if (opcode2 == 0xb6 or opcode2 == 0xb7 or opcode2 == 0xbe or opcode2 == 0xbf) {
        const modrm = parseModRm(code, opcode_offset + 2, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
        var rm = modrm.rm;
        const len = prefix_len + 2 + modrm.len;
        finalizeMemVa(&rm, va, len);
        var d = boundedDecoded(code, offset, va, len, .mov);
        d.op_count = 2;
        d.operands[0] = regOperand(modrm.reg);
        d.operands[1] = rm;
        d.mem_read = rm.kind == .mem;
        d.has_modrm = true;
        return d;
    }
    if (opcode2 == 0x05) {
        return boundedDecoded(code, offset, va, prefix_len + 7, .syscall);
    }
    if (opcode2 == 0x34) {
        return boundedDecoded(code, offset, va, prefix_len + 2, .sysenter);
    }
    if (opcode2 == 0x31) {
        return boundedDecoded(code, offset, va, prefix_len + 2, .rdtsc);
    }
    if (opcode2 == 0xa2) {
        return boundedDecoded(code, offset, va, prefix_len + 2, .cpuid);
    }
    if (opcode2 >= 0x40 and opcode2 <= 0x4f) {
        return boundedDecoded(code, offset, va, prefix_len + 2, .cmovcc);
    }
    if (opcode2 >= 0x90 and opcode2 <= 0x9f) {
        const modrm = parseModRm(code, opcode_offset + 2, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
        var rm = modrm.rm;
        const len = prefix_len + 2 + modrm.len;
        finalizeMemVa(&rm, va, len);
        var d = boundedDecoded(code, offset, va, len, .setcc);
        d.op_count = 1;
        d.operands[0] = rm;
        return d;
    }
    if (opcode2 == 0xaf) {
        const modrm = parseModRm(code, opcode_offset + 2, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
        var rm = modrm.rm;
        const len = prefix_len + 2 + modrm.len;
        finalizeMemVa(&rm, va, len);
        var d = boundedDecoded(code, offset, va, len, .imul);
        d.op_count = 2;
        d.operands[0] = regOperand(modrm.reg);
        d.operands[1] = rm;
        return d;
    }
    return boundedDecoded(code, offset, va, 1, .other);
}

fn decodeX86TwoByteExt(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8) Decoded {
    _ = opcode;
    const modrm = parseModRm(code, opcode_offset + 2, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 2 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .mov);
    d.op_count = 2;
    d.operands[0] = regOperand(modrm.reg);
    d.operands[1] = rm;
    d.mem_read = rm.kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeAccumulatorImmediate(code: []const u8, offset: usize, opcode_offset: usize, va: u64, prefix_len: usize, kind: InstrKind, imm_bytes: usize) Decoded {
    var d = boundedDecoded(code, offset, va, prefix_len + 1 + imm_bytes, kind);
    d.op_count = 2;
    d.operands[0] = regOperand(.rax);
    d.operands[1] = immOperand(readImmediate(code, opcode_offset + 1, imm_bytes));
    return d;
}

fn decodeCmpRegMem(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .cmp);
    d.op_count = 2;
    if (opcode == 0x38 or opcode == 0x39) {
        d.operands[0] = rm;
        d.operands[1] = regOperand(modrm.reg);
    } else {
        d.operands[0] = regOperand(modrm.reg);
        d.operands[1] = rm;
    }
    d.mem_read = d.operands[0].kind == .mem or d.operands[1].kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeTestRegMem(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .test_);
    d.op_count = 2;
    d.operands[0] = rm;
    d.operands[1] = regOperand(modrm.reg);
    d.mem_read = rm.kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeMovRegMem(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .mov);
    d.op_count = 2;
    if (opcode == 0x88 or opcode == 0x89) {
        d.operands[0] = rm;
        d.operands[1] = regOperand(modrm.reg);
    } else {
        d.operands[0] = regOperand(modrm.reg);
        d.operands[1] = rm;
    }
    d.mem_write = d.operands[0].kind == .mem;
    d.mem_read = d.operands[1].kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeLea(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .lea);
    d.op_count = 2;
    d.operands[0] = regOperand(modrm.reg);
    d.operands[1] = rm;
    d.has_modrm = true;
    return d;
}

fn decodeBinaryRegMem(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8, kind: InstrKind) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, kind);
    d.op_count = 2;
    if ((opcode & 0x2) == 0) {
        d.operands[0] = rm;
        d.operands[1] = regOperand(modrm.reg);
    } else {
        d.operands[0] = regOperand(modrm.reg);
        d.operands[1] = rm;
    }
    d.mem_read = d.operands[0].kind == .mem or d.operands[1].kind == .mem;
    d.mem_write = d.operands[0].kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeGroupImmediate(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8, immz: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const imm_bytes: usize = if (opcode == 0x81) immz else 1;
    const len = prefix_len + 1 + modrm.len + imm_bytes;
    finalizeMemVa(&rm, va, len);
    const kind: InstrKind = switch (modrm.reg_opcode) {
        0 => .add,
        1 => .or_,
        4 => .and_,
        5 => .sub,
        6 => .xor_,
        7 => .cmp,
        else => .other,
    };
    var d = boundedDecoded(code, offset, va, len, kind);
    d.op_count = 2;
    d.operands[0] = rm;
    d.operands[1] = immOperand(readImmediate(code, opcode_offset + 1 + modrm.len, imm_bytes));
    d.mem_read = rm.kind == .mem;
    d.mem_write = rm.kind == .mem and kind != .cmp;
    d.has_modrm = true;
    return d;
}

fn decodeMovImmediateToRm(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, immz: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len + immz;
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, .mov);
    d.op_count = 2;
    d.operands[0] = rm;
    d.operands[1] = immOperand(readImmediate(code, opcode_offset + 1 + modrm.len, immz));
    d.mem_write = rm.kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeTestGroup(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize, opcode: u8, immz: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const imm_bytes: usize = if (opcode == 0xf6) 1 else immz;
    const len = prefix_len + 1 + modrm.len + if (modrm.reg_opcode == 0) imm_bytes else @as(usize, 0);
    finalizeMemVa(&rm, va, len);
    var d = boundedDecoded(code, offset, va, len, if (modrm.reg_opcode == 0) .test_ else .other);
    d.op_count = if (modrm.reg_opcode == 0) 2 else 1;
    d.operands[0] = rm;
    if (modrm.reg_opcode == 0) d.operands[1] = immOperand(readImmediate(code, opcode_offset + 1 + modrm.len, imm_bytes));
    d.mem_read = rm.kind == .mem;
    d.has_modrm = true;
    return d;
}

fn decodeGroupFF(code: []const u8, offset: usize, opcode_offset: usize, va: u64, arch: Arch, p: PrefixInfo, prefix_len: usize) Decoded {
    const modrm = parseModRm(code, opcode_offset + 1, arch, p) orelse return boundedDecoded(code, offset, va, 1, .other);
    var rm = modrm.rm;
    const len = prefix_len + 1 + modrm.len;
    finalizeMemVa(&rm, va, len);
    const kind: InstrKind = switch (modrm.reg_opcode) {
        2 => .call,
        4 => .jmp,
        6 => .push,
        else => .other,
    };
    var d = boundedDecoded(code, offset, va, len, kind);
    d.indirect = kind == .call or kind == .jmp;
    d.op_count = 1;
    d.operands[0] = rm;
    d.mem_read = rm.kind == .mem;
    if (rm.kind == .mem) d.target = rm.mem_va;
    d.has_modrm = true;
    return d;
}

fn parseModRm(code: []const u8, off: usize, arch: Arch, p: PrefixInfo) ?ModRm {
    if (off >= code.len) return null;
    const mr = code[off];
    const mode = (mr >> 6) & 0x3;
    const reg_bits = (mr >> 3) & 0x7;
    const rm_bits = mr & 0x7;
    var len: usize = 1;
    const reg = regFromBits(reg_bits, p.rex_r);
    if (mode == 3) {
        return .{ .len = len, .reg = reg, .rm = regOperand(regFromBits(rm_bits, p.rex_b)), .reg_opcode = reg_bits, .mod_value = 3, .rm_value = rm_bits };
    }

    var base = regFromBits(rm_bits, p.rex_b);
    var disp: i64 = 0;
    var has_sib = false;
    var scale: u8 = 0;
    var index: Reg = .none;

    if (rm_bits == 4) {
        if (off + len >= code.len) return null;
        const sib = code[off + len];
        len += 1;
        has_sib = true;
        scale = @as(u8, 1) << @intCast((sib >> 6) & 0x3);
        index = regFromBits((sib >> 3) & 0x7, p.rex_x);
        const sib_base = sib & 0x7;
        if (mode == 0 and sib_base == 5) {
            if (off + len + 4 > code.len) return null;
            if (arch == .x86_64) {
                base = .rip;
                disp = utils.readInt(code, i32, off + len, .little) catch return null;
            } else {
                base = .none;
                disp = @intCast(utils.readInt(code, u32, off + len, .little) catch return null);
            }
            len += 4;
        } else {
            base = regFromBits(sib_base, p.rex_b);
        }
    } else if (mode == 0 and rm_bits == 5) {
        if (off + len + 4 > code.len) return null;
        if (arch == .x86_64) {
            base = .rip;
            disp = utils.readInt(code, i32, off + len, .little) catch return null;
        } else {
            base = .none;
            disp = @intCast(utils.readInt(code, u32, off + len, .little) catch return null);
        }
        len += 4;
    }

    if (mode == 1) {
        if (off + len >= code.len) return null;
        disp += @as(i8, @bitCast(code[off + len]));
        len += 1;
    } else if (mode == 2) {
        if (off + len + 4 > code.len) return null;
        disp += utils.readInt(code, i32, off + len, .little) catch return null;
        len += 4;
    }

    return .{
        .len = len, .reg = reg, .rm = memOperand(base, disp, index, scale),
        .reg_opcode = reg_bits, .mod_value = mode, .rm_value = rm_bits,
        .has_sib = has_sib, .scale = scale, .index = index,
    };
}

fn finalizeMemVa(op: *Operand, va: u64, len: usize) void {
    if (op.kind != .mem) return;
    if (op.base == .rip) {
        const base = va + @as(u64, @intCast(len));
        op.mem_va = addSigned(base, op.disp);
    } else if (op.base == .none and op.disp >= 0) {
        op.mem_va = @intCast(op.disp);
    }
}

fn regFromBits(bits: u8, ext: bool) Reg {
    return switch (bits + if (ext) @as(u8, 8) else @as(u8, 0)) {
        0 => .rax, 1 => .rcx, 2 => .rdx, 3 => .rbx,
        4 => .rsp, 5 => .rbp, 6 => .rsi, 7 => .rdi,
        8 => .r8, 9 => .r9, 10 => .r10, 11 => .r11,
        12 => .r12, 13 => .r13, 14 => .r14, 15 => .r15,
        else => .none,
    };
}

fn regOperand(reg: Reg) Operand {
    return .{ .kind = .reg, .reg = reg };
}

fn immOperand(value: u64) Operand {
    return .{ .kind = .imm, .imm = value };
}

fn memOperand(base: Reg, disp: i64, index: Reg, scale: u8) Operand {
    return .{ .kind = .mem, .base = base, .disp = disp, .index = index, .scale = scale };
}

fn readImmediate(code: []const u8, offset: usize, len: usize) u64 {
    var out: u64 = 0;
    var i: usize = 0;
    while (i < len and offset + i < code.len and i < 8) : (i += 1) {
        out |= @as(u64, code[offset + i]) << @intCast(i * 8);
    }
    return out;
}

fn rel8Target(code: []const u8, offset: usize, va: u64, len: usize) ?u64 {
    if (offset >= code.len) return null;
    const disp = @as(i8, @bitCast(code[offset]));
    return addSigned(va + @as(u64, @intCast(len)), disp);
}

fn rel32Target(code: []const u8, offset: usize, va: u64, len: usize) ?u64 {
    const disp = utils.readInt(code, i32, offset, .little) catch return null;
    return addSigned(va + @as(u64, @intCast(len)), disp);
}

fn addSigned(base: u64, disp: i64) ?u64 {
    const value = @as(i128, @intCast(base)) + @as(i128, disp);
    if (value < 0 or value > std.math.maxInt(u64)) return null;
    return @intCast(value);
}
