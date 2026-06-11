const std = @import("std");

const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const default_max_bytes = 256 * 1024 * 1024;
const max_following_check = 12;
const max_cleanup_cfg_instrs = 2048;
const cleanup_state_variants = 8;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var target_path: ?[]const u8 = null;
    var json_path: ?[]const u8 = null;
    var dot_path: ?[]const u8 = null;
    var diff_path: ?[]const u8 = null;
    var baseline_path: ?[]const u8 = null;
    var plain = false;
    var max_bytes: usize = default_max_bytes;
    var verbose = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const next = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, arg, "--target")) {
            i += 1;
            target_path = next;
        } else if (std.mem.eql(u8, arg, "--json")) {
            i += 1;
            json_path = next;
        } else if (std.mem.eql(u8, arg, "--dot")) {
            i += 1;
            dot_path = next;
        } else if (std.mem.eql(u8, arg, "--diff")) {
            i += 1;
            diff_path = next;
        } else if (std.mem.eql(u8, arg, "--baseline")) {
            i += 1;
            baseline_path = next;
        } else if (std.mem.eql(u8, arg, "--plain")) {
            plain = true;
        } else if (std.mem.eql(u8, arg, "--max-bytes")) {
            i += 1;
            max_bytes = std.fmt.parseInt(usize, next, 10) catch default_max_bytes;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-") and target_path == null) {
            target_path = arg;
        } else {
            const stderr = std.io.getStdErr().writer();
            try stderr.print("[IntegrityGap] opcao desconhecida: {s}\n", .{arg});
            printUsage();
            std.process.exit(1);
        }
    }

    if (target_path == null) {
        printUsage();
        return;
    }

    var target = try analyzeTarget(allocator, target_path.?, max_bytes, verbose);
    defer target.deinit(allocator);

    if (baseline_path) |base_path| {
        var base = try analyzeTarget(allocator, base_path, max_bytes, verbose);
        defer base.deinit(allocator);
        if (json_path) |path| try writeDiffJson(path, base, target, true) else try writeDiffStdout(base, target, true);
        return;
    }

    if (diff_path) |other_path| {
        var other = try analyzeTarget(allocator, other_path, max_bytes, verbose);
        defer other.deinit(allocator);
        if (json_path) |path| try writeDiffJson(path, target, other, false) else try writeDiffStdout(target, other, false);
        return;
    }

    if (plain) try writePlain(target);
    if (json_path) |path| try writeJson(path, target);
    if (dot_path) |path| try writeDot(path, target);
    if (!plain and json_path == null and dot_path == null) try writeJsonStdout(target);
}

fn printUsage() void {
    const out = std.io.getStdOut().writer();
    out.writeAll(
        \\IntegrityGap - Analise de ausencias comportamentais v1.0
        \\
        \\USO:
        \\  IntegrityGap --target <binario> [--json out.json] [--plain] [--dot out.dot]
        \\  IntegrityGap --target <binario> --diff <outro> [--json diff.json]
        \\  IntegrityGap --target <binario> --baseline <limpo> [--json diff.json]
        \\
        \\OPCOES:
        \\  --target <path>    Binario alvo PE/ELF
        \\  --json <path>      Output JSON estruturado
        \\  --plain            Output humano resumido
        \\  --dot <path>       Grafo DOT de funcoes e gaps
        \\  --diff <path>      Compara contra outro binario
        \\  --baseline <path>  Compara target contra baseline limpo conhecido
        \\  --max-bytes <N>    Limite de leitura (default: 268435456)
        \\  --verbose, -v      Logs de progresso em stderr
        \\  --help, -h         Este texto
        \\
    ) catch {};
}

const FileFormat = enum { elf32, elf64, pe32, pe64 };
const Arch = enum { x86, x86_64, arm64, unknown };

const Section = struct {
    name: []const u8 = "",
    va: u64,
    file_offset: usize,
    size: usize,
    virtual_size: u64,
    executable: bool,
};

const ImportSymbol = struct {
    name: []const u8,
    dll: []const u8 = "",
    iat_va: u64 = 0,
    plt_va: u64 = 0,
    got_va: u64 = 0,
};

const Symbol = struct {
    name: []const u8,
    va: u64,
    size: u64 = 0,
    is_function: bool = false,
    external: bool = false,
};

const BinaryImage = struct {
    format: FileFormat,
    arch: Arch,
    entry_va: u64,
    image_base: u64,
    sections: []Section,
    imports: []ImportSymbol,
    symbols: []Symbol,
    exports_count: usize = 0,
    relocations_count: usize = 0,

    fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.sections);
        allocator.free(self.imports);
        allocator.free(self.symbols);
    }
};

const InstrKind = enum {
    other,
    call,
    jmp,
    jcc,
    ret,
    cmp,
    test_,
    mov,
    lea,
    add,
    sub,
    xor_,
    and_,
    or_,
    push,
    pop,
    nop,
};

const Reg = enum(u8) {
    none = 0xff,
    rax = 0,
    rcx = 1,
    rdx = 2,
    rbx = 3,
    rsp = 4,
    rbp = 5,
    rsi = 6,
    rdi = 7,
    r8 = 8,
    r9 = 9,
    r10 = 10,
    r11 = 11,
    r12 = 12,
    r13 = 13,
    r14 = 14,
    r15 = 15,
    rip = 16,
    eax = 17,
    ax = 18,
    al = 19,
    ecx = 20,
    cx = 21,
    cl = 22,
    edx = 23,
    dx = 24,
    dl = 25,
};

const OperandKind = enum { none, reg, imm, mem };

const Operand = struct {
    kind: OperandKind = .none,
    reg: Reg = .none,
    base: Reg = .none,
    disp: i64 = 0,
    imm: u64 = 0,
    mem_va: ?u64 = null,
};

const Decoded = struct {
    va: u64,
    off: usize,
    len: usize,
    kind: InstrKind = .other,
    target: ?u64 = null,
    op_count: u8 = 0,
    operands: [2]Operand = .{ Operand{}, Operand{} },
    indirect: bool = false,
    mem_read: bool = false,
    mem_write: bool = false,

    fn operand(self: @This(), idx: usize) Operand {
        if (idx >= self.op_count) return Operand{};
        return self.operands[idx];
    }
};

const FunctionSpan = struct {
    start: u64,
    end: u64,
    instr_start: usize,
    instr_end: usize,
};

const CallCategory = enum {
    generic,
    network,
    file,
    memory,
    crypto,
    registry,
    process,
    logging,
    cleanup,
};

const CallRole = enum { neutral, acquire, release, crypto_init, crypto_op, crypto_final, crypto_destroy };

const ResolvedCall = struct {
    va: u64,
    target: ?u64,
    name: []const u8,
    category: CallCategory,
    role: CallRole,
    checked: bool,
    high_risk: bool,
};

const ResolvedName = struct {
    name: []const u8,
    external: bool,
};

const CategoryScores = struct {
    error_handling: f64 = 0,
    resource_lifecycle: f64 = 0,
    input_validation: f64 = 0,
    cryptographic: f64 = 0,
    logging_auditability: f64 = 0,
    cleanup: f64 = 0,

    fn aggregate(self: @This()) f64 {
        return clamp100(
            self.error_handling * 0.23 +
                self.resource_lifecycle * 0.20 +
                self.input_validation * 0.15 +
                self.cryptographic * 0.17 +
                self.logging_auditability * 0.12 +
                self.cleanup * 0.13,
        );
    }
};

const Evidence = struct {
    function_va: u64,
    address: u64,
    category: []const u8,
    message: []const u8,
    severity: u8,
};

const FunctionProfile = struct {
    span: FunctionSpan,
    calls: []ResolvedCall,
    scores: CategoryScores,
    confidence: f64,
    aggregate_gap: f64,
    evidence_start: usize,
    evidence_count: usize,
    critical_calls: usize,
    unchecked_critical_calls: usize,
    acquire_calls: usize,
    release_calls: usize,
    high_risk_calls: usize,
    logging_calls: usize,
    cleanup_exit_paths: usize,
    cleanup_dirty_exit_paths: usize,
    cleanup_error_dirty_paths: usize,
    pointer_deref_before_validation: bool,
};

const CleanupPathStats = struct {
    exit_paths: usize = 0,
    dirty_exit_paths: usize = 0,
    error_dirty_paths: usize = 0,
    clean_release_exit_paths: usize = 0,
    truncated: bool = false,

    fn score(self: @This(), acquire: usize, release: usize) f64 {
        if (acquire == 0) return 0;
        var out = @as(f64, @floatFromInt(acquire - @min(acquire, release))) * 55.0 / @as(f64, @floatFromInt(acquire));
        if (self.exit_paths > 0) {
            out += @as(f64, @floatFromInt(self.dirty_exit_paths)) * 35.0 / @as(f64, @floatFromInt(self.exit_paths));
            out += @as(f64, @floatFromInt(self.error_dirty_paths)) * 30.0 / @as(f64, @floatFromInt(self.exit_paths));
        }
        if (self.clean_release_exit_paths > 0 and self.dirty_exit_paths > 0) out = @max(out, 60.0);
        if (self.error_dirty_paths > 0) out = @max(out, 70.0);
        if (self.truncated and release < acquire) out += 10.0;
        return clamp100(out);
    }
};

const ThreatClass = enum {
    No_Material_Gap,
    Implant,
    Dropper,
    RAT,
    Ransomware,
    Legitimate_Anomalous,
};

const Summary = struct {
    threat: ThreatClass,
    aggregate_gap: f64,
    anomaly_confidence: f64,
    scores: CategoryScores,
};

const Analysis = struct {
    target_path: []const u8,
    bytes: []u8,
    sha256: [32]u8,
    image: BinaryImage,
    instructions: []Decoded,
    functions: []FunctionSpan,
    profiles: []FunctionProfile,
    evidence: []Evidence,
    summary: Summary,
    call_edges: []CallEdge,
    logging_present: bool,

    fn deinit(self: *@This(), allocator: Allocator) void {
        for (self.profiles) |profile| allocator.free(profile.calls);
        allocator.free(self.profiles);
        allocator.free(self.evidence);
        allocator.free(self.functions);
        allocator.free(self.instructions);
        allocator.free(self.call_edges);
        self.image.deinit(allocator);
        allocator.free(self.bytes);
    }
};

const CallEdge = struct { from: u64, to: u64 };

fn analyzeTarget(allocator: Allocator, path: []const u8, max_bytes: usize, verbose: bool) !Analysis {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
    errdefer allocator.free(bytes);

    var hash: [32]u8 = undefined;
    Sha256.hash(bytes, &hash, .{});

    var image = try parseBinary(allocator, bytes);
    errdefer image.deinit(allocator);
    if (verbose) {
        try std.io.getStdErr().writer().print("[IntegrityGap] {s}: {s}/{s}, imports={}, exec_sections={}\n", .{ path, @tagName(image.format), @tagName(image.arch), image.imports.len, countExecSections(image) });
    }

    const instructions = try decodeAll(allocator, bytes, image);
    errdefer allocator.free(instructions);
    const functions = try detectFunctions(allocator, instructions, image);
    errdefer allocator.free(functions);
    const call_edges = try buildCallEdges(allocator, instructions, functions);
    errdefer allocator.free(call_edges);

    const logging_present = detectLoggingPresent(bytes, image.imports);
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
    };
}

fn parseBinary(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) return parseElf(allocator, bytes);
    if (bytes.len >= 2 and std.mem.eql(u8, bytes[0..2], "MZ")) return parsePe(allocator, bytes);
    return error.UnsupportedBinaryFormat;
}

fn parseElf(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len < 0x34) return error.TruncatedElfHeader;
    const class = bytes[4];
    const data = bytes[5];
    const endian: std.builtin.Endian = switch (data) {
        1 => .little,
        2 => .big,
        else => return error.UnsupportedElfEndian,
    };
    return switch (class) {
        1 => parseElf32(allocator, bytes, endian),
        2 => parseElf64(allocator, bytes, endian),
        else => error.UnsupportedElfClass,
    };
}

fn parseElf32(allocator: Allocator, bytes: []const u8, endian: std.builtin.Endian) !BinaryImage {
    const machine = try readInt(bytes, u16, 0x12, endian);
    const entry = try readInt(bytes, u32, 0x18, endian);
    const shoff = try readInt(bytes, u32, 0x20, endian);
    const shentsize = try readInt(bytes, u16, 0x2e, endian);
    const shnum = try readInt(bytes, u16, 0x30, endian);
    const shstrndx = try readInt(bytes, u16, 0x32, endian);

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var symbols = std.ArrayList(Symbol).init(allocator);
    errdefer symbols.deinit();

    const shstr = elfSectionStringTable(bytes, shoff, shentsize, shnum, shstrndx, endian, false);
    var dynstr: []const u8 = "";
    var strtab: []const u8 = "";
    var dynsym_off: usize = 0;
    var dynsym_size: usize = 0;
    var dynsym_entsize: usize = 16;
    var symtab_off: usize = 0;
    var symtab_size: usize = 0;
    var symtab_entsize: usize = 16;
    var plt_va: u64 = 0;
    var plt_entsize: usize = 16;
    var plt_sec_va: u64 = 0;
    var plt_sec_entsize: usize = 16;
    var relplt_off: usize = 0;
    var relplt_size: usize = 0;
    var relplt_entsize: usize = 0;
    var relplt_is_rela = false;

    for (0..shnum) |idx| {
        const off = checkedUsize(@as(u64, shoff) + @as(u64, @intCast(idx)) * shentsize) catch break;
        if (off > bytes.len or bytes.len - off < shentsize) break;
        const name_off = try readInt(bytes, u32, off + 0, endian);
        const sh_type = try readInt(bytes, u32, off + 4, endian);
        const sh_flags = try readInt(bytes, u32, off + 8, endian);
        const sh_addr = try readInt(bytes, u32, off + 12, endian);
        const sh_offset = try readInt(bytes, u32, off + 16, endian);
        const sh_size = try readInt(bytes, u32, off + 20, endian);
        const sh_entsize = try readInt(bytes, u32, off + 36, endian);
        const name = cstrAt(shstr, name_off);
        if (sh_type != 8) try appendSection(&sections, bytes.len, name, sh_addr, sh_offset, sh_size, sh_size, (sh_flags & 0x4) != 0);
        if (std.mem.eql(u8, name, ".plt")) {
            plt_va = sh_addr;
            plt_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.eql(u8, name, ".plt.sec")) {
            plt_sec_va = sh_addr;
            plt_sec_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.indexOf(u8, name, ".rela.plt") != null) {
            relplt_off = checkedUsize(sh_offset) catch 0;
            relplt_size = checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 12 else checkedUsize(sh_entsize) catch 12;
            relplt_is_rela = true;
        } else if (std.mem.indexOf(u8, name, ".rel.plt") != null) {
            relplt_off = checkedUsize(sh_offset) catch 0;
            relplt_size = checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 8 else checkedUsize(sh_entsize) catch 8;
            relplt_is_rela = false;
        }
        if (std.mem.eql(u8, name, ".dynstr")) {
            const start = checkedUsize(sh_offset) catch continue;
            const size = checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) dynstr = bytes[start .. start + size];
        } else if (std.mem.eql(u8, name, ".strtab")) {
            const start = checkedUsize(sh_offset) catch continue;
            const size = checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) strtab = bytes[start .. start + size];
        }
        if (sh_type == 11 or std.mem.eql(u8, name, ".dynsym")) {
            dynsym_off = checkedUsize(sh_offset) catch 0;
            dynsym_size = checkedUsize(sh_size) catch 0;
            dynsym_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        } else if (sh_type == 2 or std.mem.eql(u8, name, ".symtab")) {
            symtab_off = checkedUsize(sh_offset) catch 0;
            symtab_size = checkedUsize(sh_size) catch 0;
            symtab_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        }
    }
    try parseElfSymbols(&imports, &symbols, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, false, true);
    try parseElfSymbols(&imports, &symbols, bytes, strtab, symtab_off, symtab_size, symtab_entsize, endian, false, false);
    try parseElfPltRelocs(&imports, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, false, relplt_off, relplt_size, relplt_entsize, relplt_is_rela, if (plt_sec_va != 0) plt_sec_va else plt_va, if (plt_sec_va != 0) plt_sec_entsize else plt_entsize, plt_sec_va == 0);
    try addScannedKnownImports(&imports, bytes);
    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);
    return .{ .format = .elf32, .arch = elfArch(machine), .entry_va = entry, .image_base = 0, .sections = owned_sections, .imports = try imports.toOwnedSlice(), .symbols = try symbols.toOwnedSlice() };
}

fn parseElf64(allocator: Allocator, bytes: []const u8, endian: std.builtin.Endian) !BinaryImage {
    const machine = try readInt(bytes, u16, 0x12, endian);
    const entry = try readInt(bytes, u64, 0x18, endian);
    const shoff = try readInt(bytes, u64, 0x28, endian);
    const shentsize = try readInt(bytes, u16, 0x3a, endian);
    const shnum = try readInt(bytes, u16, 0x3c, endian);
    const shstrndx = try readInt(bytes, u16, 0x3e, endian);

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var symbols = std.ArrayList(Symbol).init(allocator);
    errdefer symbols.deinit();

    const shstr = elfSectionStringTable(bytes, shoff, shentsize, shnum, shstrndx, endian, true);
    var dynstr: []const u8 = "";
    var strtab: []const u8 = "";
    var dynsym_off: usize = 0;
    var dynsym_size: usize = 0;
    var dynsym_entsize: usize = 24;
    var symtab_off: usize = 0;
    var symtab_size: usize = 0;
    var symtab_entsize: usize = 24;
    var plt_va: u64 = 0;
    var plt_entsize: usize = 16;
    var plt_sec_va: u64 = 0;
    var plt_sec_entsize: usize = 16;
    var relplt_off: usize = 0;
    var relplt_size: usize = 0;
    var relplt_entsize: usize = 0;
    var relplt_is_rela = false;

    for (0..shnum) |idx| {
        const off = checkedUsize(shoff + @as(u64, @intCast(idx)) * shentsize) catch break;
        if (off > bytes.len or bytes.len - off < shentsize) break;
        const name_off = try readInt(bytes, u32, off + 0, endian);
        const sh_type = try readInt(bytes, u32, off + 4, endian);
        const sh_flags = try readInt(bytes, u64, off + 8, endian);
        const sh_addr = try readInt(bytes, u64, off + 16, endian);
        const sh_offset = try readInt(bytes, u64, off + 24, endian);
        const sh_size = try readInt(bytes, u64, off + 32, endian);
        const sh_entsize = try readInt(bytes, u64, off + 56, endian);
        const name = cstrAt(shstr, name_off);
        if (sh_type != 8) try appendSection(&sections, bytes.len, name, sh_addr, sh_offset, sh_size, sh_size, (sh_flags & 0x4) != 0);
        if (std.mem.eql(u8, name, ".plt")) {
            plt_va = sh_addr;
            plt_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.eql(u8, name, ".plt.sec")) {
            plt_sec_va = sh_addr;
            plt_sec_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.indexOf(u8, name, ".rela.plt") != null) {
            relplt_off = checkedUsize(sh_offset) catch 0;
            relplt_size = checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 24 else checkedUsize(sh_entsize) catch 24;
            relplt_is_rela = true;
        } else if (std.mem.indexOf(u8, name, ".rel.plt") != null) {
            relplt_off = checkedUsize(sh_offset) catch 0;
            relplt_size = checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 16 else checkedUsize(sh_entsize) catch 16;
            relplt_is_rela = false;
        }
        if (std.mem.eql(u8, name, ".dynstr")) {
            const start = checkedUsize(sh_offset) catch continue;
            const size = checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) dynstr = bytes[start .. start + size];
        } else if (std.mem.eql(u8, name, ".strtab")) {
            const start = checkedUsize(sh_offset) catch continue;
            const size = checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) strtab = bytes[start .. start + size];
        }
        if (sh_type == 11 or std.mem.eql(u8, name, ".dynsym")) {
            dynsym_off = checkedUsize(sh_offset) catch 0;
            dynsym_size = checkedUsize(sh_size) catch 0;
            dynsym_entsize = if (sh_entsize == 0) 24 else checkedUsize(sh_entsize) catch 24;
        } else if (sh_type == 2 or std.mem.eql(u8, name, ".symtab")) {
            symtab_off = checkedUsize(sh_offset) catch 0;
            symtab_size = checkedUsize(sh_size) catch 0;
            symtab_entsize = if (sh_entsize == 0) 24 else checkedUsize(sh_entsize) catch 24;
        }
    }
    try parseElfSymbols(&imports, &symbols, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, true, true);
    try parseElfSymbols(&imports, &symbols, bytes, strtab, symtab_off, symtab_size, symtab_entsize, endian, true, false);
    try parseElfPltRelocs(&imports, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, true, relplt_off, relplt_size, relplt_entsize, relplt_is_rela, if (plt_sec_va != 0) plt_sec_va else plt_va, if (plt_sec_va != 0) plt_sec_entsize else plt_entsize, plt_sec_va == 0);
    try addScannedKnownImports(&imports, bytes);
    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);
    return .{ .format = .elf64, .arch = elfArch(machine), .entry_va = entry, .image_base = 0, .sections = owned_sections, .imports = try imports.toOwnedSlice(), .symbols = try symbols.toOwnedSlice() };
}

fn parsePe(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len < 0x40) return error.TruncatedPeHeader;
    const pe_off = try checkedUsize(try readInt(bytes, u32, 0x3c, .little));
    if (pe_off > bytes.len or bytes.len - pe_off < 24) return error.TruncatedPeHeader;
    if (!std.mem.eql(u8, bytes[pe_off .. pe_off + 4], "PE\x00\x00")) return error.InvalidPeSignature;
    const coff = pe_off + 4;
    const machine = try readInt(bytes, u16, coff + 0, .little);
    const num_sections = try readInt(bytes, u16, coff + 2, .little);
    const opt_size = try readInt(bytes, u16, coff + 16, .little);
    const optional = coff + 20;
    if (optional > bytes.len or bytes.len - optional < opt_size) return error.TruncatedPeOptionalHeader;
    const opt_magic = try readInt(bytes, u16, optional, .little);
    const format: FileFormat = switch (opt_magic) {
        0x10b => .pe32,
        0x20b => .pe64,
        else => return error.UnsupportedPeOptionalHeader,
    };
    const entry_rva = try readInt(bytes, u32, optional + 16, .little);
    const image_base: u64 = switch (format) {
        .pe32 => try readInt(bytes, u32, optional + 28, .little),
        .pe64 => try readInt(bytes, u64, optional + 24, .little),
        else => unreachable,
    };
    const data_dir = optional + if (format == .pe64) @as(usize, 112) else @as(usize, 96);
    const export_rva = if (data_dir + 8 <= optional + opt_size and data_dir + 8 <= bytes.len) try readInt(bytes, u32, data_dir, .little) else 0;
    const import_rva = if (data_dir + 16 <= optional + opt_size and data_dir + 16 <= bytes.len) try readInt(bytes, u32, data_dir + 8, .little) else 0;
    const base_reloc_rva = if (data_dir + 5 * 8 + 8 <= optional + opt_size and data_dir + 5 * 8 + 8 <= bytes.len) try readInt(bytes, u32, data_dir + 5 * 8, .little) else 0;

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    const sectab = optional + opt_size;
    for (0..num_sections) |idx| {
        const off = sectab + idx * 40;
        if (off > bytes.len or bytes.len - off < 40) break;
        const raw_name = bytes[off .. off + 8];
        const name_len = std.mem.indexOfScalar(u8, raw_name, 0) orelse raw_name.len;
        const name = raw_name[0..name_len];
        const vsize = try readInt(bytes, u32, off + 8, .little);
        const vaddr = try readInt(bytes, u32, off + 12, .little);
        const rsize = try readInt(bytes, u32, off + 16, .little);
        const roff = try readInt(bytes, u32, off + 20, .little);
        const chars = try readInt(bytes, u32, off + 36, .little);
        const exec = (chars & 0x20000000) != 0 or (chars & 0x00000020) != 0;
        try appendSection(&sections, bytes.len, name, image_base + vaddr, roff, rsize, if (vsize == 0) rsize else vsize, exec);
    }
    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);

    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    try parsePeImports(&imports, bytes, owned_sections, image_base, import_rva, format);
    try addScannedKnownImports(&imports, bytes);
    const empty_symbols = try allocator.alloc(Symbol, 0);

    return .{
        .format = format,
        .arch = peArch(machine),
        .entry_va = image_base + entry_rva,
        .image_base = image_base,
        .sections = owned_sections,
        .imports = try imports.toOwnedSlice(),
        .symbols = empty_symbols,
        .exports_count = if (export_rva == 0) 0 else 1,
        .relocations_count = if (base_reloc_rva == 0) 0 else 1,
    };
}

fn decodeAll(allocator: Allocator, bytes: []const u8, image: BinaryImage) ![]Decoded {
    var out = std.ArrayList(Decoded).init(allocator);
    errdefer out.deinit();
    for (image.sections) |section| {
        if (!section.executable) continue;
        const code = sectionBytes(bytes, section);
        var off: usize = 0;
        while (off < code.len) {
            const va = section.va + @as(u64, @intCast(off));
            const d = if (image.arch == .x86 or image.arch == .x86_64) decodeX86(code, off, va, image.arch) else decodeFallback(code, off, va);
            if (d.len == 0) break;
            try out.append(d);
            off += d.len;
        }
    }
    return out.toOwnedSlice();
}

fn detectFunctions(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]FunctionSpan {
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
    std.mem.sort(u64, starts.items, {}, u64Less);

    var funcs = std.ArrayList(FunctionSpan).init(allocator);
    errdefer funcs.deinit();
    for (starts.items, 0..) |start, si| {
        const sidx = index_by_va.get(start) orelse continue;
        const next_start = if (si + 1 < starts.items.len) starts.items[si + 1] else std.math.maxInt(u64);
        var eidx = sidx;
        while (eidx < instrs.len and instrs[eidx].va < next_start) : (eidx += 1) {}
        if (eidx == sidx) continue;
        const end_va = instrs[eidx - 1].va + instrs[eidx - 1].len;
        try funcs.append(.{ .start = start, .end = end_va, .instr_start = sidx, .instr_end = eidx });
    }
    return funcs.toOwnedSlice();
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

    var first_arg_deref: ?usize = null;
    var first_validation: ?usize = null;
    var memcpy_like: usize = 0;
    var bounds_checks: usize = 0;

    for (instrs[span.instr_start..span.instr_end], 0..) |instr, local_idx| {
        if (first_validation == null and isValidationInstr(instr, image)) first_validation = local_idx;
        if (first_arg_deref == null and dereferencesArgumentPointer(instr, image)) first_arg_deref = local_idx;
        if (isBoundsCheck(instr, image)) bounds_checks += 1;

        if (instr.kind == .call) {
            const resolved = resolveCallInfo(image, instr);
            const name = resolved.name;
            const category = if (resolved.external) categorizeCall(name) else .generic;
            const role = if (resolved.external) callRole(name, category) else .neutral;
            const checked = callReturnChecked(instrs, span, span.instr_start + local_idx);
            const risk = isHighRiskCategory(category);
            if (category == .logging) logging_calls += 1;
            if (risk) high_risk += 1;
            if (role == .acquire) acquire += 1;
            if (role == .release) release += 1;
            if (role == .crypto_init) crypto_init += 1;
            if (role == .crypto_op) crypto_op += 1;
            if (role == .crypto_final) crypto_final += 1;
            if (role == .crypto_destroy) crypto_destroy += 1;
            if (category == .crypto) crypto_calls_seen += 1;
            if (isCriticalReturnCall(category, role)) {
                critical += 1;
                if (!checked) {
                    unchecked_critical += 1;
                    try evidence.append(.{ .function_va = span.start, .address = instr.va, .category = "error_handling", .message = "call critica sem verificacao de retorno antes da proxima operacao relevante", .severity = 75 });
                }
            }
            if (isCopyLike(name)) memcpy_like += 1;
            try calls.append(.{ .va = instr.va, .target = instr.target, .name = name, .category = category, .role = role, .checked = checked, .high_risk = risk });
        }
    }

    const pointer_gap = if (first_arg_deref) |deref_idx| blk: {
        if (first_validation) |valid_idx| break :blk valid_idx > deref_idx;
        break :blk true;
    } else false;
    if (pointer_gap) {
        try evidence.append(.{ .function_va = span.start, .address = instrs[span.instr_start].va, .category = "input_validation", .message = "deref de ponteiro de argumento antes de validacao local observavel", .severity = 55 });
    }

    var scores = CategoryScores{};
    scores.error_handling = if (critical == 0) 0 else clamp100(@as(f64, @floatFromInt(unchecked_critical)) * 100.0 / @as(f64, @floatFromInt(critical)));
    scores.resource_lifecycle = if (acquire == 0) 0 else clamp100(@as(f64, @floatFromInt(acquire - @min(acquire, release))) * 100.0 / @as(f64, @floatFromInt(acquire)));
    scores.input_validation = inputValidationScore(pointer_gap, memcpy_like, bounds_checks, high_risk);
    const fixed_iv = crypto_calls_seen > 0 and detectFixedIv(bytes);
    scores.cryptographic = cryptoScore(crypto_init, crypto_op, crypto_final, crypto_destroy, calls.items, fixed_iv);
    scores.logging_auditability = if (!logging_present or high_risk == 0) 0 else clamp100(@as(f64, @floatFromInt(high_risk - @min(high_risk, logging_calls))) * 100.0 / @as(f64, @floatFromInt(high_risk)));
    const cleanup_stats = cleanupPathStats(instrs[span.instr_start..span.instr_end], calls.items, acquire, release);
    scores.cleanup = cleanup_stats.score(acquire, release);

    if (scores.resource_lifecycle > 50 and acquire > release) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "resource_lifecycle", .message = "aquisicoes de recurso excedem libertacoes observaveis", .severity = 70 });
    }
    if (cleanup_stats.error_dirty_paths > 0) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cleanup", .message = "path de erro sai com recurso adquirido sem libertacao observavel", .severity = 85 });
    } else if (cleanup_stats.dirty_exit_paths > 0 and cleanup_stats.clean_release_exit_paths > 0) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cleanup", .message = "cleanup aparece em alguns paths mas falta noutros paths de saida", .severity = 70 });
    }
    if (scores.cryptographic > 40) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cryptographic", .message = "sequencia criptografica incompleta ou sem destruicao/verificacao observavel", .severity = 80 });
    }
    if (fixed_iv) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "cryptographic", .message = "padrao compativel com IV fixo hardcoded detetado no binario", .severity = 85 });
    }
    if (scores.logging_auditability > 50) {
        try evidence.append(.{ .function_va = span.start, .address = span.start, .category = "logging", .message = "operacoes de alto risco sem logging num binario que contem logging", .severity = 60 });
    }

    const aggregate = scores.aggregate();
    const specificity: f64 = if (high_risk > 0) 1.15 else 0.85;
    const confidence = clamp100(aggregate * specificity);

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
    };
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
    }
    const inv = 1.0 / @as(f64, @floatFromInt(profiles.len));
    avg.error_handling *= inv;
    avg.resource_lifecycle *= inv;
    avg.input_validation *= inv;
    avg.cryptographic *= inv;
    avg.logging_auditability *= inv;
    avg.cleanup *= inv;
    var variance = CategoryScores{};
    for (profiles) |p| {
        variance.error_handling += squared(p.scores.error_handling - avg.error_handling);
        variance.resource_lifecycle += squared(p.scores.resource_lifecycle - avg.resource_lifecycle);
        variance.input_validation += squared(p.scores.input_validation - avg.input_validation);
        variance.cryptographic += squared(p.scores.cryptographic - avg.cryptographic);
        variance.logging_auditability += squared(p.scores.logging_auditability - avg.logging_auditability);
        variance.cleanup += squared(p.scores.cleanup - avg.cleanup);
    }
    const stddev = CategoryScores{
        .error_handling = @sqrt(variance.error_handling * inv),
        .resource_lifecycle = @sqrt(variance.resource_lifecycle * inv),
        .input_validation = @sqrt(variance.input_validation * inv),
        .cryptographic = @sqrt(variance.cryptographic * inv),
        .logging_auditability = @sqrt(variance.logging_auditability * inv),
        .cleanup = @sqrt(variance.cleanup * inv),
    };
    for (profiles) |*p| {
        p.scores.error_handling = normalizeAgainstLocalNorm(p.scores.error_handling, avg.error_handling, stddev.error_handling);
        p.scores.resource_lifecycle = normalizeAgainstLocalNorm(p.scores.resource_lifecycle, avg.resource_lifecycle, stddev.resource_lifecycle);
        p.scores.input_validation = normalizeAgainstLocalNorm(p.scores.input_validation, avg.input_validation, stddev.input_validation);
        p.scores.cryptographic = normalizeAgainstLocalNorm(p.scores.cryptographic, avg.cryptographic, stddev.cryptographic);
        p.scores.logging_auditability = normalizeAgainstLocalNorm(p.scores.logging_auditability, avg.logging_auditability, stddev.logging_auditability);
        p.scores.cleanup = normalizeAgainstLocalNorm(p.scores.cleanup, avg.cleanup, stddev.cleanup);
        p.aggregate_gap = p.scores.aggregate();
        const local_delta = @max(0.0, p.aggregate_gap - normalizeAgainstLocalNorm(avg.aggregate(), avg.aggregate(), stddev.aggregate()));
        p.confidence = clamp100(p.confidence + local_delta * 0.25);
    }
}

fn normalizeAgainstLocalNorm(raw: f64, avg: f64, stddev: f64) f64 {
    if (avg < 12.0) return raw;
    const spread = @max(stddev, 8.0);
    if (raw <= avg) return clamp100(raw * 0.35);
    const z = (raw - avg) / spread;
    const local_excess = clamp100(z * 22.0);
    const retained_absolute = raw * 0.28;
    return clamp100(retained_absolute + local_excess);
}

fn squared(value: f64) f64 {
    return value * value;
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
        if (p.confidence > max_conf) max_conf = p.confidence;
        if (p.aggregate_gap >= 35 or p.confidence >= 55) material_profiles += 1;
    }
    const inv = 1.0 / @as(f64, @floatFromInt(profiles.len));
    scores.error_handling *= inv;
    scores.resource_lifecycle *= inv;
    scores.input_validation *= inv;
    scores.cryptographic *= inv;
    scores.logging_auditability *= inv;
    scores.cleanup *= inv;
    const aggregate = scores.aggregate();
    const material_ratio = @as(f64, @floatFromInt(material_profiles)) / @as(f64, @floatFromInt(profiles.len));
    const threat = classifyThreat(scores, aggregate, max_conf, profiles.len, material_ratio);
    return .{ .threat = threat, .aggregate_gap = aggregate, .anomaly_confidence = clamp100((aggregate + max_conf) / 2.0), .scores = scores };
}

fn classifyThreat(scores: CategoryScores, aggregate: f64, max_conf: f64, function_count: usize, material_ratio: f64) ThreatClass {
    const size_scale = adaptiveThreatScale(function_count);
    const systemic_boost: f64 = if (material_ratio >= 0.20) 0.82 else if (material_ratio >= 0.08) 0.92 else 1.0;
    const scale = size_scale * systemic_boost;
    if (aggregate < 12.0 * scale and max_conf < 25.0 * scale and material_ratio < 0.04) return .No_Material_Gap;
    if (scores.cryptographic > 35.0 * scale and scores.resource_lifecycle > 25.0 * scale and scores.error_handling > 20.0 * scale) return .Ransomware;
    if (scores.logging_auditability > 35.0 * scale and scores.error_handling > 35.0 * scale) return .RAT;
    if (scores.resource_lifecycle > 45.0 * scale and scores.error_handling < 35.0 * scale) return .Dropper;
    if (max_conf > 65.0 * scale and aggregate < 35.0 * scale and material_ratio < 0.08) return .Implant;
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

fn countExecSections(image: BinaryImage) usize {
    var count: usize = 0;
    for (image.sections) |section| {
        if (section.executable) count += 1;
    }
    return count;
}

fn sectionBytes(bytes: []const u8, section: Section) []const u8 {
    if (section.file_offset >= bytes.len) return "";
    const end = @min(bytes.len, section.file_offset + @min(section.size, bytes.len - section.file_offset));
    return bytes[section.file_offset..end];
}

fn readInt(bytes: []const u8, comptime T: type, offset: usize, endian: std.builtin.Endian) !T {
    const info = @typeInfo(T).Int;
    const size = @divExact(info.bits, 8);
    if (offset > bytes.len or bytes.len - offset < size) return error.TruncatedRead;
    return std.mem.readInt(T, bytes[offset..][0..size], endian);
}

fn checkedUsize(value: anytype) !usize {
    const wide: u128 = @intCast(value);
    if (wide > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(wide);
}

fn appendSection(
    sections: *std.ArrayList(Section),
    bytes_len: usize,
    name: []const u8,
    va: anytype,
    file_offset: anytype,
    size: anytype,
    virtual_size: anytype,
    executable: bool,
) !void {
    const off = checkedUsize(file_offset) catch return;
    if (off >= bytes_len) return;
    const raw_size = checkedUsize(size) catch return;
    const clamped_size = @min(raw_size, bytes_len - off);
    if (clamped_size == 0) return;
    try sections.append(.{
        .name = name,
        .va = @intCast(va),
        .file_offset = off,
        .size = clamped_size,
        .virtual_size = @intCast(virtual_size),
        .executable = executable,
    });
}

fn elfSectionStringTable(
    bytes: []const u8,
    shoff_value: anytype,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
    endian: std.builtin.Endian,
    is64: bool,
) []const u8 {
    if (shstrndx >= shnum or shentsize == 0) return "";
    const shoff: u64 = @intCast(shoff_value);
    const hdr = checkedUsize(shoff + @as(u64, shstrndx) * @as(u64, shentsize)) catch return "";
    if (hdr > bytes.len or bytes.len - hdr < shentsize) return "";
    const off64: u64 = if (is64) readInt(bytes, u64, hdr + 24, endian) catch return "" else readInt(bytes, u32, hdr + 16, endian) catch return "";
    const size64: u64 = if (is64) readInt(bytes, u64, hdr + 32, endian) catch return "" else readInt(bytes, u32, hdr + 20, endian) catch return "";
    const off = checkedUsize(off64) catch return "";
    const size = checkedUsize(size64) catch return "";
    if (off > bytes.len or bytes.len - off < size) return "";
    return bytes[off .. off + size];
}

fn cstrAt(buf: []const u8, offset_value: anytype) []const u8 {
    const offset = checkedUsize(offset_value) catch return "";
    if (offset >= buf.len) return "";
    const tail = buf[offset..];
    const len = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
    return tail[0..len];
}

fn readCString(bytes: []const u8, offset: usize) []const u8 {
    if (offset >= bytes.len) return "";
    const tail = bytes[offset..];
    const len = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
    return tail[0..len];
}

fn parseElfSymbols(
    imports: *std.ArrayList(ImportSymbol),
    symbols: *std.ArrayList(Symbol),
    bytes: []const u8,
    strtab: []const u8,
    symtab_off: usize,
    symtab_size: usize,
    symtab_entsize: usize,
    endian: std.builtin.Endian,
    is64: bool,
    dynamic_table: bool,
) !void {
    if (strtab.len == 0 or symtab_off == 0 or symtab_size == 0 or symtab_entsize == 0) return;
    var off = symtab_off;
    const end = @min(bytes.len, symtab_off + @min(symtab_size, bytes.len - symtab_off));
    while (off + symtab_entsize <= end) : (off += symtab_entsize) {
        const name_off = try readInt(bytes, u32, off + 0, endian);
        const info = if (is64) bytes[off + 4] else bytes[off + 12];
        const shndx = if (is64) try readInt(bytes, u16, off + 6, endian) else try readInt(bytes, u16, off + 14, endian);
        const value: u64 = if (is64) try readInt(bytes, u64, off + 8, endian) else try readInt(bytes, u32, off + 4, endian);
        const size: u64 = if (is64) try readInt(bytes, u64, off + 16, endian) else try readInt(bytes, u32, off + 8, endian);
        if (name_off == 0) continue;
        const name = cstrAt(strtab, name_off);
        if (name.len == 0) continue;
        const typ = info & 0x0f;
        if (shndx == 0) {
            if (dynamic_table) try appendImportUnique(imports, name, "", value);
            try appendSymbolUnique(symbols, name, value, size, typ == 2, true);
        } else {
            try appendSymbolUnique(symbols, name, value, size, typ == 2, false);
        }
    }
}

fn appendSymbolUnique(symbols: *std.ArrayList(Symbol), name: []const u8, va: u64, size: u64, is_function: bool, external: bool) !void {
    if (name.len == 0) return;
    for (symbols.items) |existing| {
        if (existing.va == va and asciiEqlIgnoreCase(existing.name, name)) return;
    }
    try symbols.append(.{ .name = name, .va = va, .size = size, .is_function = is_function, .external = external });
}

fn parseElfPltRelocs(
    imports: *std.ArrayList(ImportSymbol),
    bytes: []const u8,
    dynstr: []const u8,
    dynsym_off: usize,
    dynsym_size: usize,
    dynsym_entsize: usize,
    endian: std.builtin.Endian,
    is64: bool,
    relplt_off: usize,
    relplt_size: usize,
    relplt_entsize: usize,
    relplt_is_rela: bool,
    plt_base: u64,
    plt_entsize: usize,
    skip_first_plt_slot: bool,
) !void {
    if (dynstr.len == 0 or dynsym_off == 0 or dynsym_entsize == 0 or relplt_off == 0 or relplt_size == 0 or relplt_entsize == 0 or plt_base == 0) return;
    const max_sym = dynsym_size / dynsym_entsize;
    const end = @min(bytes.len, relplt_off + @min(relplt_size, bytes.len - relplt_off));
    var off = relplt_off;
    var idx: usize = 0;
    while (off + relplt_entsize <= end and idx < 4096) : ({
        off += relplt_entsize;
        idx += 1;
    }) {
        const got_va: u64 = if (is64) try readInt(bytes, u64, off + 0, endian) else try readInt(bytes, u32, off + 0, endian);
        const sym_index: usize = if (is64) blk: {
            const r_info = try readInt(bytes, u64, off + 8, endian);
            break :blk @intCast(r_info >> 32);
        } else blk: {
            const r_info = try readInt(bytes, u32, off + 4, endian);
            break :blk @intCast(r_info >> 8);
        };
        if (sym_index == 0 or sym_index >= max_sym) continue;
        const name = elfSymbolName(bytes, dynstr, dynsym_off, dynsym_entsize, sym_index, endian);
        if (name.len == 0) continue;
        const slot_index = idx + if (skip_first_plt_slot) @as(usize, 1) else @as(usize, 0);
        const plt_va = plt_base + @as(u64, @intCast(slot_index * plt_entsize));
        try updateImportBinding(imports, name, got_va, plt_va);
    }
    _ = relplt_is_rela;
}

fn elfSymbolName(bytes: []const u8, dynstr: []const u8, dynsym_off: usize, dynsym_entsize: usize, sym_index: usize, endian: std.builtin.Endian) []const u8 {
    const sym_off = dynsym_off + sym_index * dynsym_entsize;
    if (sym_off > bytes.len or bytes.len - sym_off < 4) return "";
    const name_off = readInt(bytes, u32, sym_off, endian) catch return "";
    return cstrAt(dynstr, name_off);
}

fn updateImportBinding(imports: *std.ArrayList(ImportSymbol), name: []const u8, got_va: u64, plt_va: u64) !void {
    for (imports.items) |*existing| {
        if (asciiEqlIgnoreCase(existing.name, name)) {
            if (existing.got_va == 0) existing.got_va = got_va;
            if (existing.plt_va == 0) existing.plt_va = plt_va;
            return;
        }
    }
    try imports.append(.{ .name = name, .got_va = got_va, .plt_va = plt_va });
}

fn addScannedKnownImports(imports: *std.ArrayList(ImportSymbol), bytes: []const u8) !void {
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
    };
    for (known) |name| {
        if (std.mem.indexOf(u8, bytes, name) != null) {
            try appendImportUnique(imports, name, "", 0);
        }
    }
}

fn appendImportUnique(imports: *std.ArrayList(ImportSymbol), name: []const u8, dll: []const u8, iat_va: u64) !void {
    for (imports.items) |existing| {
        if (asciiEqlIgnoreCase(existing.name, name)) return;
    }
    try imports.append(.{ .name = name, .dll = dll, .iat_va = iat_va });
}

fn parsePeImports(
    imports: *std.ArrayList(ImportSymbol),
    bytes: []const u8,
    sections: []const Section,
    image_base: u64,
    import_rva: u32,
    format: FileFormat,
) !void {
    if (import_rva == 0) return;
    const descriptor_start = rvaToOffset(sections, import_rva, image_base) orelse return;
    var descriptor_off = descriptor_start;
    var descriptor_count: usize = 0;
    while (descriptor_off <= bytes.len and bytes.len - descriptor_off >= 20 and descriptor_count < 512) : ({
        descriptor_off += 20;
        descriptor_count += 1;
    }) {
        const original_first_thunk = try readInt(bytes, u32, descriptor_off + 0, .little);
        const name_rva = try readInt(bytes, u32, descriptor_off + 12, .little);
        const first_thunk = try readInt(bytes, u32, descriptor_off + 16, .little);
        if (original_first_thunk == 0 and name_rva == 0 and first_thunk == 0) break;

        const dll = if (rvaToOffset(sections, name_rva, image_base)) |name_off| readCString(bytes, name_off) else "unknown";
        const thunk_rva = if (original_first_thunk != 0) original_first_thunk else first_thunk;
        const thunk_off_start = rvaToOffset(sections, thunk_rva, image_base) orelse continue;
        const thunk_size: usize = if (format == .pe64) 8 else 4;
        var thunk_off = thunk_off_start;
        var thunk_index: u64 = 0;
        while (thunk_off <= bytes.len and bytes.len - thunk_off >= thunk_size and thunk_index < 4096) : ({
            thunk_off += thunk_size;
            thunk_index += 1;
        }) {
            const raw_entry: u64 = if (format == .pe64) try readInt(bytes, u64, thunk_off, .little) else try readInt(bytes, u32, thunk_off, .little);
            if (raw_entry == 0) break;
            const ordinal_mask: u64 = if (format == .pe64) 0x8000000000000000 else 0x80000000;
            if ((raw_entry & ordinal_mask) != 0) continue;
            const name_rva_entry: u32 = @intCast(raw_entry & 0x7fffffff);
            const name_off = rvaToOffset(sections, name_rva_entry, image_base) orelse continue;
            if (name_off + 2 >= bytes.len) continue;
            const name = readCString(bytes, name_off + 2);
            if (name.len == 0) continue;
            try appendImportUnique(imports, name, dll, image_base + @as(u64, first_thunk) + thunk_index * @as(u64, @intCast(thunk_size)));
        }
    }
}

fn rvaToOffset(sections: []const Section, rva: u32, image_base: u64) ?usize {
    const va = image_base + @as(u64, rva);
    for (sections) |section| {
        const span = @max(section.virtual_size, @as(u64, @intCast(section.size)));
        if (va >= section.va and va < section.va + span) {
            const delta = va - section.va;
            if (delta > std.math.maxInt(usize)) return null;
            return section.file_offset + @as(usize, @intCast(delta));
        }
    }
    return null;
}

fn elfArch(machine: u16) Arch {
    return switch (machine) {
        3 => .x86,
        62 => .x86_64,
        183 => .arm64,
        else => .unknown,
    };
}

fn peArch(machine: u16) Arch {
    return switch (machine) {
        0x014c => .x86,
        0x8664 => .x86_64,
        0xaa64 => .arm64,
        else => .unknown,
    };
}

fn sectionLess(_: void, a: Section, b: Section) bool {
    if (a.va == b.va) return a.file_offset < b.file_offset;
    return a.va < b.va;
}

const PrefixInfo = struct {
    cursor: usize,
    operand_override: bool = false,
    rex_w: bool = false,
    rex_r: bool = false,
    rex_x: bool = false,
    rex_b: bool = false,
    vex_evex: bool = false,
};

const ModRm = struct {
    len: usize,
    reg: Reg,
    rm: Operand,
    reg_opcode: u8,
};

fn decodeFallback(code: []const u8, offset: usize, va: u64) Decoded {
    if (offset >= code.len) return .{ .off = offset, .va = va, .len = 0 };
    if (offset + 4 <= code.len) {
        const word = readInt(code, u32, offset, .little) catch 0;
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
        else => return boundedDecoded(code, offset, va, 1, .other),
    }
}

fn parsePrefixes(code: []const u8, offset: usize, arch: Arch) PrefixInfo {
    var p = PrefixInfo{ .cursor = offset };
    while (p.cursor < code.len) : (p.cursor += 1) {
        const b = code[p.cursor];
        switch (b) {
            0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65 => continue,
            0x66 => {
                p.operand_override = true;
                continue;
            },
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
        return d;
    }
    return boundedDecoded(code, offset, va, 1, .other);
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
        return .{ .len = len, .reg = reg, .rm = regOperand(regFromBits(rm_bits, p.rex_b)), .reg_opcode = reg_bits };
    }

    var base = regFromBits(rm_bits, p.rex_b);
    var disp: i64 = 0;
    if (rm_bits == 4) {
        if (off + len >= code.len) return null;
        const sib = code[off + len];
        len += 1;
        const sib_base = sib & 0x7;
        if (mode == 0 and sib_base == 5) {
            if (off + len + 4 > code.len) return null;
            if (arch == .x86_64) {
                base = .rip;
                disp = readInt(code, i32, off + len, .little) catch return null;
            } else {
                base = .none;
                disp = @intCast(readInt(code, u32, off + len, .little) catch return null);
            }
            len += 4;
        } else {
            base = regFromBits(sib_base, p.rex_b);
        }
    } else if (mode == 0 and rm_bits == 5) {
        if (off + len + 4 > code.len) return null;
        if (arch == .x86_64) {
            base = .rip;
            disp = readInt(code, i32, off + len, .little) catch return null;
        } else {
            base = .none;
            disp = @intCast(readInt(code, u32, off + len, .little) catch return null);
        }
        len += 4;
    }

    if (mode == 1) {
        if (off + len >= code.len) return null;
        disp += @as(i8, @bitCast(code[off + len]));
        len += 1;
    } else if (mode == 2) {
        if (off + len + 4 > code.len) return null;
        disp += readInt(code, i32, off + len, .little) catch return null;
        len += 4;
    }

    return .{ .len = len, .reg = reg, .rm = memOperand(base, disp), .reg_opcode = reg_bits };
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
        0 => .rax,
        1 => .rcx,
        2 => .rdx,
        3 => .rbx,
        4 => .rsp,
        5 => .rbp,
        6 => .rsi,
        7 => .rdi,
        8 => .r8,
        9 => .r9,
        10 => .r10,
        11 => .r11,
        12 => .r12,
        13 => .r13,
        14 => .r14,
        15 => .r15,
        else => .none,
    };
}

fn regOperand(reg: Reg) Operand {
    return .{ .kind = .reg, .reg = reg };
}

fn immOperand(value: u64) Operand {
    return .{ .kind = .imm, .imm = value };
}

fn memOperand(base: Reg, disp: i64) Operand {
    return .{ .kind = .mem, .base = base, .disp = disp };
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
    const disp = readInt(code, i32, offset, .little) catch return null;
    return addSigned(va + @as(u64, @intCast(len)), disp);
}

fn addSigned(base: u64, disp: i64) ?u64 {
    const value = @as(i128, @intCast(base)) + @as(i128, disp);
    if (value < 0 or value > std.math.maxInt(u64)) return null;
    return @intCast(value);
}

fn buildCallEdges(allocator: Allocator, instrs: []const Decoded, functions: []const FunctionSpan) ![]CallEdge {
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
            if (!exists) try edges.append(.{ .from = function.start, .to = dest.start });
        }
    }
    return edges.toOwnedSlice();
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

fn instructionIndexByVa(instrs: []const Decoded, va: u64) ?usize {
    for (instrs, 0..) |instr, idx| {
        if (instr.va == va) return idx;
    }
    return null;
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

fn u64Less(_: void, a: u64, b: u64) bool {
    return a < b;
}

fn resolveCallInfo(image: BinaryImage, instr: Decoded) ResolvedName {
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

fn categorizeCall(name: []const u8) CallCategory {
    if (name.len == 0 or asciiEqlIgnoreCase(name, "direct_call") or asciiEqlIgnoreCase(name, "indirect_call")) return .generic;
    if (containsAny(name, &.{ "socket", "connect", "send", "recv", "internet", "http", "winhttp", "curl", "dns", "wsa" })) return .network;
    if (containsAny(name, &.{ "file", "fopen", "open", "read", "write", "deletefile", "copyfile", "movefile", "closehandle" })) return .file;
    if (containsAny(name, &.{ "malloc", "calloc", "realloc", "free", "heap", "virtualalloc", "virtualfree", "localalloc", "localfree", "mmap", "munmap" })) return .memory;
    if (containsAny(name, &.{ "crypt", "bcrypt", "evp_", "aes", "rsa", "sha", "cipher", "encrypt", "decrypt" })) return .crypto;
    if (containsAny(name, &.{ "regopen", "regset", "regquery", "regclose", "registry" })) return .registry;
    if (containsAny(name, &.{ "createprocess", "openprocess", "writeprocessmemory", "createremotethread", "exec", "fork", "system" })) return .process;
    if (containsAny(name, &.{ "syslog", "reportevent", "eventwrite", "outputdebugstring", "log_" }) or asciiContainsIgnoreCase(name, "logger")) return .logging;
    if (containsAny(name, &.{ "cleanup", "close", "destroy", "release" })) return .cleanup;
    return .generic;
}

fn callRole(name: []const u8, category: CallCategory) CallRole {
    if (category == .crypto) {
        if (containsAny(name, &.{ "init", "open", "acquire" })) return .crypto_init;
        if (containsAny(name, &.{ "final", "finish" })) return .crypto_final;
        if (containsAny(name, &.{ "destroy", "free", "close", "release" })) return .crypto_destroy;
        return .crypto_op;
    }
    if (containsAny(name, &.{ "malloc", "calloc", "realloc", "alloc", "open", "create", "socket", "connect", "acquire", "mmap" })) return .acquire;
    if (containsAny(name, &.{ "free", "close", "destroy", "release", "closesocket", "munmap" })) return .release;
    return .neutral;
}

fn callReturnChecked(instrs: []const Decoded, span: FunctionSpan, call_idx: usize) bool {
    var tracked = [_]Reg{ .none, .none, .none, .none };
    var tracked_count: usize = 1;
    tracked[0] = .rax;
    var saw_return_test = false;
    var idx = call_idx + 1;
    const end = @min(span.instr_end, call_idx + 1 + @max(max_following_check, @as(usize, 12)));
    while (idx < end) : (idx += 1) {
        const instr = instrs[idx];
        if (instr.kind == .mov and instr.op_count >= 2 and instr.operand(0).kind == .reg and operandTouchesTrackedReg(instr.operand(1), tracked[0..tracked_count])) {
            addTrackedReg(&tracked, &tracked_count, instr.operand(0).reg);
        }
        if ((instr.kind == .cmp or instr.kind == .test_) and instrTouchesTrackedReg(instr, tracked[0..tracked_count])) {
            saw_return_test = true;
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

fn operandTouchesReg(instr: Decoded, reg: Reg) bool {
    var i: usize = 0;
    while (i < instr.op_count) : (i += 1) {
        const op = instr.operand(i);
        if (op.kind == .reg and regFamily(op.reg) == regFamily(reg)) return true;
    }
    return false;
}

fn regFamily(reg: Reg) Reg {
    return switch (reg) {
        .eax, .ax, .al => .rax,
        .ecx, .cx, .cl => .rcx,
        .edx, .dx, .dl => .rdx,
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

fn isHighRiskCategory(category: CallCategory) bool {
    return switch (category) {
        .network, .file, .crypto, .registry, .process => true,
        else => false,
    };
}

fn isCriticalReturnCall(category: CallCategory, role: CallRole) bool {
    return isHighRiskCategory(category) or role == .acquire or role == .crypto_init or role == .crypto_op or category == .memory;
}

fn isCopyLike(name: []const u8) bool {
    return containsAny(name, &.{ "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "readfile", "recv", "read" });
}

fn detectLoggingPresent(bytes: []const u8, imports: []const ImportSymbol) bool {
    for (imports) |imp| {
        if (categorizeCall(imp.name) == .logging) return true;
    }
    return std.mem.indexOf(u8, bytes, "logger") != null or std.mem.indexOf(u8, bytes, "audit") != null or std.mem.indexOf(u8, bytes, "syslog") != null;
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
    const family = regFamily(reg);
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

fn inputValidationScore(pointer_gap: bool, memcpy_like: usize, bounds_checks: usize, high_risk: usize) f64 {
    var score: f64 = 0;
    if (pointer_gap) score += 55;
    if (memcpy_like > 0 and bounds_checks == 0) score += 35;
    if (high_risk > 0 and pointer_gap) score += 10;
    return clamp100(score);
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
    return clamp100(score);
}

fn detectFixedIv(bytes: []const u8) bool {
    const fixed_strings = [_][]const u8{
        "0123456789abcdef",
        "0000000000000000",
        "abcdefghijklmnop",
        "AAAAAAAAAAAAAAAA",
        "1234567890abcdef",
    };
    for (fixed_strings) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern) != null) return true;
    }
    return false;
}

const CleanupState = struct {
    idx: usize,
    outstanding: bool,
    release_seen: bool,
    error_like: bool,
};

fn cleanupPathStats(instrs: []const Decoded, calls: []const ResolvedCall, acquire: usize, release: usize) CleanupPathStats {
    if (acquire == 0) return .{};
    if (instrs.len == 0) return .{ .exit_paths = 1, .dirty_exit_paths = if (acquire > release) 1 else 0 };
    if (instrs.len > max_cleanup_cfg_instrs) return cleanupPathStatsLinear(instrs, calls, acquire, release);

    var stats = CleanupPathStats{};
    var visited = std.StaticBitSet(max_cleanup_cfg_instrs * cleanup_state_variants).initEmpty();
    var stack: [max_cleanup_cfg_instrs * cleanup_state_variants]CleanupState = undefined;
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
    return state.idx * cleanup_state_variants + variant;
}

fn pushCleanupState(stack: *[max_cleanup_cfg_instrs * cleanup_state_variants]CleanupState, stack_len: *usize, state: CleanupState, stats: *CleanupPathStats) void {
    if (state.idx >= max_cleanup_cfg_instrs) {
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

fn clamp100(value: f64) f64 {
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
}

fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (asciiContainsIgnoreCase(haystack, needle)) return true;
    }
    return false;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (asciiEqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn writeJson(path: []const u8, analysis: Analysis) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeAnalysisJson(file.writer(), analysis);
}

fn writeJsonStdout(analysis: Analysis) !void {
    try writeAnalysisJson(std.io.getStdOut().writer(), analysis);
}

fn writeAnalysisJson(w: anytype, analysis: Analysis) !void {
    try w.writeAll("{\n");
    try w.writeAll("  \"tool\": \"IntegrityGap\",\n");
    try w.writeAll("  \"version\": \"1.0\",\n");
    try w.writeAll("  \"target\": ");
    try writeJsonString(w, analysis.target_path);
    try w.writeAll(",\n");
    try w.writeAll("  \"sha256\": \"");
    try writeHexHash(w, analysis.sha256);
    try w.writeAll("\",\n");
    try w.print("  \"format\": \"{s}\",\n", .{@tagName(analysis.image.format)});
    try w.print("  \"arch\": \"{s}\",\n", .{@tagName(analysis.image.arch)});
    try w.print("  \"entry_va\": \"0x{x}\",\n", .{analysis.image.entry_va});
    try w.print("  \"executable_sections\": {},\n", .{countExecSections(analysis.image)});
    try w.print("  \"imports\": {},\n", .{analysis.image.imports.len});
    try w.print("  \"exports\": {},\n", .{analysis.image.exports_count});
    try w.print("  \"relocations\": {},\n", .{analysis.image.relocations_count});
    try w.print("  \"instructions\": {},\n", .{analysis.instructions.len});
    try w.print("  \"functions\": {},\n", .{analysis.functions.len});
    try w.print("  \"functions_identified\": {},\n", .{analysis.functions.len});
    try w.print("  \"functions_analyzed\": {},\n", .{analysis.profiles.len});
    try w.print("  \"symbols\": {},\n", .{analysis.image.symbols.len});
    try w.print("  \"logging_present\": {},\n", .{analysis.logging_present});
    try w.writeAll("  \"summary\": ");
    try writeSummaryJson(w, analysis.summary, "  ");
    try w.writeAll(",\n");

    try w.writeAll("  \"functions_detail\": [\n");
    for (analysis.profiles, 0..) |profile, idx| {
        try writeFunctionJson(w, profile, analysis.evidence, "    ");
        if (idx + 1 < analysis.profiles.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    try w.writeAll("  \"evidence\": [\n");
    for (analysis.evidence, 0..) |ev, idx| {
        try writeEvidenceJson(w, ev, "    ");
        if (idx + 1 < analysis.evidence.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    try w.writeAll("  \"call_graph\": [\n");
    for (analysis.call_edges, 0..) |edge, idx| {
        try w.print("    {{\"from\":\"0x{x}\",\"to\":\"0x{x}\"}}", .{ edge.from, edge.to });
        if (idx + 1 < analysis.call_edges.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ]\n");
    try w.writeAll("}\n");
}

fn writeSummaryJson(w: anytype, summary: Summary, indent: []const u8) !void {
    _ = indent;
    try w.writeAll("{");
    try w.print("\"threat_class\":\"{s}\",\"aggregate_gap\":{d:.2},\"anomaly_confidence\":{d:.2},\"scores\":", .{
        @tagName(summary.threat),
        summary.aggregate_gap,
        summary.anomaly_confidence,
    });
    try writeScoresJson(w, summary.scores);
    try w.writeAll("}");
}

fn writeScoresJson(w: anytype, scores: CategoryScores) !void {
    try w.print(
        "{{\"error_handling\":{d:.2},\"resource_lifecycle\":{d:.2},\"input_validation\":{d:.2},\"cryptographic\":{d:.2},\"logging_auditability\":{d:.2},\"cleanup\":{d:.2}}}",
        .{ scores.error_handling, scores.resource_lifecycle, scores.input_validation, scores.cryptographic, scores.logging_auditability, scores.cleanup },
    );
}

fn writeFunctionJson(w: anytype, profile: FunctionProfile, evidence: []const Evidence, indent: []const u8) !void {
    try w.print("{s}{{\"start\":\"0x{x}\",\"end\":\"0x{x}\",\"instruction_count\":{},\"aggregate_gap\":{d:.2},\"anomaly_confidence\":{d:.2},", .{
        indent,
        profile.span.start,
        profile.span.end,
        profile.span.instr_end - profile.span.instr_start,
        profile.aggregate_gap,
        profile.confidence,
    });
    try w.writeAll("\"scores\":");
    try writeScoresJson(w, profile.scores);
    try w.print(",\"critical_calls\":{},\"unchecked_critical_calls\":{},\"acquire_calls\":{},\"release_calls\":{},\"high_risk_calls\":{},\"logging_calls\":{},\"cleanup_exit_paths\":{},\"cleanup_dirty_exit_paths\":{},\"cleanup_error_dirty_paths\":{},\"pointer_deref_before_validation\":{},", .{
        profile.critical_calls,
        profile.unchecked_critical_calls,
        profile.acquire_calls,
        profile.release_calls,
        profile.high_risk_calls,
        profile.logging_calls,
        profile.cleanup_exit_paths,
        profile.cleanup_dirty_exit_paths,
        profile.cleanup_error_dirty_paths,
        profile.pointer_deref_before_validation,
    });
    try w.writeAll("\"calls\":[");
    for (profile.calls, 0..) |call, idx| {
        if (idx > 0) try w.writeAll(",");
        try w.print("{{\"address\":\"0x{x}\",\"name\":", .{call.va});
        try writeJsonString(w, call.name);
        try w.print(",\"category\":\"{s}\",\"role\":\"{s}\",\"checked\":{},\"high_risk\":{}", .{ @tagName(call.category), @tagName(call.role), call.checked, call.high_risk });
        if (call.target) |target| try w.print(",\"target\":\"0x{x}\"", .{target});
        try w.writeAll("}");
    }
    try w.writeAll("],\"evidence\":[");
    const end = @min(evidence.len, profile.evidence_start + profile.evidence_count);
    var first = true;
    for (evidence[profile.evidence_start..end]) |ev| {
        if (!first) try w.writeAll(",");
        first = false;
        try writeEvidenceJson(w, ev, "");
    }
    try w.writeAll("]}");
}

fn writeEvidenceJson(w: anytype, ev: Evidence, indent: []const u8) !void {
    try w.print("{s}{{\"function\":\"0x{x}\",\"address\":\"0x{x}\",\"category\":", .{ indent, ev.function_va, ev.address });
    try writeJsonString(w, ev.category);
    try w.writeAll(",\"message\":");
    try writeJsonString(w, ev.message);
    try w.print(",\"severity\":{}}}", .{ev.severity});
}

fn writePlain(analysis: Analysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("IntegrityGap: {s}\n", .{analysis.target_path});
    try w.print("Formato: {s}/{s}  Entry: 0x{x}\n", .{ @tagName(analysis.image.format), @tagName(analysis.image.arch), analysis.image.entry_va });
    try w.print("Classificacao: {s}  Gap: {d:.2}  Confidence: {d:.2}\n", .{ @tagName(analysis.summary.threat), analysis.summary.aggregate_gap, analysis.summary.anomaly_confidence });
    try w.print("Scores: error={d:.1} resource={d:.1} input={d:.1} crypto={d:.1} logging={d:.1} cleanup={d:.1}\n", .{
        analysis.summary.scores.error_handling,
        analysis.summary.scores.resource_lifecycle,
        analysis.summary.scores.input_validation,
        analysis.summary.scores.cryptographic,
        analysis.summary.scores.logging_auditability,
        analysis.summary.scores.cleanup,
    });
    try w.print("Funcoes identificadas/analisadas: {}/{}  Instrucoes: {}  Evidencias: {}\n", .{ analysis.functions.len, analysis.profiles.len, analysis.instructions.len, analysis.evidence.len });
    try w.writeAll("\nFuncoes com gap material:\n");
    var shown: usize = 0;
    for (analysis.profiles) |profile| {
        if (profile.aggregate_gap < 10 and profile.confidence < 25) continue;
        try w.print("  0x{x}-0x{x} gap={d:.2} conf={d:.2} critical={}/{} resources={}/{} cleanup_dirty={}/{}\n", .{
            profile.span.start,
            profile.span.end,
            profile.aggregate_gap,
            profile.confidence,
            profile.unchecked_critical_calls,
            profile.critical_calls,
            profile.release_calls,
            profile.acquire_calls,
            profile.cleanup_dirty_exit_paths,
            profile.cleanup_exit_paths,
        });
        shown += 1;
        if (shown >= 20) break;
    }
    if (shown == 0) try w.writeAll("  sem gaps materiais acima do limiar rapido\n");
}

fn writeDot(path: []const u8, analysis: Analysis) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    const w = file.writer();
    try w.writeAll("digraph IntegrityGap {\n");
    try w.writeAll("  rankdir=LR;\n  node [shape=box,fontname=\"monospace\",fontsize=10];\n  edge [color=gray50,arrowsize=0.6];\n");
    try w.writeAll("  legend [shape=note,label=\"IntegrityGap\\nverde: gap baixo\\namarelo: medio\\nlaranja/vermelho: alto\\narestas: call graph real\"];\n");
    for (analysis.profiles, 0..) |profile, idx| {
        const color = gapColor(profile.aggregate_gap);
        try w.print("  f{} [label=\"0x{x}\\ngap={d:.1}\\nconf={d:.1}\\n{s}\",style=filled,fillcolor=\"{s}\"];\n", .{
            idx,
            profile.span.start,
            profile.aggregate_gap,
            profile.confidence,
            topGapName(profile.scores),
            color,
        });
    }
    for (analysis.call_edges) |edge| {
        const from = functionIndexByStart(analysis.functions, edge.from) orelse continue;
        const to = functionIndexByStart(analysis.functions, edge.to) orelse continue;
        try w.print("  f{} -> f{};\n", .{ from, to });
    }
    try w.writeAll("}\n");
}

fn gapColor(score: f64) []const u8 {
    if (score >= 70) return "#e53935";
    if (score >= 40) return "#fb8c00";
    if (score >= 15) return "#fdd835";
    return "#66bb6a";
}

fn topGapName(scores: CategoryScores) []const u8 {
    var best = scores.error_handling;
    var name: []const u8 = "error";
    if (scores.resource_lifecycle > best) { best = scores.resource_lifecycle; name = "resource"; }
    if (scores.input_validation > best) { best = scores.input_validation; name = "input"; }
    if (scores.cryptographic > best) { best = scores.cryptographic; name = "crypto"; }
    if (scores.logging_auditability > best) { best = scores.logging_auditability; name = "logging"; }
    if (scores.cleanup > best) { name = "cleanup"; }
    return name;
}

fn functionIndexByStart(functions: []const FunctionSpan, start: u64) ?usize {
    for (functions, 0..) |function, idx| {
        if (function.start == start) return idx;
    }
    return null;
}

fn writeDiffJson(path: []const u8, base: Analysis, other: Analysis, baseline_mode: bool) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeDiffJsonTo(file.writer(), base, other, baseline_mode);
}

fn writeDiffStdout(base: Analysis, other: Analysis, baseline_mode: bool) !void {
    try writeDiffJsonTo(std.io.getStdOut().writer(), base, other, baseline_mode);
}

fn writeDiffJsonTo(w: anytype, base: Analysis, other: Analysis, baseline_mode: bool) !void {
    const similarity = scoreSimilarity(base.summary.scores, other.summary.scores);
    try w.writeAll("{\n");
    try w.print("  \"tool\": \"IntegrityGap\",\n  \"diff_mode\": {},\n  \"baseline_mode\": {},\n", .{ !baseline_mode, baseline_mode });
    try w.writeAll("  \"base\": ");
    try writeJsonString(w, base.target_path);
    try w.writeAll(",\n  \"target\": ");
    try writeJsonString(w, other.target_path);
    try w.writeAll(",\n");
    try w.print("  \"base_threat\": \"{s}\",\n  \"target_threat\": \"{s}\",\n  \"global_similarity\": {d:.2},\n", .{
        @tagName(base.summary.threat),
        @tagName(other.summary.threat),
        similarity,
    });
    try w.print("  \"aggregate_gap_delta\": {d:.2},\n  \"confidence_delta\": {d:.2},\n", .{
        other.summary.aggregate_gap - base.summary.aggregate_gap,
        other.summary.anomaly_confidence - base.summary.anomaly_confidence,
    });
    try w.writeAll("  \"category_delta\": ");
    try writeScoresDeltaJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll(",\n");
    try w.print("  \"function_count_delta\": {},\n  \"evidence_count_delta\": {},\n", .{
        @as(isize, @intCast(other.functions.len)) - @as(isize, @intCast(base.functions.len)),
        @as(isize, @intCast(other.evidence.len)) - @as(isize, @intCast(base.evidence.len)),
    });
    try w.writeAll("  \"semantic_change\": ");
    try writeSemanticDiffJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll(",\n  \"semantic_changes\": ");
    try writeSemanticChangesJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll("\n");
    try w.writeAll("}\n");
}

fn writeScoresDeltaJson(w: anytype, a: CategoryScores, b: CategoryScores) !void {
    try w.print(
        "{{\"error_handling\":{d:.2},\"resource_lifecycle\":{d:.2},\"input_validation\":{d:.2},\"cryptographic\":{d:.2},\"logging_auditability\":{d:.2},\"cleanup\":{d:.2}}}",
        .{
            b.error_handling - a.error_handling,
            b.resource_lifecycle - a.resource_lifecycle,
            b.input_validation - a.input_validation,
            b.cryptographic - a.cryptographic,
            b.logging_auditability - a.logging_auditability,
            b.cleanup - a.cleanup,
        },
    );
}

fn scoreSimilarity(a: CategoryScores, b: CategoryScores) f64 {
    const dist =
        @abs(a.error_handling - b.error_handling) +
        @abs(a.resource_lifecycle - b.resource_lifecycle) +
        @abs(a.input_validation - b.input_validation) +
        @abs(a.cryptographic - b.cryptographic) +
        @abs(a.logging_auditability - b.logging_auditability) +
        @abs(a.cleanup - b.cleanup);
    return clamp100(100.0 - dist / 6.0);
}

fn writeSemanticDiffJson(w: anytype, base: CategoryScores, other: CategoryScores) !void {
    const name = dominantDeltaCategory(base, other);
    const delta = categoryDeltaByName(base, other, name);
    try w.writeAll("{\"dominant_category\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"direction\":");
    try writeJsonString(w, if (delta > 2.5) "worse" else if (delta < -2.5) "better" else "stable");
    try w.print(",\"magnitude\":{d:.2},\"classification\":", .{delta});
    try writeJsonString(w, semanticChangeClass(name, delta));
    try w.writeAll("}");
}

fn writeSemanticChangesJson(w: anytype, base: CategoryScores, other: CategoryScores) !void {
    const items = [_][]const u8{
        "error_handling",
        "resource_lifecycle",
        "input_validation",
        "cryptographic",
        "logging_auditability",
        "cleanup",
    };
    try w.writeAll("[");
    for (items, 0..) |name, idx| {
        if (idx > 0) try w.writeAll(",");
        const delta = categoryDeltaByName(base, other, name);
        try w.writeAll("{\"category\":");
        try writeJsonString(w, name);
        try w.writeAll(",\"direction\":");
        try writeJsonString(w, if (delta > 2.5) "worse" else if (delta < -2.5) "better" else "stable");
        try w.print(",\"delta\":{d:.2},\"classification\":", .{delta});
        try writeJsonString(w, semanticChangeClass(name, delta));
        try w.writeAll("}");
    }
    try w.writeAll("]");
}

fn dominantDeltaCategory(base: CategoryScores, other: CategoryScores) []const u8 {
    var name: []const u8 = "error_handling";
    var best = @abs(other.error_handling - base.error_handling);
    const candidates = [_]struct { name: []const u8, delta: f64 }{
        .{ .name = "resource_lifecycle", .delta = @abs(other.resource_lifecycle - base.resource_lifecycle) },
        .{ .name = "input_validation", .delta = @abs(other.input_validation - base.input_validation) },
        .{ .name = "cryptographic", .delta = @abs(other.cryptographic - base.cryptographic) },
        .{ .name = "logging_auditability", .delta = @abs(other.logging_auditability - base.logging_auditability) },
        .{ .name = "cleanup", .delta = @abs(other.cleanup - base.cleanup) },
    };
    for (candidates) |candidate| {
        if (candidate.delta > best) {
            best = candidate.delta;
            name = candidate.name;
        }
    }
    return name;
}

fn categoryDeltaByName(base: CategoryScores, other: CategoryScores, name: []const u8) f64 {
    if (std.mem.eql(u8, name, "error_handling")) return other.error_handling - base.error_handling;
    if (std.mem.eql(u8, name, "resource_lifecycle")) return other.resource_lifecycle - base.resource_lifecycle;
    if (std.mem.eql(u8, name, "input_validation")) return other.input_validation - base.input_validation;
    if (std.mem.eql(u8, name, "cryptographic")) return other.cryptographic - base.cryptographic;
    if (std.mem.eql(u8, name, "logging_auditability")) return other.logging_auditability - base.logging_auditability;
    return other.cleanup - base.cleanup;
}

fn semanticChangeClass(name: []const u8, delta: f64) []const u8 {
    if (@abs(delta) <= 2.5) return "semantically_stable";
    if (delta < 0) return "integrity_improved";
    if (std.mem.eql(u8, name, "error_handling")) return "weaker_error_handling";
    if (std.mem.eql(u8, name, "resource_lifecycle")) return "weaker_resource_lifecycle";
    if (std.mem.eql(u8, name, "input_validation")) return "weaker_input_validation";
    if (std.mem.eql(u8, name, "cryptographic")) return "weaker_crypto_integrity";
    if (std.mem.eql(u8, name, "logging_auditability")) return "weaker_auditability";
    return "weaker_cleanup";
}

fn writeJsonString(w: anytype, text: []const u8) !void {
    const hex = "0123456789abcdef";
    try w.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11...12, 14...31 => {
                try w.writeAll("\\u00");
                try w.writeByte(hex[byte >> 4]);
                try w.writeByte(hex[byte & 0x0f]);
            },
            else => try w.writeByte(byte),
        }
    }
    try w.writeByte('"');
}

fn writeHexHash(w: anytype, hash: [32]u8) !void {
    const hex = "0123456789abcdef";
    for (hash) |byte| {
        try w.writeByte(hex[byte >> 4]);
        try w.writeByte(hex[byte & 0x0f]);
    }
}
