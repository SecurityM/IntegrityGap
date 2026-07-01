const std = @import("std");

pub const Allocator = std.mem.Allocator;

pub const default_max_bytes = 256 * 1024 * 1024;
pub const max_following_check = 12;
pub const max_cleanup_cfg_instrs = 2048;
pub const cleanup_state_variants = 8;

pub const FileFormat = enum { elf32, elf64, pe32, pe64, macho32, macho64, raw };
pub const Arch = enum { x86, x86_64, arm64, arm, riscv64, mips, powerpc, wasm, unknown };

pub const Section = struct {
    name: []const u8 = "",
    va: u64,
    file_offset: usize,
    size: usize,
    virtual_size: u64,
    executable: bool,
    writable: bool = false,
    contains_code: bool = false,
    alignment: u64 = 0,
};

pub const ImportSymbol = struct {
    name: []const u8,
    dll: []const u8 = "",
    iat_va: u64 = 0,
    plt_va: u64 = 0,
    got_va: u64 = 0,
    ordinal: u16 = 0,
    hint: u16 = 0,
};

pub const Symbol = struct {
    name: []const u8,
    va: u64,
    size: u64 = 0,
    is_function: bool = false,
    external: bool = false,
    binding: u8 = 0,
    visibility: u8 = 0,
    section_index: u16 = 0,
};

pub const Relocation = struct {
    va: u64,
    offset: u64,
    type_index: u32,
    symbol_index: u32,
    addend: i64,
    is_relative: bool = false,
};

pub const BinaryImage = struct {
    format: FileFormat,
    arch: Arch,
    entry_va: u64,
    image_base: u64,
    sections: []Section,
    imports: []ImportSymbol,
    symbols: []Symbol,
    exports_count: usize = 0,
    relocations_count: usize = 0,
    relocations: []Relocation = &[_]Relocation{},
    subsystem: u16 = 0,
    major_linker_version: u8 = 0,
    minor_linker_version: u8 = 0,
    is_pie: bool = false,
    is_signed: bool = false,
    has_tls: bool = false,
    has_import_table: bool = false,
    has_export_table: bool = false,
    has_exception_table: bool = false,
    has_debug_table: bool = false,
    has_rich_header: bool = false,
    compile_timestamp: i64 = 0,
    stack_reserve_size: u64 = 0,
    stack_commit_size: u64 = 0,
    heap_reserve_size: u64 = 0,
    heap_commit_size: u64 = 0,
    dll_characteristics: u16 = 0,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.sections);
        allocator.free(self.imports);
        allocator.free(self.symbols);
        allocator.free(self.relocations);
    }
};

pub const InstrKind = enum(u16) {
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
    imul,
    idiv,
    div,
    mul,
    not_,
    neg,
    inc,
    dec,
    shl,
    shr,
    sar,
    rol,
    ror,
    xchg,
    cmovcc,
    setcc,
    cpuid,
    rdtsc,
    syscall,
    sysenter,
    int3,
    into,
    bound,
};

pub const Reg = enum(u8) {
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
    ebx = 26,
    bx = 27,
    bl = 28,
    esp = 29,
    ebp = 30,
    esi = 31,
    edi = 32,
    r8d = 33,
    r8w = 34,
    r8b = 35,
    r9d = 36,
    r9w = 37,
    r9b = 38,
    r10d = 39,
    r10w = 40,
    r10b = 41,
    r11d = 42,
    r11w = 43,
    r11b = 44,
    r12d = 45,
    r12w = 46,
    r12b = 47,
    r13d = 48,
    r13w = 49,
    r13b = 50,
    r14d = 51,
    r14w = 52,
    r14b = 53,
    r15d = 54,
    r15w = 55,
    r15b = 56,
    xmm0 = 57,
    xmm1 = 58,
    xmm2 = 59,
    xmm3 = 60,
    xmm4 = 61,
    xmm5 = 62,
    xmm6 = 63,
    xmm7 = 64,
    xmm8 = 65,
    xmm9 = 66,
    xmm10 = 67,
    xmm11 = 68,
    xmm12 = 69,
    xmm13 = 70,
    xmm14 = 71,
    xmm15 = 72,
};

pub const OperandKind = enum { none, reg, imm, mem, rel8, rel32, segment };

pub const Operand = struct {
    kind: OperandKind = .none,
    reg: Reg = .none,
    base: Reg = .none,
    index: Reg = .none,
    scale: u8 = 0,
    disp: i64 = 0,
    imm: u64 = 0,
    mem_va: ?u64 = null,
    segment: u8 = 0,
};

pub const Decoded = struct {
    va: u64,
    off: usize,
    len: usize,
    kind: InstrKind = .other,
    target: ?u64 = null,
    op_count: u8 = 0,
    operands: [3]Operand = .{ Operand{}, Operand{}, Operand{} },
    indirect: bool = false,
    mem_read: bool = false,
    mem_write: bool = false,
    has_modrm: bool = false,
    has_sib: bool = false,
    prefix_count: u8 = 0,
    rep_prefix: bool = false,
    lock_prefix: bool = false,
    op_size_override: bool = false,
    addr_size_override: bool = false,

    pub fn operand(self: @This(), idx: usize) Operand {
        if (idx >= self.op_count) return Operand{};
        return self.operands[idx];
    }

    pub fn isBranch(self: @This()) bool {
        return self.kind == .call or self.kind == .jmp or self.kind == .jcc or self.kind == .ret;
    }

    pub fn isTerminal(self: @This()) bool {
        return self.kind == .ret or self.kind == .syscall or self.kind == .sysenter;
    }
};

pub const FunctionSpan = struct {
    start: u64,
    end: u64,
    instr_start: usize,
    instr_end: usize,
    name: []const u8 = "",
    is_leaf: bool = false,
    is_thunk: bool = false,
    is_plt: bool = false,
    call_count: usize = 0,
    basic_block_count: usize = 0,
    cyclomatic_complexity: u32 = 0,
};

pub const CallCategory = enum {
    generic,
    network,
    file,
    memory,
    crypto,
    registry,
    process,
    logging,
    cleanup,
    synchronization,
    threading,
    serialization,
    ui,
    audio,
    graphics,
    database,
};

pub const CallRole = enum {
    neutral,
    acquire,
    release,
    crypto_init,
    crypto_op,
    crypto_final,
    crypto_destroy,
    lock_acquire,
    lock_release,
    thread_create,
    thread_join,
};

pub const ResolvedCall = struct {
    va: u64,
    target: ?u64,
    name: []const u8,
    category: CallCategory,
    role: CallRole,
    checked: bool,
    high_risk: bool,
    is_dynamic: bool = false,
    call_depth: u32 = 0,
};

pub const ResolvedName = struct {
    name: []const u8,
    external: bool,
};

pub const CategoryScores = struct {
    error_handling: f64 = 0,
    resource_lifecycle: f64 = 0,
    input_validation: f64 = 0,
    cryptographic: f64 = 0,
    logging_auditability: f64 = 0,
    cleanup: f64 = 0,
    concurrency: f64 = 0,
    memory_safety: f64 = 0,
    configuration: f64 = 0,
    supply_chain: f64 = 0,

    pub fn aggregate(self: @This()) f64 {
        return clamp100(
            self.error_handling * 0.15 +
                self.resource_lifecycle * 0.12 +
                self.input_validation * 0.10 +
                self.cryptographic * 0.13 +
                self.logging_auditability * 0.08 +
                self.cleanup * 0.10 +
                self.concurrency * 0.10 +
                self.memory_safety * 0.10 +
                self.configuration * 0.06 +
                self.supply_chain * 0.06,
        );
    }
};

pub const Evidence = struct {
    function_va: u64,
    address: u64,
    category: []const u8,
    message: []const u8,
    severity: u8,
    module: []const u8 = "integrity_gap",
    confidence: f64 = 1.0,
    cwe_id: u32 = 0,
};

pub const FunctionProfile = struct {
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
    has_stack_canary: bool = false,
    frame_size: usize = 0,
    uses_alloca: bool = false,
    uses_setjmp: bool = false,
    has_vla: bool = false,
    is_recursive: bool = false,
    recursion_depth: u32 = 0,
};

pub const CleanupPathStats = struct {
    exit_paths: usize = 0,
    dirty_exit_paths: usize = 0,
    error_dirty_paths: usize = 0,
    clean_release_exit_paths: usize = 0,
    truncated: bool = false,

    pub fn score(self: @This(), acquire: usize, release: usize) f64 {
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

pub const ThreatClass = enum {
    No_Material_Gap,
    Implant,
    Dropper,
    RAT,
    Ransomware,
    Legitimate_Anomalous,
    Supply_Chain_Compromise,
    Firmware_Backdoor,
    Crypto_Malware,
    Rootkit,
    Bootkit,
    InfoStealer,
    Loader,
    Downloader,
    KeyLogger,
    Worm,
};

pub const Summary = struct {
    threat: ThreatClass,
    aggregate_gap: f64,
    anomaly_confidence: f64,
    scores: CategoryScores,
};

pub const Analysis = struct {
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
    has_pdb_info: bool = false,
    pdb_path: []const u8 = "",
    compile_time: i64 = 0,
    is_dotnet: bool = false,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
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

pub const CallEdge = struct { from: u64, to: u64, call_type: CallType = .direct };
pub const CallType = enum { direct, indirect, tail, virtual };

pub const PrefixInfo = struct {
    cursor: usize,
    operand_override: bool = false,
    address_override: bool = false,
    rex_w: bool = false,
    rex_r: bool = false,
    rex_x: bool = false,
    rex_b: bool = false,
    vex_evex: bool = false,
    rep: bool = false,
    repne: bool = false,
    lock: bool = false,
    branch_not_taken: bool = false,
    branch_taken: bool = false,
};

pub const ModRm = struct {
    len: usize,
    reg: Reg,
    rm: Operand,
    reg_opcode: u8,
    mod_value: u8 = 0,
    rm_value: u8 = 0,
    has_sib: bool = false,
    scale: u8 = 0,
    index: Reg = .none,
};

pub const CleanupState = struct {
    idx: usize,
    outstanding: bool,
    release_seen: bool,
    error_like: bool,
};

pub const VersionInfo = struct {
    major: u16,
    minor: u16,
    patch: u16,
    build: u16,
    product_name: []const u8 = "",
    company_name: []const u8 = "",
    file_description: []const u8 = "",
    file_version: []const u8 = "",
    product_version: []const u8 = "",
    legal_copyright: []const u8 = "",
    legal_trademarks: []const u8 = "",
    original_filename: []const u8 = "",
    internal_name: []const u8 = "",
};

pub const DebugInfo = struct {
    debug_type: DebugType,
    timestamp: i64 = 0,
    age: u32 = 0,
    guid: [16]u8 = [_]u8{0} ** 16,
    path: []const u8 = "",
    codeview_signature: u32 = 0,
};

pub const DebugType = enum {
    codeview,
    coff,
    fpo,
    exception,
    fixup,
    omap_to_src,
    omap_from_src,
    borland,
    reserved10,
    clsid,
    unknown,
};

pub const RichHeaderEntry = struct {
    product_id: u16,
    build_id: u16,
    count: u32,
};

pub const BasicBlock = struct {
    start_va: u64,
    end_va: u64,
    instr_start: usize,
    instr_end: usize,
    successors: []u64,
    predecessors: []u64,
    dominates: bool = false,
    is_loop_header: bool = false,
    is_exit_block: bool = false,
    depth: u32 = 0,
};

fn clamp100(value: f64) f64 {
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
}
