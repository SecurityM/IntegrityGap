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

pub const MemoryAccess = struct {
    address: u64,
    function_va: u64,
    instr_va: u64,
    is_write: bool,
    access_size: usize,
    is_atomic: bool,
    synchronized: bool,
    severity: u8,
};

pub const LockOperation = struct {
    address: u64,
    function_va: u64,
    instr_va: u64,
    lock_type: LockType,
    is_acquire: bool,
    guarded_region: ?GuardedRegion = null,
};

pub const LockType = enum {
    mutex,
    critical_section,
    spinlock,
    rwlock,
    semaphore,
    atomic,
    unknown,
};

pub const GuardedRegion = struct {
    start_va: u64,
    end_va: u64,
    function_va: u64,
    lock_va: u64,
    unlock_va: u64,
    function_name: []const u8 = "",
    has_nested_lock: bool = false,
    has_early_exit: bool = false,
    has_missing_unlock: bool = false,
};

pub const RaceCondition = struct {
    address: u64,
    function_va: u64,
    access1: MemoryAccess,
    access2: MemoryAccess,
    severity: u8,
    description: []const u8 = "",
};

pub const ThreadingIssue = struct {
    function_va: u64,
    address: u64,
    issue_type: ThreadingIssueType,
    severity: u8,
    description: []const u8 = "",
};

pub const ThreadingIssueType = enum {
    missing_synchronization,
    double_lock,
    lock_ordering_violation,
    lock_held_during_blocking_call,
    unchecked_thread_create,
    potential_deadlock,
    potential_livelock,
    thread_affinity_issue,
    unguarded_shared_access,
};

pub const ThreadCreateInfo = struct {
    address: u64,
    function_va: u64,
    thread_func_va: u64,
    thread_func_name: []const u8 = "",
};

pub const ConcurrencyAnalysis = struct {
    memory_accesses: []MemoryAccess,
    lock_operations: []LockOperation,
    guarded_regions: []GuardedRegion,
    race_conditions: []RaceCondition,
    threading_issues: []ThreadingIssue,
    thread_creates: []ThreadCreateInfo,
    unguarded_shared_data: usize,
    total_shared_locations: usize,
    deadlock_potential: f64,
    concurrency_gap_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.memory_accesses);
        allocator.free(self.lock_operations);
        allocator.free(self.guarded_regions);
        allocator.free(self.race_conditions);
        allocator.free(self.threading_issues);
        allocator.free(self.thread_creates);
    }
};

const lock_function_names = [_][]const u8{
    "EnterCriticalSection", "LeaveCriticalSection", "InitializeCriticalSection",
    "pthread_mutex_lock", "pthread_mutex_unlock", "pthread_mutex_init", "pthread_mutex_destroy",
    "pthread_rwlock_rdlock", "pthread_rwlock_wrlock", "pthread_rwlock_unlock",
    "pthread_spin_lock", "pthread_spin_unlock", "pthread_spin_init", "pthread_spin_destroy",
    "CreateMutexA", "CreateMutexW", "OpenMutexA", "OpenMutexW", "ReleaseMutex",
    "WaitForSingleObject", "WaitForMultipleObjects", "SetEvent", "ResetEvent", "CreateEventA",
    "sem_wait", "sem_post", "sem_init", "sem_destroy",
    "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange",
    "__sync_fetch_and_add", "__sync_lock_test_and_set", "__sync_val_compare_and_swap",
    "__atomic_add_fetch", "__atomic_store_n", "__atomic_load_n",
};

const thread_function_names = [_][]const u8{
    "CreateThread", "CreateRemoteThread", "_beginthreadex", "pthread_create",
    "std::thread", "std::async", "std::future",
};

fn matchLockFunction(name: []const u8) ?struct { lock_type: LockType, is_acquire: bool } {
    const lower = name;
    if (utils.containsAny(lower, &.{ "EnterCriticalSection", "pthread_mutex_lock", "pthread_spin_lock", "pthread_rwlock_rdlock", "pthread_rwlock_wrlock" }))
        return .{ .lock_type = .mutex, .is_acquire = true };
    if (utils.containsAny(lower, &.{ "LeaveCriticalSection", "pthread_mutex_unlock", "pthread_spin_unlock", "pthread_rwlock_unlock" }))
        return .{ .lock_type = .mutex, .is_acquire = false };
    if (utils.containsAny(lower, &.{ "CreateMutex", "OpenMutex", "WaitForSingleObject" }))
        return .{ .lock_type = .mutex, .is_acquire = true };
    if (utils.asciiEqlIgnoreCase(lower, "ReleaseMutex"))
        return .{ .lock_type = .mutex, .is_acquire = false };
    if (utils.containsAny(lower, &.{ "sem_wait" }))
        return .{ .lock_type = .semaphore, .is_acquire = true };
    if (utils.containsAny(lower, &.{ "sem_post" }))
        return .{ .lock_type = .semaphore, .is_acquire = false };
    if (utils.containsAny(lower, &.{ "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange", "__sync_", "__atomic_" }))
        return .{ .lock_type = .atomic, .is_acquire = true };
    return null;
}

fn isThreadFunction(name: []const u8) bool {
    return utils.containsAny(name, &thread_function_names);
}

pub fn analyzeConcurrency(allocator: Allocator, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !ConcurrencyAnalysis {
    var memory_accesses = std.ArrayList(MemoryAccess).init(allocator);
    errdefer memory_accesses.deinit();
    var lock_operations = std.ArrayList(LockOperation).init(allocator);
    errdefer lock_operations.deinit();
    var guarded_regions = std.ArrayList(GuardedRegion).init(allocator);
    errdefer guarded_regions.deinit();
    var race_conditions = std.ArrayList(RaceCondition).init(allocator);
    errdefer race_conditions.deinit();
    var threading_issues = std.ArrayList(ThreadingIssue).init(allocator);
    errdefer threading_issues.deinit();
    var thread_creates = std.ArrayList(ThreadCreateInfo).init(allocator);
    errdefer thread_creates.deinit();

    var shared_data_locations = std.AutoHashMap(u64, usize).init(allocator);
    defer shared_data_locations.deinit();
    var shared_data_writes = std.AutoHashMap(u64, usize).init(allocator);
    defer shared_data_writes.deinit();

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        var lock_stack: [16]u64 = undefined;
        var lock_stack_len: usize = 0;
        var last_lock_va: ?u64 = null;

        for (func_instrs, 0..func_instrs.len) |instr, local_idx| {
            if (instr.mem_read or instr.mem_write) {
                if (instr.op_count > 0) {
                    const op = instr.operand(0);
                    if (op.kind == .mem) {
                        if (op.mem_va) |mem_va| {
                            const is_shared = isLikelySharedMemory(mem_va, image);
                            if (is_shared) {
                                try memory_accesses.append(.{
                                    .address = mem_va,
                                    .function_va = function.start,
                                    .instr_va = instr.va,
                                    .is_write = instr.mem_write,
                                    .access_size = detectAccessSize(instr),
                                    .is_atomic = false,
                                    .synchronized = lock_stack_len > 0,
                                    .severity = if (instr.mem_write and lock_stack_len == 0) 70 else 30,
                                });

                                const entry = shared_data_locations.getOrPut(mem_va) catch continue;
                                entry.value_ptr.* += 1;
                                if (instr.mem_write) {
                                    const wentry = shared_data_writes.getOrPut(mem_va) catch continue;
                                    wentry.value_ptr.* += 1;
                                }
                            }
                        }
                    }
                }
            }

            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                const name = resolved.name;

                if (isThreadFunction(name)) {
                    const thread_func = extractThreadFunctionArg(instr, func_instrs, local_idx, image);
                    try thread_creates.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .thread_func_va = thread_func orelse 0,
                        .thread_func_name = "",
                    });
                    if (thread_func == null) {
                        try threading_issues.append(.{
                            .function_va = function.start,
                            .address = instr.va,
                            .issue_type = .unchecked_thread_create,
                            .severity = 60,
                            .description = "Thread creation without visible function pointer resolution",
                        });
                    }
                }

                if (matchLockFunction(name)) |lock_info| {
                    try lock_operations.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .instr_va = instr.va,
                        .lock_type = lock_info.lock_type,
                        .is_acquire = lock_info.is_acquire,
                    });

                    if (lock_info.is_acquire) {
                        if (lock_stack_len > 0) {
                            var has_prev = false;
                            for (lock_stack[0..lock_stack_len]) |prev_lock| {
                                if (prev_lock == instr.va) {
                                    has_prev = true;
                                    break;
                                }
                            }
                            if (!has_prev and lock_stack_len > 0) {
                                const prev = lock_stack[lock_stack_len - 1];
                                if (!isSameLockType(prev, instr.va, lock_operations.items)) {
                                    try threading_issues.append(.{
                                        .function_va = function.start,
                                        .address = instr.va,
                                        .issue_type = .lock_ordering_violation,
                                        .severity = 75,
                                        .description = "Potential lock ordering violation - different lock types nested",
                                    });
                                }
                            }
                        }
                        if (lock_stack_len < lock_stack.len) {
                            lock_stack[lock_stack_len] = instr.va;
                            lock_stack_len += 1;
                        }
                        last_lock_va = instr.va;
                    } else {
                        if (lock_stack_len > 0) {
                            lock_stack_len -= 1;
                        } else {
                            try threading_issues.append(.{
                                .function_va = function.start,
                                .address = instr.va,
                                .issue_type = .missing_synchronization,
                                .severity = 80,
                                .description = "Unlock without matching lock detected",
                            });
                        }
                    }
                }

                const call_is_blocking = isBlockingCall(name);
                if (call_is_blocking and lock_stack_len > 0) {
                    try threading_issues.append(.{
                        .function_va = function.start,
                        .address = instr.va,
                        .issue_type = .lock_held_during_blocking_call,
                        .severity = 70,
                        .description = "Blocking call while lock is held - potential deadlock",
                    });
                }
            }

            if (instr.kind == .ret and lock_stack_len > 0 and isFunctionWithoutUnlock(func_instrs, local_idx, image)) {
                try guarded_regions.append(.{
                    .start_va = last_lock_va orelse 0,
                    .end_va = instr.va,
                    .function_va = function.start,
                    .lock_va = if (lock_stack_len > 0) lock_stack[lock_stack_len - 1] else 0,
                    .unlock_va = 0,
                    .has_missing_unlock = true,
                });
                try threading_issues.append(.{
                    .function_va = function.start,
                    .address = instr.va,
                    .issue_type = .missing_synchronization,
                    .severity = 85,
                    .description = "Function returns with lock still held",
                });
            }
        }
    }

    var shared_locations: usize = 0;
    var unguarded_locations: usize = 0;
    var shared_iter = shared_data_locations.iterator();
    while (shared_iter.next()) |entry| {
        shared_locations += 1;
        const writes = shared_data_writes.get(entry.key_ptr.*) orelse 0;
        if (writes > 0) {
            var is_guarded = false;
            for (lock_operations.items) |lock_op| {
                if (lock_op.is_acquire) {
                    for (memory_accesses.items) |access| {
                        if (access.address == entry.key_ptr.* and access.synchronized) {
                            is_guarded = true;
                            break;
                        }
                    }
                }
                if (is_guarded) break;
            }
            if (!is_guarded) {
                unguarded_locations += 1;
                var has_race = false;
                for (memory_accesses.items) |access| {
                    if (access.address == entry.key_ptr.* and access.is_write and !access.synchronized) {
                        if (!has_race) {
                            for (memory_accesses.items) |access2| {
                                if (access2.address == entry.key_ptr.* and access2.instr_va != access.instr_va and (!access2.synchronized or access2.function_va != access.function_va)) {
                                    try race_conditions.append(.{
                                        .address = entry.key_ptr.*,
                                        .function_va = access.function_va,
                                        .access1 = access,
                                        .access2 = access2,
                                        .severity = 80,
                                        .description = "Potential data race on shared memory location",
                                    });
                                    has_race = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    const concurrency_score = computeConcurrencyScore(
        race_conditions.items.len,
        threading_issues.items.len,
        unguarded_locations,
        shared_locations,
        lock_operations.items.len,
    );

    return .{
        .memory_accesses = try memory_accesses.toOwnedSlice(),
        .lock_operations = try lock_operations.toOwnedSlice(),
        .guarded_regions = try guarded_regions.toOwnedSlice(),
        .race_conditions = try race_conditions.toOwnedSlice(),
        .threading_issues = try threading_issues.toOwnedSlice(),
        .thread_creates = try thread_creates.toOwnedSlice(),
        .unguarded_shared_data = unguarded_locations,
        .total_shared_locations = shared_locations,
        .deadlock_potential = if (lock_operations.items.len > 0) computeDeadlockPotential(lock_operations.items) else 0,
        .concurrency_gap_score = concurrency_score,
    };
}

fn detectAccessSize(instr: Decoded) usize {
    for (0..2) |i| {
        const op = instr.operand(i);
        if (op.kind == .mem) {
            if (op.base == .none) return 8;
        }
    }
    return 4;
}

fn isLikelySharedMemory(va: u64, image: BinaryImage) bool {
    for (image.sections) |section| {
        if (section.va <= va and va < section.va + section.virtual_size) {
            if (!section.executable) {
                const name = section.name;
                if (std.mem.indexOf(u8, name, ".data") != null or
                    std.mem.indexOf(u8, name, ".bss") != null or
                    std.mem.indexOf(u8, name, ".rdata") != null or
                    std.mem.indexOf(u8, name, "DATA") != null)
                    return true;
            }
            return false;
        }
    }
    return false;
}

fn extractThreadFunctionArg(instr: Decoded, func_instrs: []const Decoded, local_idx: usize, image: BinaryImage) ?u64 {
    if (instr.op_count > 0) {
        const op = instr.operand(0);
        if (op.kind == .imm) {
            for (image.symbols) |sym| {
                if (sym.is_function and sym.va == op.imm) return sym.va;
            }
            return op.imm;
        }
        if (op.kind == .reg) {
            const reg = op.reg;
            var i: usize = local_idx;
            while (i > 0) {
                i -= 1;
                const prev = func_instrs[i];
                if (prev.kind == .mov and prev.op_count >= 2) {
                    const dst = prev.operand(0);
                    const src = prev.operand(1);
                    if (dst.kind == .reg and decoder.regFamily(dst.reg) == decoder.regFamily(reg)) {
                        if (src.kind == .imm) {
                            for (image.symbols) |sym| {
                                if (sym.is_function and sym.va == src.imm) return sym.va;
                            }
                            return src.imm;
                        }
                    }
                }
                if (prev.kind == .call or prev.kind == .ret) break;
            }
        }
    }
    return null;
}

fn isSameLockType(lock1_va: u64, lock2_va: u64, lock_ops: []const LockOperation) bool {
    var type1: LockType = .unknown;
    var type2: LockType = .unknown;
    for (lock_ops) |op| {
        if (op.instr_va == lock1_va) type1 = op.lock_type;
        if (op.instr_va == lock2_va) type2 = op.lock_type;
    }
    return type1 == type2;
}

fn isBlockingCall(name: []const u8) bool {
    return utils.containsAny(name, &.{
        "sleep", "WaitForSingleObject", "WaitForMultipleObjects", "WaitForSingleObjectEx",
        "MsgWaitForMultipleObjects", "SleepEx", "SwitchToThread",
        "read", "write", "recv", "send", "accept", "connect",
        "fread", "fwrite", "fscanf", "fgets", "fgetc",
        "pthread_join", "join", "future.get", "condition_variable.wait",
    });
}

fn isFunctionWithoutUnlock(func_instrs: []const Decoded, ret_idx: usize, image: BinaryImage) bool {
    const end = @min(func_instrs.len, ret_idx + 1);
    for (func_instrs[0..end]) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (matchLockFunction(resolved.name)) |lock| {
                if (!lock.is_acquire) return false;
            }
        }
    }
    return true;
}

fn computeDeadlockPotential(lock_ops: []const LockOperation) f64 {
    var acquire_count: usize = 0;
    var release_count: usize = 0;
    for (lock_ops) |op| {
        if (op.is_acquire) acquire_count += 1 else release_count += 1;
    }
    if (acquire_count == 0) return 0;
    const imbalance = if (acquire_count > release_count)
        @as(f64, @floatFromInt(acquire_count - release_count)) / @as(f64, @floatFromInt(acquire_count))
    else
        0;
    return utils.clamp100(imbalance * 85.0);
}

fn computeConcurrencyScore(race_count: usize, issue_count: usize, unguarded: usize, total_shared: usize, lock_count: usize) f64 {
    if (total_shared == 0 and lock_count == 0) return 0;
    var score: f64 = 0;
    if (total_shared > 0) {
        score += @as(f64, @floatFromInt(unguarded)) * 50.0 / @as(f64, @floatFromInt(total_shared));
    }
    score += @as(f64, @floatFromInt(race_count)) * 15.0;
    score += @as(f64, @floatFromInt(issue_count)) * 10.0;
    if (lock_count == 0 and total_shared > 0) score += 30;
    return utils.clamp100(score);
}

pub fn analyzeAtomicUsage(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]ThreadingIssue {
    var issues = std.ArrayList(ThreadingIssue).init(allocator);
    errdefer issues.deinit();
    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (resolved.external and utils.containsAny(resolved.name, &.{ "Interlocked", "__sync", "__atomic" })) {
                const prefix = resolved.name;
                if (utils.containsAny(prefix, &.{ "Exchange", "CompareExchange", "Compare_And_Swap" })) {
                    continue;
                }
            }
        }
        if (instr.kind == .mov and instr.mem_write and instr.mem_read) {
            if (instr.operand(0).kind == .mem and instr.operand(1).kind == .mem) {
                try issues.append(.{
                    .function_va = 0,
                    .address = instr.va,
                    .issue_type = .unguarded_shared_access,
                    .severity = 50,
                    .description = "Memory-to-memory move without atomic guarantee",
                });
            }
        }
    }
    return issues.toOwnedSlice();
}

pub fn detectDeadlockPatterns(allocator: Allocator, lock_ops: []const LockOperation) ![]RaceCondition {
    var races = std.ArrayList(RaceCondition).init(allocator);
    errdefer races.deinit();
    var lock_order_map = std.AutoHashMap(u64, std.ArrayList(u64)).init(allocator);
    defer {
        var it = lock_order_map.valueIterator();
        while (it.next()) |list| list.deinit();
        lock_order_map.deinit();
    }
    var i: usize = 0;
    while (i < lock_ops.len) {
        if (lock_ops[i].is_acquire) {
            var j = i + 1;
            while (j < lock_ops.len and j - i < 20) : (j += 1) {
                if (lock_ops[j].is_acquire and lock_ops[j].instr_va != lock_ops[i].instr_va) {
                    const list = try lock_order_map.getOrPut(lock_ops[i].instr_va);
                    if (!list.found_existing) list.value_ptr.* = std.ArrayList(u64).init(allocator);
                    try list.value_ptr.*.append(lock_ops[j].instr_va);
                    break;
                }
                if (!lock_ops[j].is_acquire and lock_ops[j].lock_type == lock_ops[i].lock_type) break;
            }
        }
        i += 1;
    }
    return races.toOwnedSlice();
}
