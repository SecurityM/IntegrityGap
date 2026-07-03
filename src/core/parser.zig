const std = @import("std");
const types = @import("../types.zig");
const utils = @import("utils.zig");
const signatures = @import("signatures.zig");

const Allocator = types.Allocator;
const FileFormat = types.FileFormat;
const Arch = types.Arch;
const Section = types.Section;
const ImportSymbol = types.ImportSymbol;
const Symbol = types.Symbol;
const BinaryImage = types.BinaryImage;
const Relocation = types.Relocation;
const VersionInfo = types.VersionInfo;
const DebugInfo = types.DebugInfo;
const DebugType = types.DebugType;
const RichHeaderEntry = types.RichHeaderEntry;

pub fn parseBinary(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\x7fELF")) return parseElf(allocator, bytes);
    if (bytes.len >= 2 and std.mem.eql(u8, bytes[0..2], "MZ")) return parsePe(allocator, bytes);
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\xfe\xed\xfa\xce")) return parseMachO(allocator, bytes, .big);
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\xfe\xed\xfa\xcf")) return parseMachO(allocator, bytes, .big);
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\xce\xfa\xed\xfe")) return parseMachO(allocator, bytes, .little);
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\xcf\xfa\xed\xfe")) return parseMachO(allocator, bytes, .little);
    if (bytes.len >= 4 and std.mem.eql(u8, bytes[0..4], "\xca\xfe\xba\xbe")) return parseMachOFat(allocator, bytes);
    return error.UnsupportedBinaryFormat;
}

fn parseElf(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len < 0x40) return error.TruncatedElfHeader;
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

fn parseElfCommon(_: Allocator, bytes: []const u8, endian: std.builtin.Endian, is64: bool) !struct {
    machine: u16,
    entry: u64,
    shoff: u64,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
    flags: u32,
    type_index: u16,
} {
    const machine = try utils.readInt(bytes, u16, 0x12, endian);
    const entry: u64 = if (is64) try utils.readInt(bytes, u64, 0x18, endian) else try utils.readInt(bytes, u32, 0x18, endian);
    const phoff: u64 = if (is64) try utils.readInt(bytes, u64, 0x20, endian) else try utils.readInt(bytes, u32, 0x1c, endian);
    const shoff: u64 = if (is64) try utils.readInt(bytes, u64, 0x28, endian) else try utils.readInt(bytes, u32, 0x20, endian);
    const flags: u32 = if (is64) try utils.readInt(bytes, u32, 0x24, endian) else try utils.readInt(bytes, u32, 0x24, endian);
    const type_index: u16 = try utils.readInt(bytes, u16, 0x10, endian);
    const phentsize: u16 = if (is64) @as(u16, 56) else @as(u16, 32);
    const phnum: u16 = if (is64) try utils.readInt(bytes, u16, 0x38, endian) else try utils.readInt(bytes, u16, 0x2c, endian);
    const shentsize: u16 = if (is64) try utils.readInt(bytes, u16, 0x3a, endian) else try utils.readInt(bytes, u16, 0x2e, endian);
    const shnum: u16 = if (is64) try utils.readInt(bytes, u16, 0x3c, endian) else try utils.readInt(bytes, u16, 0x30, endian);
    const shstrndx: u16 = if (is64) try utils.readInt(bytes, u16, 0x3e, endian) else try utils.readInt(bytes, u16, 0x32, endian);
    return .{ .machine = machine, .entry = entry, .shoff = shoff, .shentsize = shentsize, .shnum = shnum, .shstrndx = shstrndx, .phoff = phoff, .phentsize = phentsize, .phnum = phnum, .flags = flags, .type_index = type_index };
}

fn parseElf32(allocator: Allocator, bytes: []const u8, endian: std.builtin.Endian) !BinaryImage {
    const hdr = try parseElfCommon(allocator, bytes, endian, false);
    const machine = hdr.machine;
    const entry = hdr.entry;
    const shoff = hdr.shoff;
    const shentsize = hdr.shentsize;
    const shnum = hdr.shnum;
    const shstrndx = hdr.shstrndx;
    const phoff = hdr.phoff;
    const phentsize = hdr.phentsize;
    const phnum = hdr.phnum;
    _ = hdr.flags;
    _ = hdr.type_index;

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var symbols = std.ArrayList(Symbol).init(allocator);
    errdefer symbols.deinit();
    var relocations = std.ArrayList(Relocation).init(allocator);
    errdefer relocations.deinit();

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
    var dyn_off: usize = 0;
    var dyn_size: usize = 0;
    var dynamic_section_va: u64 = 0;
    var interpreter_offset: usize = 0;
    var is_pie = false;
    var has_interp = false;

    if (phoff > 0 and phnum > 0 and phentsize > 0) {
        var ph_idx: u16 = 0;
        while (ph_idx < phnum) : (ph_idx += 1) {
            const ph_off = utils.checkedUsize(phoff + @as(u64, ph_idx) * @as(u64, phentsize)) catch break;
            if (ph_off > bytes.len or bytes.len - ph_off < phentsize) break;
            const p_type = try utils.readInt(bytes, u32, ph_off, endian);
            if (p_type == 2) { is_pie = true; }
            if (p_type == 3) {
                const p_offset = try utils.readInt(bytes, u32, ph_off + 4, endian);
                if (p_offset < bytes.len) {
                    has_interp = true;
                    interpreter_offset = utils.checkedUsize(p_offset) catch 0;
                }
            }
        }
    }

    var imports_from_dynamic: usize = 0;

    for (0..shnum) |idx| {
        const off = utils.checkedUsize(shoff + @as(u64, @intCast(idx)) * shentsize) catch break;
        if (off > bytes.len or bytes.len - off < shentsize) break;
        const name_off = try utils.readInt(bytes, u32, off + 0, endian);
        const sh_type = try utils.readInt(bytes, u32, off + 4, endian);
        const sh_flags = try utils.readInt(bytes, u32, off + 8, endian);
        const sh_addr = try utils.readInt(bytes, u32, off + 12, endian);
        const sh_offset = try utils.readInt(bytes, u32, off + 16, endian);
        const sh_size = try utils.readInt(bytes, u32, off + 20, endian);
        const sh_entsize = try utils.readInt(bytes, u32, off + 36, endian);
        const sh_addralign = try utils.readInt(bytes, u32, off + 32, endian);
        const name = utils.cstrAt(shstr, name_off);

        if (sh_type != 8) {
            try appendSection(&sections, bytes.len, name, sh_addr, sh_offset, sh_size, sh_size, (sh_flags & 0x4) != 0, (sh_flags & 0x2) != 0, (sh_flags & 0x4) != 0, sh_addralign);
        }

        if (sh_type == 6 and sh_offset > 0 and sh_size > 0) {
            dyn_off = utils.checkedUsize(sh_offset) catch 0;
            dyn_size = utils.checkedUsize(sh_size) catch 0;
            dynamic_section_va = sh_addr;
        }

        if (std.mem.eql(u8, name, ".plt")) {
            plt_va = sh_addr;
            plt_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.eql(u8, name, ".plt.sec")) {
            plt_sec_va = sh_addr;
            plt_sec_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.indexOf(u8, name, ".rela.plt") != null) {
            relplt_off = utils.checkedUsize(sh_offset) catch 0;
            relplt_size = utils.checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 12 else utils.checkedUsize(sh_entsize) catch 12;
            relplt_is_rela = true;
        } else if (std.mem.indexOf(u8, name, ".rel.plt") != null) {
            relplt_off = utils.checkedUsize(sh_offset) catch 0;
            relplt_size = utils.checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 8 else utils.checkedUsize(sh_entsize) catch 8;
            relplt_is_rela = false;
        }

        if (std.mem.eql(u8, name, ".dynstr")) {
            const start = utils.checkedUsize(sh_offset) catch continue;
            const size = utils.checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) dynstr = bytes[start .. start + size];
        } else if (std.mem.eql(u8, name, ".strtab")) {
            const start = utils.checkedUsize(sh_offset) catch continue;
            const size = utils.checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) strtab = bytes[start .. start + size];
        }

        if (sh_type == 11 or std.mem.eql(u8, name, ".dynsym")) {
            dynsym_off = utils.checkedUsize(sh_offset) catch 0;
            dynsym_size = utils.checkedUsize(sh_size) catch 0;
            dynsym_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (sh_type == 2 or std.mem.eql(u8, name, ".symtab")) {
            symtab_off = utils.checkedUsize(sh_offset) catch 0;
            symtab_size = utils.checkedUsize(sh_size) catch 0;
            symtab_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (sh_type == 4 or std.mem.indexOf(u8, name, ".rela") != null or std.mem.indexOf(u8, name, ".rel") != null) {
            if (sh_offset > 0 and sh_size > 0 and (sh_type == 4 or sh_type == 9)) {
                const rel_off = utils.checkedUsize(sh_offset) catch 0;
                const rel_size = utils.checkedUsize(sh_size) catch 0;
                const rel_entsize = if (sh_entsize == 0) if (sh_type == 4) @as(usize, 8) else @as(usize, 12) else utils.checkedUsize(sh_entsize) catch 8;
                try parseElfRelocations(&relocations, bytes, rel_off, rel_size, rel_entsize, endian, sh_type == 9);
            }
        }
    }

    if (dynamic_section_va > 0 and dyn_off > 0 and dyn_size > 0) {
        imports_from_dynamic = try parseElfDynamicImports(&imports, bytes, dynstr, dyn_off, dyn_size, endian, false);
    }

    if (imports_from_dynamic == 0) {
        try parseElfSymbols(&imports, &symbols, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, false, true);
        try parseElfSymbols(&imports, &symbols, bytes, strtab, symtab_off, symtab_size, symtab_entsize, endian, false, false);
    }

    try parseElfPltRelocs(&imports, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, false, relplt_off, relplt_size, relplt_entsize, relplt_is_rela, if (plt_sec_va != 0) plt_sec_va else plt_va, if (plt_sec_va != 0) plt_sec_entsize else plt_entsize, plt_sec_va == 0);
    try signatures.addScannedKnownImports(&imports, bytes);

    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);
    const relocs_count = relocations.items.len;

    return .{
        .format = .elf32, .arch = elfArch(machine), .entry_va = entry, .image_base = 0,
        .sections = owned_sections, .imports = try imports.toOwnedSlice(),
        .symbols = try symbols.toOwnedSlice(), .relocations = try relocations.toOwnedSlice(),
        .exports_count = 0, .relocations_count = relocs_count,
        .is_pie = is_pie, .has_import_table = true,
    };
}

fn parseElf64(allocator: Allocator, bytes: []const u8, endian: std.builtin.Endian) !BinaryImage {
    const hdr = try parseElfCommon(allocator, bytes, endian, true);
    const machine = hdr.machine;
    const entry = hdr.entry;
    const shoff = hdr.shoff;
    const shentsize = hdr.shentsize;
    const shnum = hdr.shnum;
    const shstrndx = hdr.shstrndx;
    const phoff = hdr.phoff;
    const phentsize = hdr.phentsize;
    const phnum = hdr.phnum;
    _ = hdr.flags;
    _ = hdr.type_index;

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var symbols = std.ArrayList(Symbol).init(allocator);
    errdefer symbols.deinit();
    var relocations = std.ArrayList(Relocation).init(allocator);
    errdefer relocations.deinit();

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
    var dyn_off: usize = 0;
    var dyn_size: usize = 0;
    var dynamic_section_va: u64 = 0;
    var interpreter_offset: usize = 0;
    var is_pie = false;
    var has_interp = false;

    if (phoff > 0 and phnum > 0 and phentsize > 0) {
        var ph_idx: u16 = 0;
        while (ph_idx < phnum) : (ph_idx += 1) {
            const ph_off = utils.checkedUsize(phoff + @as(u64, ph_idx) * @as(u64, phentsize)) catch break;
            if (ph_off > bytes.len or bytes.len - ph_off < phentsize) break;
            const p_type = try utils.readInt(bytes, u32, ph_off, endian);
            if (p_type == 2) { is_pie = true; }
            if (p_type == 3) {
                const p_offset = try utils.readInt(bytes, u64, ph_off + 8, endian);
                if (p_offset < bytes.len) {
                    has_interp = true;
                    interpreter_offset = utils.checkedUsize(p_offset) catch 0;
                }
            }
        }
    }

    for (0..shnum) |idx| {
        const off = utils.checkedUsize(shoff + @as(u64, @intCast(idx)) * shentsize) catch break;
        if (off > bytes.len or bytes.len - off < shentsize) break;
        const name_off = try utils.readInt(bytes, u32, off + 0, endian);
        const sh_type = try utils.readInt(bytes, u32, off + 4, endian);
        const sh_flags = try utils.readInt(bytes, u64, off + 8, endian);
        const sh_addr = try utils.readInt(bytes, u64, off + 16, endian);
        const sh_offset = try utils.readInt(bytes, u64, off + 24, endian);
        const sh_size = try utils.readInt(bytes, u64, off + 32, endian);
        const sh_entsize = try utils.readInt(bytes, u64, off + 56, endian);
        const sh_addralign = try utils.readInt(bytes, u64, off + 48, endian);
        const name = utils.cstrAt(shstr, name_off);

        if (sh_type != 8) {
            try appendSection(&sections, bytes.len, name, sh_addr, sh_offset, sh_size, sh_size, (sh_flags & 0x4) != 0, (sh_flags & 0x2) != 0, (sh_flags & 0x4) != 0, sh_addralign);
        }

        if (sh_type == 6 and sh_offset > 0 and sh_size > 0) {
            dyn_off = utils.checkedUsize(sh_offset) catch 0;
            dyn_size = utils.checkedUsize(sh_size) catch 0;
            dynamic_section_va = sh_addr;
        }

        if (std.mem.eql(u8, name, ".debug_info")) {
            if (sh_offset > 0 and sh_size > 0) {
                const dbg_off = utils.checkedUsize(sh_offset) catch 0;
                _ = dbg_off;
            }
        }

        if (std.mem.eql(u8, name, ".plt")) {
            plt_va = sh_addr;
            plt_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.eql(u8, name, ".plt.sec")) {
            plt_sec_va = sh_addr;
            plt_sec_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
        } else if (std.mem.indexOf(u8, name, ".rela.plt") != null) {
            relplt_off = utils.checkedUsize(sh_offset) catch 0;
            relplt_size = utils.checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 24 else utils.checkedUsize(sh_entsize) catch 24;
            relplt_is_rela = true;
        } else if (std.mem.indexOf(u8, name, ".rel.plt") != null) {
            relplt_off = utils.checkedUsize(sh_offset) catch 0;
            relplt_size = utils.checkedUsize(sh_size) catch 0;
            relplt_entsize = if (sh_entsize == 0) 16 else utils.checkedUsize(sh_entsize) catch 16;
            relplt_is_rela = false;
        }

        if (std.mem.eql(u8, name, ".dynstr")) {
            const start = utils.checkedUsize(sh_offset) catch continue;
            const size = utils.checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) dynstr = bytes[start .. start + size];
        } else if (std.mem.eql(u8, name, ".strtab")) {
            const start = utils.checkedUsize(sh_offset) catch continue;
            const size = utils.checkedUsize(sh_size) catch continue;
            if (start <= bytes.len and bytes.len - start >= size) strtab = bytes[start .. start + size];
        }

        if (sh_type == 11 or std.mem.eql(u8, name, ".dynsym")) {
            dynsym_off = utils.checkedUsize(sh_offset) catch 0;
            dynsym_size = utils.checkedUsize(sh_size) catch 0;
            dynsym_entsize = if (sh_entsize == 0) 24 else utils.checkedUsize(sh_entsize) catch 24;
        } else if (sh_type == 2 or std.mem.eql(u8, name, ".symtab")) {
            symtab_off = utils.checkedUsize(sh_offset) catch 0;
            symtab_size = utils.checkedUsize(sh_size) catch 0;
            symtab_entsize = if (sh_entsize == 0) 24 else utils.checkedUsize(sh_entsize) catch 24;
        } else if (sh_type == 4 or sh_type == 9) {
            if (sh_offset > 0 and sh_size > 0) {
                const rel_off = utils.checkedUsize(sh_offset) catch 0;
                const rel_size = utils.checkedUsize(sh_size) catch 0;
                const rel_entsize = if (sh_entsize == 0) if (sh_type == 4) @as(usize, 16) else @as(usize, 24) else utils.checkedUsize(sh_entsize) catch 16;
                try parseElfRelocations(&relocations, bytes, rel_off, rel_size, rel_entsize, endian, sh_type == 9);
            }
        }
    }

    try parseElfSymbols(&imports, &symbols, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, true, true);
    try parseElfSymbols(&imports, &symbols, bytes, strtab, symtab_off, symtab_size, symtab_entsize, endian, true, false);
    try parseElfPltRelocs(&imports, bytes, dynstr, dynsym_off, dynsym_size, dynsym_entsize, endian, true, relplt_off, relplt_size, relplt_entsize, relplt_is_rela, if (plt_sec_va != 0) plt_sec_va else plt_va, if (plt_sec_va != 0) plt_sec_entsize else plt_entsize, plt_sec_va == 0);
    try signatures.addScannedKnownImports(&imports, bytes);

    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);
    const relocs_count = relocations.items.len;

    return .{
        .format = .elf64, .arch = elfArch(machine), .entry_va = entry, .image_base = 0,
        .sections = owned_sections, .imports = try imports.toOwnedSlice(),
        .symbols = try symbols.toOwnedSlice(), .relocations = try relocations.toOwnedSlice(),
        .exports_count = 0, .relocations_count = relocs_count,
        .is_pie = is_pie, .has_import_table = true,
    };
}

fn parseElfDynamicImports(imports: *std.ArrayList(ImportSymbol), bytes: []const u8, dynstr: []const u8, dyn_off: usize, dyn_size: usize, endian: std.builtin.Endian, is64: bool) !usize {
    if (dynstr.len == 0 or dyn_off == 0) return 0;
    const entry_size: usize = if (is64) 16 else 8;
    var off = dyn_off;
    var count: usize = 0;
    while (off + entry_size <= dyn_off + dyn_size and off + entry_size <= bytes.len) : (off += entry_size) {
        const d_tag: u64 = if (is64) try utils.readInt(bytes, u64, off, endian) else try utils.readInt(bytes, u32, off, endian);
        const d_val: u64 = if (is64) try utils.readInt(bytes, u64, off + 8, endian) else try utils.readInt(bytes, u32, off + 4, endian);
        if (d_tag == 0) break;
        if (d_tag == 1) {
            const name = utils.cstrAt(dynstr, d_val);
            if (name.len > 0) {
                try appendImportUnique(imports, name, "", 0);
                count += 1;
            }
        }
    }
    return count;
}

fn parseElfRelocations(relocations: *std.ArrayList(Relocation), bytes: []const u8, rel_off: usize, rel_size: usize, rel_entsize: usize, endian: std.builtin.Endian, is_rela: bool) !void {
    if (rel_entsize == 0) return;
    var off = rel_off;
    const end = @min(bytes.len, rel_off + rel_size);
    while (off + rel_entsize <= end) : (off += rel_entsize) {
        const r_offset: u64 = if (rel_entsize >= 16) try utils.readInt(bytes, u64, off, endian) else try utils.readInt(bytes, u32, off, endian);
        const r_info: u64 = if (rel_entsize >= 16) try utils.readInt(bytes, u64, off + 8, endian) else try utils.readInt(bytes, u32, off + 4, endian);
        const sym_index = @as(u32, @intCast(r_info >> (if (rel_entsize >= 16) @as(u6, 32) else @as(u6, 8))));
        const type_index = @as(u32, @intCast(r_info & 0xff));
        const addend: i64 = if (is_rela and (off + if (rel_entsize >= 16) @as(usize, 8) else @as(usize, 8)) < end)
            if (rel_entsize >= 16) try utils.readInt(bytes, i64, off + 16, endian) else try utils.readInt(bytes, i32, off + 8, endian)
        else 0;
        try relocations.append(.{ .va = r_offset, .offset = r_offset, .type_index = type_index, .symbol_index = sym_index, .addend = addend, .is_relative = false });
    }
}

fn parsePe(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len < 0x40) return error.TruncatedPeHeader;
    const pe_off = try utils.checkedUsize(try utils.readInt(bytes, u32, 0x3c, .little));
    if (pe_off > bytes.len or bytes.len - pe_off < 24) return error.TruncatedPeHeader;
    if (!std.mem.eql(u8, bytes[pe_off .. pe_off + 4], "PE\x00\x00")) return error.InvalidPeSignature;
    const coff = pe_off + 4;
    const machine = try utils.readInt(bytes, u16, coff + 0, .little);
    const num_sections = try utils.readInt(bytes, u16, coff + 2, .little);
    const opt_size = try utils.readInt(bytes, u16, coff + 16, .little);
    _ = try utils.readInt(bytes, u16, coff + 18, .little);
    const timestamp = try utils.readInt(bytes, u32, coff + 8, .little);
    const optional = coff + 20;
    if (optional > bytes.len or bytes.len - optional < opt_size) return error.TruncatedPeOptionalHeader;
    const opt_magic = try utils.readInt(bytes, u16, optional, .little);
    const format: FileFormat = switch (opt_magic) {
        0x10b => .pe32,
        0x20b => .pe64,
        else => return error.UnsupportedPeOptionalHeader,
    };
    const entry_rva = try utils.readInt(bytes, u32, optional + 16, .little);
    const image_base: u64 = switch (format) {
        .pe32 => try utils.readInt(bytes, u32, optional + 28, .little),
        .pe64 => try utils.readInt(bytes, u64, optional + 24, .little),
        else => unreachable,
    };
    const major_linker = try utils.readInt(bytes, u8, optional + (if (format == .pe64) @as(usize, 42) else @as(usize, 38)), .little);
    const minor_linker = try utils.readInt(bytes, u8, optional + (if (format == .pe64) @as(usize, 43) else @as(usize, 39)), .little);
    _ = try utils.readInt(bytes, u32, optional + (if (format == .pe64) @as(usize, 4) else @as(usize, 4)), .little);
    _ = try utils.readInt(bytes, u32, optional + (if (format == .pe64) @as(usize, 8) else @as(usize, 8)), .little);
    _ = try utils.readInt(bytes, u32, optional + (if (format == .pe64) @as(usize, 12) else @as(usize, 12)), .little);
    const dll_characteristics = try utils.readInt(bytes, u16, optional + (if (format == .pe64) @as(usize, 70) else @as(usize, 64)), .little);
    const stack_reserve: u64 = if (format == .pe64) try utils.readInt(bytes, u64, optional + 48, .little) else try utils.readInt(bytes, u32, optional + 44, .little);
    const stack_commit: u64 = if (format == .pe64) try utils.readInt(bytes, u64, optional + 56, .little) else try utils.readInt(bytes, u32, optional + 48, .little);
    const heap_reserve: u64 = if (format == .pe64) try utils.readInt(bytes, u64, optional + 64, .little) else try utils.readInt(bytes, u32, optional + 52, .little);
    const heap_commit: u64 = if (format == .pe64) try utils.readInt(bytes, u64, optional + 72, .little) else try utils.readInt(bytes, u32, optional + 56, .little);

    const data_dir = optional + if (format == .pe64) @as(usize, 112) else @as(usize, 96);
    const export_rva = if (data_dir + 8 <= optional + opt_size and data_dir + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir, .little) else 0;
    _ = if (data_dir + 8 <= optional + opt_size and data_dir + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 4, .little) else 0;
    const import_rva = if (data_dir + 16 <= optional + opt_size and data_dir + 16 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 8, .little) else 0;
    _ = if (data_dir + 16 <= optional + opt_size and data_dir + 16 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 12, .little) else 0;
    const base_reloc_rva = if (data_dir + 5 * 8 + 8 <= optional + opt_size and data_dir + 5 * 8 + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 5 * 8, .little) else 0;
    const debug_rva = if (data_dir + 6 * 8 + 8 <= optional + opt_size and data_dir + 6 * 8 + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 6 * 8, .little) else 0;
    const tls_rva = if (data_dir + 9 * 8 + 8 <= optional + opt_size and data_dir + 9 * 8 + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 9 * 8, .little) else 0;
    const exception_rva = if (data_dir + 3 * 8 + 8 <= optional + opt_size and data_dir + 3 * 8 + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 3 * 8, .little) else 0;
    const security_rva = if (data_dir + 4 * 8 + 8 <= optional + opt_size and data_dir + 4 * 8 + 8 <= bytes.len) try utils.readInt(bytes, u32, data_dir + 4 * 8, .little) else 0;

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    const sectab = optional + opt_size;
    for (0..num_sections) |idx| {
        const off = sectab + idx * 40;
        if (off > bytes.len or bytes.len - off < 40) break;
        const raw_name = bytes[off .. off + 8];
        const name_len = std.mem.indexOfScalar(u8, raw_name, 0) orelse raw_name.len;
        const name = raw_name[0..name_len];
        const vsize = try utils.readInt(bytes, u32, off + 8, .little);
        const vaddr = try utils.readInt(bytes, u32, off + 12, .little);
        const rsize = try utils.readInt(bytes, u32, off + 16, .little);
        const roff = try utils.readInt(bytes, u32, off + 20, .little);
        const chars = try utils.readInt(bytes, u32, off + 36, .little);
        const exec = (chars & 0x20000000) != 0 or (chars & 0x00000020) != 0;
        const writable = (chars & 0x80000000) != 0;
        const contains_code = (chars & 0x00000020) != 0;
        try appendSection(&sections, bytes.len, name, image_base + vaddr, roff, rsize, if (vsize == 0) rsize else vsize, exec, writable, contains_code, 0);
    }
    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);

    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var relocations = std.ArrayList(Relocation).init(allocator);
    errdefer relocations.deinit();

    try parsePeImports(&imports, bytes, owned_sections, image_base, import_rva, format);
    try signatures.addScannedKnownImports(&imports, bytes);

    if (base_reloc_rva > 0) {
        try parsePeBaseRelocs(&relocations, bytes, owned_sections, image_base, base_reloc_rva, format);
    }

    const has_rich_header = detectRichHeader(bytes, pe_off);

    const empty_symbols = try allocator.alloc(Symbol, 0);
    const relocs_count = relocations.items.len;

    return .{
        .format = format,
        .arch = peArch(machine),
        .entry_va = image_base + entry_rva,
        .image_base = image_base,
        .sections = owned_sections,
        .imports = try imports.toOwnedSlice(),
        .symbols = empty_symbols,
        .relocations = try relocations.toOwnedSlice(),
        .exports_count = if (export_rva == 0) 0 else 1,
        .relocations_count = relocs_count,
        .subsystem = 0,
        .major_linker_version = major_linker,
        .minor_linker_version = minor_linker,
        .is_pie = false,
        .is_signed = security_rva > 0,
        .has_tls = tls_rva > 0,
        .has_import_table = import_rva > 0,
        .has_export_table = export_rva > 0,
        .has_exception_table = exception_rva > 0,
        .has_debug_table = debug_rva > 0,
        .has_rich_header = has_rich_header,
        .compile_timestamp = timestamp,
        .stack_reserve_size = stack_reserve,
        .stack_commit_size = stack_commit,
        .heap_reserve_size = heap_reserve,
        .heap_commit_size = heap_commit,
        .dll_characteristics = dll_characteristics,
    };
}

fn detectRichHeader(bytes: []const u8, pe_offset: usize) bool {
    if (pe_offset < 128) return false;
    var i: usize = 0x80;
    const search_end = @min(bytes.len, pe_offset);
    while (i < search_end - 4) {
        if (std.mem.eql(u8, bytes[i..][0..4], "Rich")) {
            if (i >= 4 and bytes[i - 1] == 0x53 and bytes[i - 2] == 0x57 and bytes[i - 3] == 0x0D) return true;
        }
        i += 1;
    }
    return false;
}

fn parsePeBaseRelocs(relocations: *std.ArrayList(Relocation), bytes: []const u8, sections: []const Section, image_base: u64, reloc_rva: u32, _: FileFormat) !void {
    const block_start = rvaToOffset(sections, reloc_rva, image_base) orelse return;
    var off = block_start;
    while (off + 8 <= bytes.len) {
        const page_rva = try utils.readInt(bytes, u32, off, .little);
        const block_size = try utils.readInt(bytes, u32, off + 4, .little);
        if (page_rva == 0 and block_size == 0) break;
        if (block_size < 8) break;
        const entry_count = (block_size - 8) / 2;
        var entry_idx: usize = 0;
        while (entry_idx < entry_count and off + 8 + (entry_idx + 1) * 2 <= bytes.len) : (entry_idx += 1) {
            const entry = try utils.readInt(bytes, u16, off + 8 + entry_idx * 2, .little);
            const reloc_type = (entry >> 12) & 0x0f;
            const reloc_offset = page_rva + (entry & 0x0fff);
            try relocations.append(.{
                .va = image_base + reloc_offset,
                .offset = reloc_offset,
                .type_index = reloc_type,
                .symbol_index = 0,
                .addend = 0,
                .is_relative = reloc_type == 3,
            });
        }
        off += block_size;
    }
}

fn parseMachO(allocator: Allocator, bytes: []const u8, endian: std.builtin.Endian) !BinaryImage {
    if (bytes.len < 28) return error.TruncatedMachOHeader;
    const cputype = try utils.readInt(bytes, u32, 4, endian);
    _ = try utils.readInt(bytes, u32, 8, endian);
    _ = try utils.readInt(bytes, u32, 12, endian);
    const ncmds = try utils.readInt(bytes, u32, 16, endian);
    _ = try utils.readInt(bytes, u32, 20, endian);
    const is64 = (bytes[4] == 1);

    var sections = std.ArrayList(Section).init(allocator);
    errdefer sections.deinit();
    var imports = std.ArrayList(ImportSymbol).init(allocator);
    errdefer imports.deinit();
    var symbols = std.ArrayList(Symbol).init(allocator);
    errdefer symbols.deinit();
    var entry_va: u64 = 0;
    var image_base: u64 = 0;
    var cmd_off: usize = if (is64) @as(usize, 32) else @as(usize, 28);

    for (0..ncmds) |_| {
        if (cmd_off + 8 > bytes.len) break;
        const cmd_type = try utils.readInt(bytes, u32, cmd_off, endian);
        const cmd_size = try utils.readInt(bytes, u32, cmd_off + 4, endian);
        if (cmd_size < 8 or cmd_off + cmd_size > bytes.len) break;

        if (cmd_type == 0x19 or cmd_type == 0x01) {
            const segname_start = cmd_off + 8;
            const segname_end = segname_start + 16;
            const segname = bytes[segname_start..@min(segname_end, bytes.len)];
            const name_end = std.mem.indexOfScalar(u8, segname, 0) orelse segname.len;
            const vmaddr: u64 = if (is64) try utils.readInt(bytes, u64, cmd_off + 24, endian) else try utils.readInt(bytes, u32, cmd_off + 24, endian);
            _ = if (is64) try utils.readInt(bytes, u64, cmd_off + 32, endian) else try utils.readInt(bytes, u32, cmd_off + 28, endian);
            _ = if (is64) try utils.readInt(bytes, u64, cmd_off + 40, endian) else try utils.readInt(bytes, u32, cmd_off + 32, endian);
            _ = if (is64) try utils.readInt(bytes, u64, cmd_off + 48, endian) else try utils.readInt(bytes, u32, cmd_off + 36, endian);
            const nsects: u32 = if (is64) try utils.readInt(bytes, u32, cmd_off + 56, endian) else try utils.readInt(bytes, u32, cmd_off + 40, endian);
            const maxprot: u32 = if (is64) try utils.readInt(bytes, u32, cmd_off + 60, endian) else try utils.readInt(bytes, u32, cmd_off + 44, endian);

            if (segname[0..name_end].len > 0 and std.mem.eql(u8, segname[0..name_end], "__TEXT")) image_base = vmaddr;

            const sect_entry_size: usize = if (is64) 80 else 68;
            var sect_off = cmd_off + (if (is64) @as(usize, 72) else @as(usize, 56));
            for (0..nsects) |_| {
                if (sect_off + sect_entry_size > bytes.len) break;
                const sname_raw = bytes[sect_off..sect_off + 16];
                const sname_end = std.mem.indexOfScalar(u8, sname_raw, 0) orelse sname_raw.len;
                const sname = sname_raw[0..sname_end];
                const saddr: u64 = if (is64) try utils.readInt(bytes, u64, sect_off + (if (is64) @as(usize, 40) else @as(usize, 32)), endian) else try utils.readInt(bytes, u32, sect_off + 32, endian);
                const ssize: u64 = if (is64) try utils.readInt(bytes, u64, sect_off + (if (is64) @as(usize, 48) else @as(usize, 36)), endian) else try utils.readInt(bytes, u32, sect_off + 36, endian);
                const soff: u32 = if (is64) try utils.readInt(bytes, u32, sect_off + (if (is64) @as(usize, 56) else @as(usize, 40)), endian) else try utils.readInt(bytes, u32, sect_off + 40, endian);
                const sflags = if (is64) try utils.readInt(bytes, u32, sect_off + 72, endian) else try utils.readInt(bytes, u32, sect_off + 60, endian);
                const exec = (maxprot & 0x4) != 0 or (sflags & 0x80000000) != 0;
                const contains_code = (sflags & 0x80000000) != 0 or exec;
                if (soff > 0 and ssize > 0 and soff < bytes.len) {
                    try sections.append(.{
                        .name = sname, .va = saddr, .file_offset = @intCast(soff),
                        .size = @intCast(@min(ssize, bytes.len - soff)),
                        .virtual_size = ssize, .executable = exec,
                        .writable = (maxprot & 0x2) != 0,
                        .contains_code = contains_code, .alignment = 0,
                    });
                }
                sect_off += sect_entry_size;
            }
        }

        if (cmd_type == 0x0d or cmd_type == 0x0c) {
            const is_thread_64 = cmd_type == 0x0d;
            _ = try utils.readInt(bytes, u32, cmd_off + 8, endian);
            const count = try utils.readInt(bytes, u32, cmd_off + 12, endian);
            if (is_thread_64 and cputype == 0x01000007 and count >= 2) {
                entry_va = image_base + try utils.readInt(bytes, u64, cmd_off + 16, endian);
            } else if (count >= 2) {
                entry_va = image_base + try utils.readInt(bytes, u32, cmd_off + 16, endian);
            }
        }

        if (cmd_type == 0x02 or cmd_type == 0x0e) {
            const symoff = try utils.readInt(bytes, u32, cmd_off + 8, endian);
            const nsyms = try utils.readInt(bytes, u32, cmd_off + 12, endian);
            const stroff = try utils.readInt(bytes, u32, cmd_off + 16, endian);
            const strsize = try utils.readInt(bytes, u32, cmd_off + 20, endian);

            if (symoff > 0 and stroff > 0 and strsize > 0) {
                const str_end = @min(bytes.len, stroff + strsize);
                if (stroff < str_end) {
                    const strtab = bytes[stroff..str_end];
                    const sym_size: usize = 16;
                    for (0..nsyms) |sym_idx| {
                        const sym_off = symoff + sym_idx * sym_size;
                        if (sym_off + sym_size > bytes.len) break;
                        const n_strx = try utils.readInt(bytes, u32, sym_off, endian);
                        const n_type = bytes[sym_off + 4];
                        const n_sect = bytes[sym_off + 5];
                        _ = try utils.readInt(bytes, u16, sym_off + 6, endian);
                        const n_value = if (is64) try utils.readInt(bytes, u64, sym_off + 8, endian) else try utils.readInt(bytes, u32, sym_off + 8, endian);
                        if (n_strx == 0 or n_strx >= strtab.len) continue;
                        const sym_name = utils.cstrAt(strtab, n_strx);
                        if (sym_name.len == 0) continue;
                        const is_ext = (n_type & 0x01) != 0;
                        const is_func = (n_type & 0x0e) == 0x0e;
                        if (is_ext and n_value > 0) {
                            try appendSymbolUnique(&symbols, sym_name, n_value, 0, is_func, true, 0, 0, n_sect);
                        } else if (n_value > 0) {
                            try appendSymbolUnique(&symbols, sym_name, n_value, 0, is_func, false, 0, 0, n_sect);
                        }
                        if (is_ext and n_value == 0 and is_func) {
                            try appendImportUnique(&imports, sym_name, "", 0);
                        }
                    }
                }
            }
        }

        if (cmd_type == 0x1c or cmd_type == 0x0b) {
            const bind_off = try utils.readInt(bytes, u32, cmd_off + 8, endian);
            const bind_size = try utils.readInt(bytes, u32, cmd_off + 12, endian);
            if (bind_off > 0 and bind_size > 0) {
                const end = @min(bytes.len, bind_off + bind_size);
                var bind_pos = bind_off;
                while (bind_pos < end) {
                    const opcode = bytes[bind_pos];
                    const imm = opcode & 0x0f;
                    _ = imm;
                    if (opcode == 0x00) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x01) {
                        if (bind_pos + 2 > end) break;
                        bind_pos += 2;
                        continue;
                    }
                    if ((opcode >> 4) == 0x02) {
                        _ = bytes[bind_pos + 1];
                        bind_pos += 2;
                        continue;
                    }
                    if ((opcode >> 4) == 0x03) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x04) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x05) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x06) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x07) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x08) { bind_pos += 1; continue; }
                    if ((opcode >> 4) == 0x09) {
                        if (bind_pos + 2 > end) break;
                        const seg = bytes[bind_pos + 1];
                        const seg_name = if (seg == 1) "__LINKEDIT" else "__DATA";
                        _ = seg_name;
                        bind_pos += 2;
                        continue;
                    }
                    if ((opcode >> 4) == 0x10) {
                        if (bind_pos + 3 > end) break;
                        const lib_ord = try utils.readInt(bytes, u16, bind_pos + 1, endian);
                        _ = lib_ord;
                        bind_pos += 3;
                        continue;
                    }
                    if ((opcode >> 4) == 0x11) {
                        if (bind_pos + 2 > end) break;
                        const str_len = bytes[bind_pos + 1];
                        if (bind_pos + 2 + str_len > end) break;
                        const imp_name = bytes[bind_pos + 2 .. bind_pos + 2 + str_len];
                        try appendImportUnique(&imports, imp_name, "", 0);
                        bind_pos += 2 + str_len;
                        continue;
                    }
                    if ((opcode >> 4) == 0x12) {
                        if (bind_pos + 3 > end) break;
                        const lib_ord = try utils.readInt(bytes, u16, bind_pos + 1, endian);
                        _ = lib_ord;
                        bind_pos += 3;
                        continue;
                    }
                    if ((opcode >> 4) == 0x13) {
                        if (bind_pos + 2 > end) break;
                        const str_len = bytes[bind_pos + 1];
                        if (bind_pos + 2 + str_len > end) break;
                        bind_pos += 2 + str_len;
                        continue;
                    }
                    if (opcode == 0x00) break;
                    bind_pos += 1;
                }
            }
        }

        cmd_off += cmd_size;
    }

    const arch: Arch = switch (cputype) {
        0x01000007, 7 => .x86_64,
        0x0100000c, 12 => .arm64,
        0x0100000a, 10 => .arm,
        0x01000006, 6 => .x86,
        else => .unknown,
    };
    const format: FileFormat = if (is64) .macho64 else .macho32;

    const owned_sections = try sections.toOwnedSlice();
    std.mem.sort(Section, owned_sections, {}, sectionLess);

    return .{
        .format = format, .arch = arch, .entry_va = entry_va, .image_base = image_base,
        .sections = owned_sections, .imports = try imports.toOwnedSlice(),
        .symbols = try symbols.toOwnedSlice(), .relocations = try allocator.alloc(Relocation, 0),
    };
}

fn parseMachOFat(allocator: Allocator, bytes: []const u8) !BinaryImage {
    if (bytes.len < 12) return error.TruncatedMachOFatHeader;
    const narchs = try utils.readInt(bytes, u32, 4, .big);
    if (narchs == 0 or narchs > 16) return error.UnsupportedMachOFatArchCount;
    const arch_offset: usize = 8;
    for (0..narchs) |i| {
        const entry_off = arch_offset + i * 20;
        if (entry_off + 20 > bytes.len) break;
        _ = try utils.readInt(bytes, u32, entry_off, .big);
        _ = try utils.readInt(bytes, u32, entry_off + 4, .big);
        const offset = try utils.readInt(bytes, u32, entry_off + 8, .big);
        const size = try utils.readInt(bytes, u32, entry_off + 12, .big);
        if (offset >= bytes.len or offset + size > bytes.len) continue;

        const slice = bytes[offset .. offset + size];
        if (slice.len < 4) continue;
        const endian: std.builtin.Endian = if (slice[0] == 0xFE or slice[0] == 0xCE) .big else .little;
        const result = parseMachO(allocator, slice, endian) catch continue;
        return result;
    }
    return error.UnsupportedMachOFatArchitecture;
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
        const name_off = try utils.readInt(bytes, u32, off + 0, endian);
        const info = if (is64) bytes[off + 4] else bytes[off + 12];
        const other = if (is64) bytes[off + 5] else bytes[off + 13];
        const shndx = if (is64) try utils.readInt(bytes, u16, off + 6, endian) else try utils.readInt(bytes, u16, off + 14, endian);
        const value: u64 = if (is64) try utils.readInt(bytes, u64, off + 8, endian) else try utils.readInt(bytes, u32, off + 4, endian);
        const size: u64 = if (is64) try utils.readInt(bytes, u64, off + 16, endian) else try utils.readInt(bytes, u32, off + 8, endian);
        if (name_off == 0) continue;
        const name = utils.cstrAt(strtab, name_off);
        if (name.len == 0) continue;
        const typ = info & 0x0f;
        const bind = info >> 4;
        const vis = other & 0x03;
        if (shndx == 0) {
            if (dynamic_table) try appendImportUnique(imports, name, "", value);
            try appendSymbolUnique(symbols, name, value, size, typ == 2, true, bind, vis, shndx);
        } else {
            try appendSymbolUnique(symbols, name, value, size, typ == 2, false, bind, vis, shndx);
        }
    }
}

fn appendImportUnique(imports: *std.ArrayList(ImportSymbol), name: []const u8, dll: []const u8, iat_va: u64) !void {
    for (imports.items) |existing| {
        if (utils.asciiEqlIgnoreCase(existing.name, name)) return;
    }
    try imports.append(.{ .name = name, .dll = dll, .iat_va = iat_va });
}

fn appendSymbolUnique(symbols: *std.ArrayList(Symbol), name: []const u8, va: u64, size: u64, is_function: bool, external: bool, binding: u8, visibility: u8, section_index: u16) !void {
    if (name.len == 0) return;
    for (symbols.items) |existing| {
        if (existing.va == va and utils.asciiEqlIgnoreCase(existing.name, name)) return;
    }
    try symbols.append(.{ .name = name, .va = va, .size = size, .is_function = is_function, .external = external, .binding = binding, .visibility = visibility, .section_index = section_index });
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
    const max_sym = if (dynsym_entsize > 0) dynsym_size / dynsym_entsize else 0;
    const end = @min(bytes.len, relplt_off + @min(relplt_size, bytes.len - relplt_off));
    var off = relplt_off;
    var idx: usize = 0;
    while (off + relplt_entsize <= end and idx < 4096) : ({
        off += relplt_entsize;
        idx += 1;
    }) {
        const got_va: u64 = if (is64) try utils.readInt(bytes, u64, off + 0, endian) else try utils.readInt(bytes, u32, off + 0, endian);
        const sym_index: usize = if (is64) blk: {
            const r_info = try utils.readInt(bytes, u64, off + 8, endian);
            break :blk @intCast(r_info >> 32);
        } else blk: {
            const r_info = try utils.readInt(bytes, u32, off + 4, endian);
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
    const name_off = utils.readInt(bytes, u32, sym_off, endian) catch return "";
    return utils.cstrAt(dynstr, name_off);
}

fn updateImportBinding(imports: *std.ArrayList(ImportSymbol), name: []const u8, got_va: u64, plt_va: u64) !void {
    for (imports.items) |*existing| {
        if (utils.asciiEqlIgnoreCase(existing.name, name)) {
            if (existing.got_va == 0) existing.got_va = got_va;
            if (existing.plt_va == 0) existing.plt_va = plt_va;
            return;
        }
    }
    try imports.append(.{ .name = name, .got_va = got_va, .plt_va = plt_va });
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
        const original_first_thunk = try utils.readInt(bytes, u32, descriptor_off + 0, .little);
        const name_rva = try utils.readInt(bytes, u32, descriptor_off + 12, .little);
        const first_thunk = try utils.readInt(bytes, u32, descriptor_off + 16, .little);
        if (original_first_thunk == 0 and name_rva == 0 and first_thunk == 0) break;

        const dll = if (rvaToOffset(sections, name_rva, image_base)) |name_off| utils.readCString(bytes, name_off) else "unknown";
        const thunk_rva = if (original_first_thunk != 0) original_first_thunk else first_thunk;
        const thunk_off_start = rvaToOffset(sections, thunk_rva, image_base) orelse continue;
        const thunk_size: usize = if (format == .pe64) 8 else 4;
        var thunk_off = thunk_off_start;
        var thunk_index: u64 = 0;
        while (thunk_off <= bytes.len and bytes.len - thunk_off >= thunk_size and thunk_index < 4096) : ({
            thunk_off += thunk_size;
            thunk_index += 1;
        }) {
            const raw_entry: u64 = if (format == .pe64) try utils.readInt(bytes, u64, thunk_off, .little) else try utils.readInt(bytes, u32, thunk_off, .little);
            if (raw_entry == 0) break;
            const ordinal_mask: u64 = if (format == .pe64) 0x8000000000000000 else 0x80000000;
            if ((raw_entry & ordinal_mask) != 0) {
                const ordinal = raw_entry & 0xffff;
                try imports.append(.{ .name = try std.fmt.allocPrint(imports.allocator, "ORDINAL_{}", .{ordinal}), .dll = dll, .ordinal = @intCast(ordinal) });
                continue;
            }
            const name_rva_entry: u32 = @intCast(raw_entry & 0x7fffffff);
            const name_off = rvaToOffset(sections, name_rva_entry, image_base) orelse continue;
            if (name_off + 2 >= bytes.len) continue;
            const hint = try utils.readInt(bytes, u16, name_off, .little);
            const name = utils.readCString(bytes, name_off + 2);
            if (name.len == 0) continue;
            try appendImportUnique(imports, name, dll, image_base + @as(u64, first_thunk) + thunk_index * @as(u64, @intCast(thunk_size)));
            if (imports.items.len > 0) imports.items[imports.items.len - 1].hint = hint;
        }
    }
}

pub fn sectionBytes(bytes: []const u8, section: Section) []const u8 {
    if (section.file_offset >= bytes.len) return "";
    const end = @min(bytes.len, section.file_offset + @min(section.size, bytes.len - section.file_offset));
    return bytes[section.file_offset..end];
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
    writable: bool,
    contains_code: bool,
    alignment: anytype,
) !void {
    const off = utils.checkedUsize(file_offset) catch return;
    if (off >= bytes_len) return;
    const raw_size = utils.checkedUsize(size) catch return;
    const clamped_size = @min(raw_size, bytes_len - off);
    if (clamped_size == 0) return;
    try sections.append(.{
        .name = name,
        .va = @intCast(va),
        .file_offset = off,
        .size = clamped_size,
        .virtual_size = @intCast(virtual_size),
        .executable = executable,
        .writable = writable,
        .contains_code = contains_code,
        .alignment = @intCast(alignment),
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
    const hdr = utils.checkedUsize(shoff + @as(u64, shstrndx) * @as(u64, shentsize)) catch return "";
    if (hdr > bytes.len or bytes.len - hdr < shentsize) return "";
    const off64: u64 = if (is64) utils.readInt(bytes, u64, hdr + 24, endian) catch return "" else utils.readInt(bytes, u32, hdr + 16, endian) catch return "";
    const size64: u64 = if (is64) utils.readInt(bytes, u64, hdr + 32, endian) catch return "" else utils.readInt(bytes, u32, hdr + 20, endian) catch return "";
    const off = utils.checkedUsize(off64) catch return "";
    const size = utils.checkedUsize(size64) catch return "";
    if (off > bytes.len or bytes.len - off < size) return "";
    return bytes[off .. off + size];
}

fn elfArch(machine: u16) Arch {
    return switch (machine) {
        3 => .x86,
        62 => .x86_64,
        40 => .arm,
        183 => .arm64,
        243 => .riscv64,
        8 => .mips,
        20 => .powerpc,
        0xF7 => .wasm,
        else => .unknown,
    };
}

fn peArch(machine: u16) Arch {
    return switch (machine) {
        0x014c => .x86,
        0x8664 => .x86_64,
        0xaa64 => .arm64,
        0x01c0 => .arm,
        0x5032 => .riscv64,
        0x01f0 => .powerpc,
        else => .unknown,
    };
}

fn sectionLess(_: void, a: Section, b: Section) bool {
    if (a.va == b.va) return a.file_offset < b.file_offset;
    return a.va < b.va;
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

pub fn countExecSections(image: BinaryImage) usize {
    var count: usize = 0;
    for (image.sections) |section| {
        if (section.executable) count += 1;
    }
    return count;
}

pub fn extractVersionInfo(bytes: []const u8, image: BinaryImage) ?VersionInfo {
    for (image.sections) |section| {
        if (std.mem.indexOf(u8, section.name, ".rsrc") != null or
            std.mem.indexOf(u8, section.name, ".rdata") != null) {
            const data = sectionBytes(bytes, section);
            const vs_pos = std.mem.indexOf(u8, data, "VS_VERSION_INFO");
            if (vs_pos) |pos| {
                if (pos + 60 < data.len) {
                    const ver_info = data[pos..@min(pos + 60, data.len)];
                    if (ver_info.len >= 56) {
                        const major = utils.readInt(ver_info, u16, 44, .little) catch 0;
                        const minor = utils.readInt(ver_info, u16, 46, .little) catch 0;
                        const patch = utils.readInt(ver_info, u16, 48, .little) catch 0;
                        const build = utils.readInt(ver_info, u16, 50, .little) catch 0;
                        return VersionInfo{ .major = major, .minor = minor, .patch = patch, .build = build };
                    }
                }
                return VersionInfo{ .major = 0, .minor = 0, .patch = 0, .build = 0 };
            }
        }
    }
    return null;
}

pub fn findDebugInfo(bytes: []const u8, image: BinaryImage) ?DebugInfo {
    for (image.sections) |section| {
        if (std.mem.indexOf(u8, section.name, ".debug") != null or
            std.mem.indexOf(u8, section.name, "debug") != null) {
            const data = sectionBytes(bytes, section);
            if (data.len >= 4) {
                const sig = utils.readInt(data, u32, 0, .little) catch 0;
                const debug_type: DebugType = switch (sig) {
                    0x53445352 => .codeview,
                    0x00000001 => .coff,
                    0x00000002 => .fpo,
                    0x00000003 => .exception,
                    0x00000004 => .fixup,
                    0x00000005 => .omap_to_src,
                    0x00000006 => .omap_from_src,
                    0x00000007 => .borland,
                    0x00000008 => .reserved10,
                    0x00000009 => .clsid,
                    else => .codeview,
                };
                const guid_start = 4;
                const guid = if (guid_start + 16 <= data.len)
                    data[guid_start..guid_start + 16].*
                else
                    [_]u8{0} ** 16;
                const age = if (guid_start + 16 + 4 <= data.len)
                    utils.readInt(data, u32, guid_start + 16, .little) catch 0
                else
                    0;
                const path_start = guid_start + 16 + 4;
                const path = if (path_start < data.len)
                    std.mem.sliceTo(data[path_start..], 0)
                else
                    "";
                return DebugInfo{ .debug_type = debug_type, .timestamp = 0, .age = age, .guid = guid, .path = path, .codeview_signature = sig };
            }
        }
    }
    return null;
}
