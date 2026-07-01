const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const decoder = @import("../core/decoder.zig");

const Allocator = types.Allocator;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const FunctionSpan = types.FunctionSpan;
const InstrKind = types.InstrKind;
const ResolvedCall = types.ResolvedCall;

pub const CipherAlgorithm = enum {
    aes_ecb,
    aes_cbc,
    aes_gcm,
    aes_ctr,
    aes_xts,
    des,
    triple_des,
    rc4,
    rc2,
    blowfish,
    twofish,
    serpent,
    chacha20,
    salsa20,
    poly1305,
    unknown,
};

pub const KeyType = enum {
    symmetric_aes_128,
    symmetric_aes_192,
    symmetric_aes_256,
    symmetric_des,
    symmetric_3des,
    symmetric_rc4,
    rsa_1024,
    rsa_2048,
    rsa_4096,
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,
    hmac_sha256,
    unknown,
};

pub const KeyStrength = enum {
    weak,
    acceptable,
    strong,
    very_strong,
    unknown,
};

pub const CryptoIssue = enum {
    weak_cipher,
    hardcoded_key,
    static_iv,
    weak_key_length,
    deprecated_algorithm,
    missing_key_rotation,
    key_in_plaintext,
    ecb_mode,
    no_authentication,
    padding_oracle_vulnerable,
    certificate_validation_disabled,
    weak_randomness,
    reuse_nonce,
    truncated_mac,
    missing_key_derivation,
    improper_key_storage,
};

pub const CipherUsage = struct {
    address: u64,
    function_va: u64,
    algorithm: CipherAlgorithm,
    key_type: KeyType,
    key_source: KeySource,
    mode: CipherMode,
    has_auth_tag: bool,
    has_iv: bool,
    iv_is_static: bool,
    key_is_hardcoded: bool,
    severity: u8,
};

pub const KeySource = enum {
    hardcoded,
    derived_from_password,
    derived_from_other_key,
    obtained_from_hsm,
    obtained_from_keychain,
    obtained_from_network,
    obtained_from_file,
    user_input,
    unknown,
};

pub const CipherMode = enum {
    ecb,
    cbc,
    ctr,
    gcm,
    ccm,
    xts,
    ofb,
    cfb,
    poly1305_aead,
    unknown,
};

pub const CryptoFinding = struct {
    address: u64,
    function_va: u64,
    issue: CryptoIssue,
    severity: u8,
    cipher: CipherAlgorithm,
    description: []const u8 = "",
    recommendation: []const u8 = "",
};

pub const KeyMaterial = struct {
    address: u64,
    function_va: u64,
    key_type: KeyType,
    key_source: KeySource,
    strength: KeyStrength,
    location: KeyLocation,
    is_exposed: bool,
    rotation_period_days: ?u32 = null,
};

pub const KeyLocation = enum {
    code_section,
    data_section,
    rdata_section,
    stack_local,
    heap_allocated,
    register_temporary,
    external_hsm,
    file_on_disk,
    environment_variable,
    unknown,
};

pub const RandomnessSource = enum {
    bcrypt_gen_random,
    crypt_gen_random,
    openssl_rand_bytes,
    getrandom,
    arc4random,
    rand_c_stdlib,
    time_seeded,
    unknown,
};

pub const CryptoAudit = struct {
    cipher_usages: []CipherUsage,
    findings: []CryptoFinding,
    key_materials: []KeyMaterial,
    randomness_sources: []RandomnessSource,
    weak_cipher_count: usize,
    hardcoded_key_count: usize,
    deprecated_count: usize,
    total_crypto_operations: usize,
    crypto_gap_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.cipher_usages);
        allocator.free(self.findings);
        allocator.free(self.key_materials);
        allocator.free(self.randomness_sources);
    }
};

const weak_ciphers = [_][]const u8{ "DES", "RC4", "RC2", "MD4", "MD5", "SHA1", "blowfish", "idea", "cast5" };
const deprecated_algorithms = [_][]const u8{ "EVP_des", "EVP_rc4", "EVP_md5", "EVP_sha1", "EVP_bf" };
const strong_random_sources = [_][]const u8{ "BCryptGenRandom", "CryptGenRandom", "getrandom", "getentropy", "arc4random_buf", "RAND_bytes", "OpenSSL_random" };

fn classifyCipher(name: []const u8) ?CipherAlgorithm {
    if (utils.containsAny(name, &.{ "AES_128_ECB", "aes_128_ecb", "AES-128-ECB", "AES-256-ECB", "aes_256_ecb" })) return .aes_ecb;
    if (utils.containsAny(name, &.{ "AES_128_CBC", "aes_128_cbc", "AES-128-CBC", "AES-256-CBC", "aes_256_cbc" })) return .aes_cbc;
    if (utils.containsAny(name, &.{ "AES_128_GCM", "aes_128_gcm", "AES-128-GCM", "AES-256-GCM", "aes_256_gcm" })) return .aes_gcm;
    if (utils.containsAny(name, &.{ "AES_128_CTR", "aes_128_ctr", "AES-128-CTR", "AES-256-CTR" })) return .aes_ctr;
    if (utils.containsAny(name, &.{ "AES_128_XTS", "aes_128_xts", "AES-256-XTS" })) return .aes_xts;
    if (utils.containsAny(name, &.{ "EVP_aes_128_ecb", "EVP_aes_256_ecb" })) return .aes_ecb;
    if (utils.containsAny(name, &.{ "EVP_aes_128_cbc", "EVP_aes_256_cbc" })) return .aes_cbc;
    if (utils.containsAny(name, &.{ "EVP_aes_128_gcm", "EVP_aes_256_gcm" })) return .aes_gcm;
    if (utils.containsAny(name, &.{ "EVP_aes_128_ctr", "EVP_aes_256_ctr" })) return .aes_ctr;
    if (utils.containsAny(name, &.{ "DES", "EVP_des" })) return .des;
    if (utils.containsAny(name, &.{ "DES_ede3", "3DES", "EVP_des_ede3" })) return .triple_des;
    if (utils.containsAny(name, &.{ "RC4", "EVP_rc4" })) return .rc4;
    if (utils.containsAny(name, &.{ "ChaCha20", "chacha20", "ChaCha" })) return .chacha20;
    if (utils.containsAny(name, &.{ "Poly1305", "poly1305" })) return .poly1305;
    if (utils.containsAny(name, &.{ "Blowfish", "EVP_bf" })) return .blowfish;
    if (utils.containsAny(name, &.{ "Salsa20", "salsa20" })) return .salsa20;
    if (utils.containsAny(name, &.{ "Twofish", "twofish" })) return .twofish;
    if (utils.containsAny(name, &.{ "Serpent", "serpent" })) return .serpent;
    return null;
}

fn isWeakAlgorithm(name: []const u8) bool {
    return utils.containsAny(name, &weak_ciphers);
}

fn isDeprecatedAlgorithm(name: []const u8) bool {
    return utils.containsAny(name, &deprecated_algorithms);
}

fn isStrongRandom(name: []const u8) bool {
    return utils.containsAny(name, &strong_random_sources);
}

fn isStaticIv(bytes: []const u8) bool {
    const patterns = [_][]const u8{
        "0000000000000000",
        "0123456789abcdef",
        "abcdefghijklmnop",
        "AAAAAAAAAAAAAAAA",
        "deadbeef",
        "1234567890abcdef",
        "0001020304050607",
        "0102030405060708",
    };
    for (patterns) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern) != null) return true;
    }
    return false;
}

fn isKeyInPlaintext(bytes: []const u8, key: []const u8) bool {
    return std.mem.indexOf(u8, bytes, key) != null;
}

pub fn auditCrypto(allocator: Allocator, bytes: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !CryptoAudit {
    var cipher_usages = std.ArrayList(CipherUsage).init(allocator);
    errdefer cipher_usages.deinit();
    var findings = std.ArrayList(CryptoFinding).init(allocator);
    errdefer findings.deinit();
    var key_materials = std.ArrayList(KeyMaterial).init(allocator);
    errdefer key_materials.deinit();
    var randomness_sources = std.ArrayList(RandomnessSource).init(allocator);
    errdefer randomness_sources.deinit();

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind != .call) continue;
            const resolved = decoder.resolveCallInfo(image, instr);
            const name = resolved.name;
            const has_crypto = utils.containsAny(name, &.{
                "Crypt", "BCrypt", "EVP_", "AES", "DES_", "RC4", "SHA",
                "encrypt", "decrypt", "cipher", "sign", "verify",
                "hash", "hmac", "pbkdf", "bcrypt", "scrypt",
            });

            if (!has_crypto) {
                if (utils.containsAny(name, &.{ "rand", "srand", "random", "Random", "RAND_" })) {
                    try randomness_sources.append(if (isStrongRandom(name)) RandomnessSource.openssl_rand_bytes else RandomnessSource.rand_c_stdlib);
                    if (!isStrongRandom(name)) {
                        try findings.append(.{
                            .address = instr.va,
                            .function_va = function.start,
                            .issue = .weak_randomness,
                            .severity = 70,
                            .cipher = .unknown,
                            .description = "Weak pseudo-random number generator used instead of cryptographically secure RNG",
                            .recommendation = "Replace with BCryptGenRandom, getrandom(2), or RAND_bytes",
                        });
                    }
                }
                continue;
            }

            const alg = classifyCipher(name) orelse .unknown;
            const is_weak = isWeakAlgorithm(name);
            const is_deprecated = isDeprecatedAlgorithm(name);
            const is_ecb = alg == .aes_ecb;
            const key_is_hardcoded = isKeyLikelyHardcoded(bytes, name);
            const iv_static = isStaticIv(bytes);

            try cipher_usages.append(.{
                .address = instr.va,
                .function_va = function.start,
                .algorithm = alg,
                .key_type = classifyKeyType(name),
                .key_source = if (key_is_hardcoded) .hardcoded else .unknown,
                .mode = classifyMode(alg),
                .has_auth_tag = alg == .aes_gcm or alg == .chacha20 or alg == .poly1305,
                .has_iv = true,
                .iv_is_static = iv_static,
                .key_is_hardcoded = key_is_hardcoded,
                .severity = if (is_weak or is_deprecated) @as(u8, 80) else if (key_is_hardcoded) @as(u8, 90) else @as(u8, 30),
            });

            if (is_weak) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .issue = .weak_cipher,
                    .severity = 75,
                    .cipher = alg,
                    .description = try std.fmt.allocPrint(allocator, "Weak cipher algorithm: {s}", .{name}),
                    .recommendation = "Replace with AES-256-GCM or ChaCha20-Poly1305",
                });
            }

            if (is_deprecated) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .issue = .deprecated_algorithm,
                    .severity = 70,
                    .cipher = alg,
                    .description = try std.fmt.allocPrint(allocator, "Deprecated algorithm: {s}", .{name}),
                    .recommendation = "Migrate to modern AEAD cipher",
                });
            }

            if (is_ecb) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .issue = .ecb_mode,
                    .severity = 80,
                    .cipher = alg,
                    .description = "ECB mode detected - does not provide semantic security",
                    .recommendation = "Use GCM or at minimum CBC with HMAC",
                });
            }

            if (key_is_hardcoded) {
                try key_materials.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .key_type = classifyKeyType(name),
                    .key_source = .hardcoded,
                    .strength = .unknown,
                    .location = .code_section,
                    .is_exposed = true,
                });
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .issue = .hardcoded_key,
                    .severity = 90,
                    .cipher = alg,
                    .description = "Hardcoded cryptographic key detected",
                    .recommendation = "Use key management service or derive from secure source",
                });
            }

            if (iv_static) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = function.start,
                    .issue = .static_iv,
                    .severity = 75,
                    .cipher = alg,
                    .description = "Static initialization vector detected",
                    .recommendation = "Generate random IV for each encryption operation",
                });
            }

            if (!is_weak and !is_deprecated) {
                if (!isStrongRandom(name)) {
                    const init_patterns = [_][]const u8{ "Init", "init", "Open", "open", "Acquire", "acquire" };
                    for (init_patterns) |pattern| {
                        if (std.mem.indexOf(u8, name, pattern) != null) {
                            break;
                        }
                    }
                }
            }
        }
    }

    var weak_count: usize = 0;
    var hk_count: usize = 0;
    var dep_count: usize = 0;

    for (findings.items) |f| {
        switch (f.issue) {
            .weak_cipher => weak_count += 1,
            .hardcoded_key => hk_count += 1,
            .deprecated_algorithm => dep_count += 1,
            else => {},
        }
    }

    const score = computeCryptoGapScore(findings.items, cipher_usages.items);

    return .{
        .cipher_usages = try cipher_usages.toOwnedSlice(),
        .findings = try findings.toOwnedSlice(),
        .key_materials = try key_materials.toOwnedSlice(),
        .randomness_sources = try randomness_sources.toOwnedSlice(),
        .weak_cipher_count = weak_count,
        .hardcoded_key_count = hk_count,
        .deprecated_count = dep_count,
        .total_crypto_operations = cipher_usages.items.len,
        .crypto_gap_score = score,
    };
}

fn classifyKeyType(name: []const u8) KeyType {
    if (utils.containsAny(name, &.{ "AES_128", "aes_128" })) return .symmetric_aes_128;
    if (utils.containsAny(name, &.{ "AES_192", "aes_192" })) return .symmetric_aes_192;
    if (utils.containsAny(name, &.{ "AES_256", "aes_256", "AES256" })) return .symmetric_aes_256;
    if (utils.containsAny(name, &.{ "RSA_1024", "rsa_1024" })) return .rsa_1024;
    if (utils.containsAny(name, &.{ "RSA_2048", "rsa_2048", "RSA2048" })) return .rsa_2048;
    if (utils.containsAny(name, &.{ "RSA_4096", "rsa_4096" })) return .rsa_4096;
    if (utils.containsAny(name, &.{ "ECDSA_P256", "ecdsa_p256", "prime256v1" })) return .ecdsa_p256;
    if (utils.containsAny(name, &.{ "ECDSA_P384", "ecdsa_p384", "secp384r1" })) return .ecdsa_p384;
    if (utils.containsAny(name, &.{ "DSA", "dsa" })) return .symmetric_des;
    return .unknown;
}

fn classifyMode(alg: CipherAlgorithm) CipherMode {
    return switch (alg) {
        .aes_ecb => .ecb,
        .aes_cbc => .cbc,
        .aes_gcm => .gcm,
        .aes_ctr => .ctr,
        .chacha20 => .poly1305_aead,
        .poly1305 => .poly1305_aead,
        .des, .triple_des => .cbc,
        .rc4 => .ofb,
        else => .unknown,
    };
}

fn isKeyLikelyHardcoded(bytes: []const u8, name: []const u8) bool {
    _ = name;
    const hex_key_patterns = [_]usize{ 16, 32, 64 };
    if (bytes.len < 16) return false;
    for (hex_key_patterns) |len| {
        var off: usize = 0;
        while (off + len <= bytes.len) : (off += 1) {
            const slice = bytes[off..off + len];
            if (isLikelyHexKey(slice, len)) return true;
        }
    }
    return false;
}

fn isLikelyHexKey(data: []const u8, expected_len: usize) bool {
    if (data.len != expected_len) return false;
    var hex_chars: usize = 0;
    for (data) |byte| {
        switch (byte) {
            '0'...'9', 'a'...'f', 'A'...'F', 'x', 'X' => hex_chars += 1,
            else => return false,
        }
    }
    return hex_chars >= expected_len - 2;
}

fn computeCryptoGapScore(findings: []const CryptoFinding, usages: []const CipherUsage) f64 {
    if (usages.len == 0 and findings.len == 0) return 0;
    var score: f64 = 0;
    for (findings) |f| {
        score += @as(f64, @floatFromInt(f.severity)) * 0.2;
    }
    var weak_count: usize = 0;
    var hk_count: usize = 0;
    const deprecated_count = findings.len;
    for (findings) |f| {
        switch (f.issue) {
            .weak_cipher => weak_count += 1,
            .hardcoded_key => hk_count += 1,
            else => {},
        }
    }
    if (usages.len > 0) {
        score += @as(f64, @floatFromInt(weak_count)) * 20.0 / @as(f64, @floatFromInt(usages.len));
        score += @as(f64, @floatFromInt(hk_count)) * 35.0 / @as(f64, @floatFromInt(usages.len));
    }
    _ = deprecated_count;
    return utils.clamp100(score);
}

pub fn auditKeyStorage(allocator: Allocator, bytes: []const u8, _: BinaryImage) ![]KeyMaterial {
    var keys = std.ArrayList(KeyMaterial).init(allocator);
    errdefer keys.deinit();

    const plaintext_key_patterns = [_][]const u8{
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "ssh-rsa", "ssh-ed25519",
        "private_key", "secret_key", "key_secret", "encryption_key",
    };

    for (plaintext_key_patterns) |pattern| {
        var off: usize = 0;
        while (std.mem.indexOf(u8, bytes[off..], pattern)) |match| {
            const abs_off = off + match;
            try keys.append(.{
                .address = abs_off,
                .function_va = 0,
                .key_type = .rsa_2048,
                .key_source = .hardcoded,
                .strength = .weak,
                .location = .data_section,
                .is_exposed = true,
            });
            off = abs_off + 1;
        }
    }

    return keys.toOwnedSlice();
}

pub fn analyzeTLSConfiguration(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]CryptoFinding {
    var findings = std.ArrayList(CryptoFinding).init(allocator);
    errdefer findings.deinit();

    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            const name = resolved.name;

            if (utils.containsAny(name, &.{ "SSL_CTX_set_verify", "set_verify" })) {
                continue;
            }

            if (utils.containsAny(name, &.{ "SSL_CTX_set_options", "SSL_OP_NO_SSLv2", "SSL_OP_NO_SSLv3", "SSL_OP_NO_TLSv1" })) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = 0,
                    .issue = .certificate_validation_disabled,
                    .severity = 85,
                    .cipher = .unknown,
                    .description = "TLS version restriction detected - may indicate legacy protocol support",
                    .recommendation = "Disable TLS 1.0/1.1, require TLS 1.2+",
                });
            }

            if (utils.containsAny(name, &.{ "SSL_CTX_set_cipher_list", "set_cipher" })) {
                continue;
            }
        }
    }

    return findings.toOwnedSlice();
}

pub fn scoreKeyStrength(key_type: KeyType) KeyStrength {
    return switch (key_type) {
        .symmetric_aes_256, .rsa_4096, .ecdsa_p521, .hmac_sha256 => .very_strong,
        .symmetric_aes_192, .rsa_2048, .ecdsa_p384 => .strong,
        .symmetric_aes_128, .rsa_1024, .ecdsa_p256 => .acceptable,
        .symmetric_des, .symmetric_3des, .symmetric_rc4 => .weak,
        else => .unknown,
    };
}
