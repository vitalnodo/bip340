const std = @import("std");
const testing = std.testing;
const fmt = std.fmt;
const mem = std.mem;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn taggedHash(tag: []const u8, msg: []const u8) [32]u8 {
    var buf: [32]u8 = undefined;
    Sha256.hash(tag, &buf, .{});

    var sha256 = Sha256.init(.{});
    sha256.update(buf[0..]);
    sha256.update(buf[0..]);
    sha256.update(msg);
    sha256.final(&buf);
    return buf;
}

fn sign(secret: [32]u8, msg: [32]u8, aux_rand: [32]u8) ![64]u8 {
    const d0 = try Scalar.fromBytes(secret, .Big);
    const P = try Secp256k1.basePoint.mulPublic(d0.toBytes(.Big), .Big);
    var d = d0;
    if (P.affineCoordinates().y.isOdd()) {
        d = d.neg();
    }
    var t: [32]u8 = undefined;
    for (d.toBytes(.Big), 0..) |byte, i| {
        t[i] = byte ^ taggedHash("BIP0340/aux", aux_rand[0..])[i];
    }
    var to_hash: [96]u8 = undefined;
    mem.copy(u8, to_hash[0..32], t[0..]);
    mem.copy(u8, to_hash[32..64], P.toCompressedSec1()[1..]);
    mem.copy(u8, to_hash[64..96], msg[0..]);
    const k0: [32]u8 = taggedHash("BIP0340/nonce", to_hash[0..]); // rand
    var k = try Scalar.fromBytes(k0, .Big);
    var R = try Secp256k1.basePoint.mul(k0, .Big);
    if (R.affineCoordinates().y.isOdd()) {
        k = k.neg();
    }
    mem.copy(u8, to_hash[0..32], R.toCompressedSec1()[1..]);
    mem.copy(u8, to_hash[32..64], P.toCompressedSec1()[1..]);
    mem.copy(u8, to_hash[64..96], msg[0..]);
    const e: [32]u8 = taggedHash("BIP0340/challenge", to_hash[0..]);
    var res: [64]u8 = undefined;
    mem.copy(u8, res[0..32], R.toCompressedSec1()[1..]);
    var seems_as_final = (try Scalar.fromBytes(e, .Big)).mul(d).add(k);
    mem.copy(u8, res[32..64], seems_as_final.toBytes(.Big)[0..]);
    return res;
}

fn verify(public_key: [32]u8, msg: [32]u8, signature: [64]u8) !bool {
    const Px = try Secp256k1.Fe.fromBytes(public_key, .Big);
    const Py = try Secp256k1.recoverY(Px, false);
    const P = try Secp256k1.fromAffineCoordinates(.{ .x = Px, .y = Py });
    const r = try Secp256k1.Fe.fromBytes(signature[0..32].*, .Big);
    const s = try Secp256k1.scalar.Scalar.fromBytes(signature[32..64].*, .Big);
    var to_hash: [96]u8 = undefined;
    mem.copy(u8, to_hash[0..32], signature[0..32]);
    mem.copy(u8, to_hash[32..64], public_key[0..]);
    mem.copy(u8, to_hash[64..96], msg[0..]);
    const e = try Scalar.fromBytes(
        taggedHash("BIP0340/challenge", to_hash[0..]),
        .Big,
    );
    const R = (try Secp256k1.basePoint.mulPublic(
        s.toBytes(.Big),
        .Big,
    )).sub(try P.mul(e.toBytes(.Big), .Big));
    if (R.affineCoordinates().y.isOdd()) {
        return false;
    }
    if (!R.affineCoordinates().x.equivalent(r)) {
        return false;
    }
    return true;
}

// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
test "sign" {
    const Vectors = struct {
        secret: []const u8,
        public: []const u8,
        aux_rand: []const u8,
        msg: []const u8,
        signature: []const u8,
    };

    var to_sign = [_]Vectors{
        Vectors{
            .secret = "0000000000000000000000000000000000000000000000000000000000000003",
            .public = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            .aux_rand = "0000000000000000000000000000000000000000000000000000000000000000",
            .msg = "0000000000000000000000000000000000000000000000000000000000000000",
            .signature = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
        },
        Vectors{
            .secret = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .aux_rand = "0000000000000000000000000000000000000000000000000000000000000001",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
        },
        Vectors{
            .secret = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            .public = "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            .aux_rand = "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            .msg = "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            .signature = "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
        },
        Vectors{
            .secret = "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            .public = "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            .aux_rand = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            .msg = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            .signature = "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
        },
    };

    for (to_sign) |v| {
        var secret: [32]u8 = undefined;
        _ = try fmt.hexToBytes(secret[0..], v.secret);
        var public: [32]u8 = undefined;
        _ = try fmt.hexToBytes(public[0..], v.public);
        var aux_rand: [32]u8 = undefined;
        _ = try fmt.hexToBytes(aux_rand[0..], v.aux_rand);
        var msg: [32]u8 = undefined;
        _ = try fmt.hexToBytes(msg[0..], v.msg);
        var signature: [64]u8 = undefined;
        _ = try fmt.hexToBytes(signature[0..], v.signature);

        const signature_ev = try sign(secret, msg, aux_rand);
        var res: [128]u8 = undefined;
        _ = try fmt.bufPrint(
            res[0..],
            "{x}",
            .{fmt.fmtSliceHexUpper(signature_ev[0..])},
        );
        try testing.expectEqualStrings(v.signature, res[0..]);
    }
}

test "verify" {
    const Vectors = struct {
        public: []const u8,
        msg: []const u8,
        signature: []const u8,
        result: bool,
    };

    const to_verify = [_]Vectors{
        Vectors{
            .public = "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            .msg = "0000000000000000000000000000000000000000000000000000000000000000",
            .signature = "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            .result = true,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            .result = true,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            .result = true,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            .result = true,
        },
        Vectors{
            .public = "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            .msg = "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            .signature = "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            .result = true,
        },
        Vectors{
            .public = "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            .msg = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            .signature = "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            .result = true,
        },
        Vectors{
            .public = "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            .msg = "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            .signature = "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            .result = true,
        },
        Vectors{
            .public = "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            .result = false,
        },
        Vectors{
            .public = "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            .result = false,
        },
        Vectors{
            .public = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            .msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            .signature = "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            .result = false,
        },
    };

    for (to_verify) |v| {
        var public: [32]u8 = undefined;
        _ = try fmt.hexToBytes(public[0..], v.public);
        var msg: [32]u8 = undefined;
        _ = try fmt.hexToBytes(msg[0..], v.msg);
        var signature: [64]u8 = undefined;
        _ = try fmt.hexToBytes(signature[0..], v.signature);
        const res = verify(public, msg, signature) catch false;
        try testing.expectEqual(v.result, res);
    }
}
