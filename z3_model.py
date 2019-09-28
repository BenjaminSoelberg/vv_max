from z3 import *

BIT_MASK = 0x1
NIBBLE_MASK = 0xF
BYTE_MASK = 0xFF
WORD_MASK = 0xFFFF
DWORD_MASK = 0xFFFFFFFF


class Z3ModelBuilder:

    def __init__(self):
        self.solver = Solver()
        self.bitvec_id = 1
        self.bitvec_name_prefix = ""

    ##############################################################
    # Z3 solver helpers
    ##############################################################

    def get_byte_range_constraint(self, bv, byte_pos, start, end):
        value = LShR(bv, byte_pos * 8) & BYTE_MASK
        return And(UGE(value, start), ULE(value, end))

    def add_byte_range_constraint_with_zero(self, bv, byte_pos, start, end):
        value = LShR(bv, byte_pos * 8) & BYTE_MASK
        self.add(Or(value == 0, And(UGE(value, start), ULE(value, end))))

    def add(self, *args):
        self.solver.add(*args)

    def check(self):
        return self.solver.check() == sat

    def create_bitvec(self, name=""):
        if name != "":
            name = "_" + name
        name = ('%s%s_%03d' % (self.bitvec_name_prefix, name, self.bitvec_id)).ljust(42)
        res = BitVec(name, 256)
        self.bitvec_id += 1
        return res

    def create_bitvecval(self, val):
        res = BitVecVal(val, 256)
        return res

    def dump_model(self):
        if not self.check():
            print("Model failed!")
            return

        m = self.solver.model()
        print("traversing model...")
        for d in m:
            print("%s = %s" % (d.name(), hex(m[d].as_long())))

    def u2s(self, value, bits):
        res = self.create_bitvec("u2s")
        mask = 1 << (bits - 1)
        self.add(res == (value & (mask - 1)) - (value & mask))
        return res

    def s2u(self, value, bits):
        res = BitVec("s2u", 256)
        mask = (1 << bits) - 1
        self.add(res == (value & mask))
        return res

    ##############################################################
    # BYTES
    ##############################################################

    def ins_07_vpaddb(self, a, b):
        res = self.create_bitvec()

        for j in range(32):
            mask = 0xFF << j * 8
            self.add(res & mask == ((a & mask) + (b & mask)) & mask)

        return res

    def ins_05_vpand(self, a, b):
        res = self.create_bitvec()
        self.add(res == a & b)
        return res

    def ins_16_vpcmpeqb(self, a, b):
        res = self.create_bitvec()

        for j in range(32):
            mask = BYTE_MASK << j * 8
            self.add(res & mask == If((a & mask) == (b & mask), self.create_bitvecval(0xFF) << (j * 8), 0))

        return res

    def ins_03_vpxor(self, a, b):
        res = self.create_bitvec()
        self.add(res == a ^ b)
        return res

    def ins_04_vpor(self, a, b):
        res = self.create_bitvec()
        self.add(res == a | b)
        return res

    def ins_14_vpshufb(self, a, b):
        res = self.create_bitvec()
        for i in range(16):
            bit_index = i * 8
            bit_index_128 = 128 + (i * 8)
            ctrl_bit_index = bit_index + 7
            ctrl_bit_index_128 = bit_index_128 + 7
            select_mask = BYTE_MASK << bit_index
            select_mask_128 = BYTE_MASK << bit_index_128

            self.add(res & select_mask ==
                     If((LShR(b, ctrl_bit_index) & 1) == 1,
                        0,
                        (LShR(a, (LShR(b, bit_index) & NIBBLE_MASK) * 8) & BYTE_MASK) << bit_index))
            self.add(res & select_mask_128 ==
                     If((LShR(b, ctrl_bit_index_128) & 1) == 1, 0,
                        (LShR(a,
                              128 + ((LShR(b, bit_index_128) & NIBBLE_MASK) * 8)) & BYTE_MASK) << bit_index_128))

        return res

    def ins_01_vpmaddubsw(self, a, b):
        res = self.create_bitvec()
        temp = [None] * 32
        for j in range(32):
            a1 = (LShR(a, j * 8) & BYTE_MASK)  # Unsigned
            b1 = self.u2s(LShR(b, j * 8) & BYTE_MASK, 8)  # Signed
            temp[j] = (b1 * a1) & WORD_MASK

        for j in range(16):
            select_mask = WORD_MASK << (j * 16)
            self.add((res & select_mask) == (((temp[j * 2] + temp[(j * 2) + 1]) & WORD_MASK) << (j * 16)))

        return res

    ##############################################################
    # WORDS
    ##############################################################

    def ins_02_vpmaddwd(self, a, b):  # TODO: Sign handling not implemented
        res = self.create_bitvec()
        temp = [None] * 16
        for j in range(16):
            temp[j] = ((LShR(a, j * 16) & WORD_MASK) * (LShR(b, j * 16) & WORD_MASK)) & DWORD_MASK

        for j in range(8):
            select_mask = DWORD_MASK << (j * 32)
            self.add((res & select_mask) == ((temp[j * 2] + temp[(j * 2) + 1]) & DWORD_MASK) << (j * 32))

        return res

    ##############################################################
    # DWORDS
    ##############################################################

    def ins_0B_vpaddd(self, a, b):
        res = self.create_bitvec()

        for j in range(8):
            select_mask = DWORD_MASK << (j * 32)
            self.add(res & select_mask == ((a & select_mask) + (b & select_mask)) & select_mask)

        return res

    def ins_15_vpermd(self, a, b):
        res = self.create_bitvec()

        for j in range(8):
            select_mask = DWORD_MASK << (j * 32)
            index_value = LShR(b, (j * 32)) & 0x07
            data_value = LShR(a, index_value * 32) & DWORD_MASK
            self.add(res & select_mask == (data_value << (j * 32)))

        return res

    def ins_12_vpsrld(self, a, b):
        res = self.create_bitvec()

        for j in range(8):
            select_mask = DWORD_MASK << (j * 32)
            self.add(res & select_mask == LShR(a & select_mask, b) & select_mask)

        return res

    def ins_13_vpslld(self, a, b):
        res = self.create_bitvec()

        for j in range(8):
            select_mask = DWORD_MASK << (j * 32)
            self.add(res & select_mask == ((a & select_mask) << b) & select_mask)

        return res

    ##############################################################
    # QQWORDS
    ##############################################################

    def ins_11_vmovdqu(self, a):
        res = BitVecVal(a, 256)
        self.add(self.create_bitvec() == res)
        return res


##############################################################
# TEST
##############################################################
def test():
    # Unit u2s
    s = Z3ModelBuilder()
    a = BitVecVal(0xFF, 256)
    e = BitVecVal(-1, 256)
    s.add(e == s.u2s(a, 8))
    assert s.check()

    s = Z3ModelBuilder()
    a = BitVecVal(0x7FFF, 256)
    e = BitVecVal(32767, 256)
    s.add(e == s.u2s(a, 16))
    assert s.check()

    s = Z3ModelBuilder()
    a = BitVecVal(0x1, 256)
    e = BitVecVal(1, 256)
    s.add(e == s.u2s(a, 16))
    assert s.check()

    for i in range(-128, 127):
        s = Z3ModelBuilder()
        a = s.s2u(BitVecVal(i, 256), 8)
        e = BitVecVal(i & 0xff, 256)
        s.add(e == a)
        assert s.check()

    s = Z3ModelBuilder()
    a = BitVecVal(0x01, 256)
    e = BitVecVal(0x01, 256)
    s.add(e == s.u2s(a, 8))
    assert s.check()

    # Unit vmovdqu
    s = Z3ModelBuilder()
    a = 0x15111111111111111111131a1b1b1b1a15111111111111111111131a1b1b1b1a
    e = BitVecVal(0x15111111111111111111131a1b1b1b1a15111111111111111111131a1b1b1b1a, 256)
    s.add(e == s.ins_11_vmovdqu(a))
    assert s.check()

    # Unit vpcmpeqb
    s = Z3ModelBuilder()
    a = BitVecVal(0x3838383837373737363636363535353534343434333333333232323231313131, 256)
    b = BitVecVal(0x3838383837373737363636363535353534343434333333333232323231313131, 256)
    e = BitVecVal(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 256)
    s.add(e == s.ins_16_vpcmpeqb(a, b))
    assert s.check()

    s = Z3ModelBuilder()
    a = BitVecVal(0x3838383837373737363636363535353534343434333333333232323231313131, 256)
    b = BitVecVal(0x0038383837373737360036363535353534343434333300333232323231003131, 256)
    e = BitVecVal(0x00ffffffffffffffff00ffffffffffffffffffffffff00ffffffffffff00ffff, 256)
    s.add(e == s.ins_16_vpcmpeqb(a, b))
    assert s.check()

    # Unit vpermd
    s = Z3ModelBuilder()
    a = BitVecVal(0x26046af3103cd6712cbff536b48a790f90f7651cfc3b994e2a906eae5b53c1f9, 256)
    b = BitVecVal(0x0000000300000002000000010000000000000007000000060000000500000004, 256)
    e = BitVecVal(0x90f7651cfc3b994e2a906eae5b53c1f926046af3103cd6712cbff536b48a790f, 256)
    s.add(e == s.ins_15_vpermd(a, b))
    assert s.check()
    s = Z3ModelBuilder()
    a = BitVecVal(0x0000000000000000000000000000000000000000000000393130324552414c46, 256)
    b = BitVecVal(0x0000000000000000000000000000000000000000000000000000000000000000, 256)
    e = BitVecVal(0x52414c4652414c4652414c4652414c4652414c4652414c4652414c4652414c46, 256)
    s.add(e == s.ins_15_vpermd(a, b))
    assert s.check()

    # Unit vpsrld
    s = Z3ModelBuilder()
    a = BitVecVal(0x6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19, 256)
    b = 25
    e = BitVecVal(0x000000350000005d0000001e00000052000000280000004d0000000f0000002d, 256)
    s.add(e == s.ins_12_vpsrld(a, b))
    assert s.check()

    # Unit vpxor
    s = Z3ModelBuilder()
    a = BitVecVal(0xad8c66f08fd5ecc14d46b482a83f2987529dfaa71eb97937dd42d7b3b533f304, 256)
    b = BitVecVal(0x197C2BA37BF06335AD609311CA21EA4FFEA954A7DE8D476EF56CB7D03C41EDCC, 256)
    e = BitVecVal(0xb4f04d53f4258ff4e0262793621ec3c8ac34ae00c0343e59282e606389721ec8, 256)
    s.add(e == s.ins_03_vpxor(a, b))
    assert s.check()

    # Unit vpor
    s = Z3ModelBuilder()
    a = BitVecVal(0x808c66f080d5ecc10046b482803f2987009dfaa700b979378042d7b38033f304, 256)
    b = BitVecVal(0x2D0000000F0000004D00000028000000520000001E0000005D00000035000000, 256)
    e = BitVecVal(0xad8c66f08fd5ecc14d46b482a83f2987529dfaa71eb97937dd42d7b3b533f304, 256)
    s.add(e == s.ins_04_vpor(a, b))
    assert s.check()

    # Unit vpaddd
    s = Z3ModelBuilder()
    a = BitVecVal(0xefbebfb9fdbff7b9bdfefbffedbffbbdbdfef3fbfdffb3f9bfbfb3bdafbefffd, 256)
    b = BitVecVal(0x55b65510758db09291cf8f0dea3b0b783587272ba14b334258f12a9236227380, 256)
    e = BitVecVal(0x457514c9734da84b4fce8b0cd7fb0735f3861b269f4ae73b18b0de4fe5e1737d, 256)
    s.add(e == s.ins_0B_vpaddd(a, b))
    assert s.check()

    # Unit vpshufb
    s = Z3ModelBuilder()
    a = BitVecVal(0x00f3cf3c00efbefb00ebaeba00e79e7900e38e3800df7df700db6db600d75d75, 256)
    b = BitVecVal(0xffffffff0c0d0e08090a040506000102ffffffff0c0d0e08090a040506000102, 256)
    e = BitVecVal(0x000000003ccff3fbbeefbaaeeb799ee700000000388ee3f77ddfb66ddb755dd7, 256)
    s.add(e == s.ins_14_vpshufb(a, b))
    assert s.check()

    # Unit vpslld
    s = Z3ModelBuilder()
    a = BitVecVal(0x0fe3659de36721abbdca14695d223f97624fc76e90dc9313e9f0cfd058d3aa67, 256)
    b = BitVecVal(0x07, 256)
    e = BitVecVal(0xf1b2ce80b390d580e50a3480911fcb8027e3b7006e498980f867e80069d53380, 256)
    s.add(e == s.ins_13_vpslld(a, b))
    assert s.check()

    # Unit vpmaddwd
    s = Z3ModelBuilder()
    a = BitVecVal(0x0f3c0f3c0efb0efb0eba0eba0e790e790e380e380df70df70db60db60d750d75, 256)
    b = BitVecVal(0x0001100000011000000110000001100000011000000110000001100000011000, 256)
    e = BitVecVal(0x00f3cf3c00efbefb00ebaeba00e79e7900e38e3800df7df700db6db600d75d75, 256)
    s.add(e == s.ins_02_vpmaddwd(a, b))
    assert s.check()

    # Unit vpmaddubsw
    s = Z3ModelBuilder()
    a = BitVecVal(0x3c3c3c3c3b3b3b3b3a3a3a3a3939393938383838373737373636363635353535, 256)
    b = BitVecVal(0x0140014001400140014001400140014001400140014001400140014001400140, 256)
    e = BitVecVal(0xf3c0f3c0efb0efb0eba0eba0e790e790e380e380df70df70db60db60d750d75, 256)
    s.add(e == s.ins_01_vpmaddubsw(a, b))
    assert s.check()

    # Unit vpaddb
    s = Z3ModelBuilder()
    a = BitVecVal(0xff0001001b1a191817161514131211100f0e0d0c0b0a09080706050403020100, 256)
    b = BitVecVal(0x0100ff001b1a191817161514131211100f0e0d0c0b0a09080706050403020100, 256)
    e = BitVecVal(0x00000000363432302e2c2a28262422201e1c1a18161412100e0c0a0806040200, 256)
    e = s.create_bitvec("e")
    s.add(e == s.ins_07_vpaddb(a, b))
    assert s.check()

    # Unit vpand
    s = Z3ModelBuilder()
    a = BitVecVal(0x3c3c3c3c3b3b3b3b3a3a3a3a3939393938383838373737373636363635353535, 256)
    b = BitVecVal(0x0140014001400140014001400140014001400140014001400140014001400140, 256)
    e = BitVecVal(0x0000000001000100000000000100010000000000010001000000000001000100, 256)
    s.add(e == s.ins_05_vpand(a, b))
    assert s.check()


if __name__ == '__main__':
    test()
