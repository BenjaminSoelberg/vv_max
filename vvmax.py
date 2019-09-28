import binascii
import struct

from z3_model import *

'''
This project aims to solve Flareon6 challenge 11 using the Z3 solver.
The overall architecture is to emulate all the used AVX2 instructions good enough to solve the challenge.
It works much like a CPU where AVX2 instructions are implemented as z3 constraints. 
I don't know much about Z3 or actually how to use it effectively but this gets the job done.
The "self.builder.bitvec_name_prefix" helps to assert that the Z3 solver follows the actual values in the original
program by giving each resulting bitvec a "meaningful" name that corresponds to the IP and instruction in the VM.

I had a lot of problems with signed/unsigned vales as well as endianness. Z3 uses big endian and intel little endian.
But in the end it didn't seems to matter. Only the signed stuff probably has bugs but works good enough for now.

The vpermd instruction has 1. and 2. operand reversed with respect to the intel manual which also caused some headache.

All in all a very good (yet frustrating) learning experience with Z3.

A few key takeaways when using Z3:
    Write unit tests
    Give each BitVec a meaningful name.
    Add as many constraints as you can think of.
    
benjamin.soelberg@gmail.com
'''
class VM:
    OPCODES = {
        0x00: (0x01, lambda: VM.vm_ins_00_init),
        0x01: (0x04, lambda: VM.vm_ins_01_vpmaddubsw),
        0x02: (0x04, lambda: VM.vm_ins_02_vpmaddwd),
        0x03: (0x04, lambda: VM.vm_ins_03_vpxor),
        0x04: (0x04, lambda: VM.vm_ins_04_vpor),
        0x05: (0x04, lambda: VM.vm_ins_05_vpand),
        0x07: (0x04, lambda: VM.vm_ins_07_vpaddb),
        0x0B: (0x04, lambda: VM.vm_ins_0B_vpaddd),
        0x11: (0x22, lambda: VM.vm_ins_11_vmovdqu),
        0x12: (0x04, lambda: VM.vm_ins_12_vpsrld),
        0x13: (0x04, lambda: VM.vm_ins_13_vpslld),
        0x14: (0x04, lambda: VM.vm_ins_14_vpshufb),
        0x15: (0x04, lambda: VM.vm_ins_15_vpermd),
        0x16: (0x04, lambda: VM.vm_ins_16_vpcmpeqb),
        0xFF: (0x01, lambda: VM.vm_ins_FF_end),
    }

    def __init__(self, arg1, arg2):
        self.arg1 = arg1
        self.arg2 = arg2
        self.ip = 0

        with open("code.vm", 'rb') as f:
            self.mem = f.read()

        if arg1:
            for i, c in enumerate(arg1):
                self.set_byte(i + 0x03, ord(c))

        if arg2:
            for i, c in enumerate(arg2):
                self.set_byte(i + 0x25, ord(c))

        self.builder = Z3ModelBuilder()

        self.regs = [None] * 32
        for r in range(len(self.regs)):
            if r == 0 and self.arg1 is None:
                bv = self.builder.create_bitvec('r0')
            elif r == 1 and self.arg2 is None:
                bv = self.builder.create_bitvec('r1')
            else:
                bv = self.builder.create_bitvecval(0)
            self.regs[r] = bv

    # --- VM helpers ---
    def get_raw(self, index, size):
        return self.mem[index:index + size]

    def set_raw(self, index, data):
        self.mem = self.mem[0:index] + data + self.mem[index + len(data):]

    def get_byte(self, index):
        return self.mem[index] & 0xFF

    def set_byte(self, index, value):
        self.set_raw(index, struct.pack("<B", value))

    def get_qqword(self, index):
        return self.get_dqword(index) | (self.get_dqword(index + 16) << 128)

    def get_dqword(self, index):
        return self.get_qword(index) | (self.get_qword(index + 8) << 64)

    def get_qword(self, index):
        return struct.unpack("<Q", self.get_raw(index, 8))[0]

    def get_r_a_b(self):
        r = self.get_byte(self.ip + 1)
        a = self.get_byte(self.ip + 2)
        b = self.get_byte(self.ip + 3)
        print("r%d, r%d, r%d" % (r, a, b))
        return r, a, b

    def get_r_a_c(self):
        r = self.get_byte(self.ip + 1)
        a = self.get_byte(self.ip + 2)
        c = self.get_byte(self.ip + 3)
        print("r%d, r%d, %d" % (r, a, c))
        return r, a, c

    def execute_with_r_a_b(self, f):
        r, a, b = self.get_r_a_b()
        self.regs[r] = f(self.regs[a], self.regs[b])

    def execute_with_r_a_c(self, f):
        r, a, c = self.get_r_a_c()
        self.regs[r] = f(self.regs[a], c)

    # --- Instructions ---
    def vm_ins_00_init(self):
        # Actual setup handled in init()
        print("r0-31, 0")
        return self.builder.create_bitvec("ignore")

    def vm_ins_01_vpmaddubsw(self):
        return self.execute_with_r_a_b(self.builder.ins_01_vpmaddubsw)

    def vm_ins_02_vpmaddwd(self):
        return self.execute_with_r_a_b(self.builder.ins_02_vpmaddwd)

    def vm_ins_03_vpxor(self):
        return self.execute_with_r_a_b(self.builder.ins_03_vpxor)

    def vm_ins_04_vpor(self):
        return self.execute_with_r_a_b(self.builder.ins_04_vpor)

    def vm_ins_05_vpand(self):
        return self.execute_with_r_a_b(self.builder.ins_05_vpand)

    def vm_ins_07_vpaddb(self):
        return self.execute_with_r_a_b(self.builder.ins_07_vpaddb)

    def vm_ins_0B_vpaddd(self):
        return self.execute_with_r_a_b(self.builder.ins_0B_vpaddd)

    def vm_ins_11_vmovdqu(self):
        r = self.get_byte(self.ip + 1)
        if (r == 0 and self.arg1 is None) or (r == 1 and self.arg2 is None):
            print("r%d, UNKNOWN" % r)
            return self.builder.create_bitvec("unknown")

        raw = self.get_raw(self.ip + 2, 32)[::-1]
        print("r%d, %s" % (r, binascii.hexlify(raw)))
        a = 0
        for b in raw:
            a = (a << 8) + b
        res = self.builder.ins_11_vmovdqu(a)
        self.regs[r] = res
        return res

    def vm_ins_12_vpsrld(self):
        return self.execute_with_r_a_c(self.builder.ins_12_vpsrld)

    def vm_ins_13_vpslld(self):
        return self.execute_with_r_a_c(self.builder.ins_13_vpslld)

    def vm_ins_14_vpshufb(self):
        return self.execute_with_r_a_b(self.builder.ins_14_vpshufb)

    def vm_ins_15_vpermd(self):
        return self.execute_with_r_a_b(self.builder.ins_15_vpermd)

    def vm_ins_16_vpcmpeqb(self):
        return self.execute_with_r_a_b(self.builder.ins_16_vpcmpeqb)

    def vm_ins_FF_end(self):
        print("^C")
        return self.builder.create_bitvec("ignore")

    # --- Run loop ---
    def run(self):
        print("IP     Op   Len  Name              Args")
        print("------------------------------------------------------------------------------------------------------")

        ins_count = 0
        while True:
            ins_count += 1
            opcode = self.get_byte(self.ip)
            size, handler = self.OPCODES[opcode]

            self.builder.bitvec_name_prefix = "0x%04X xxxx xxxx %s" % (self.ip, handler().__name__)
            print(("0x%04X 0x%02X 0x%02X %s" % (self.ip, opcode, size, handler().__name__)).ljust(42), end='')

            handler()(self)
            assert self.builder.check()

            if opcode == 255:
                break

            ins_count += 1
            self.ip += size

        self.builder.add(self.regs[2] == self.regs[20])
        assert self.builder.check()

        flag = BitVec("flag", 256)
        self.builder.add(flag == self.regs[1] ^ self.regs[31])
        assert self.builder.check()
        for i in range(32):
            print("Constraining arg2 index", i)
            self.builder.get_byte_range_constraint(flag, i, 0x20, 0x7a)
            assert self.builder.check()

        for i in range(32):
            print("Constraining flag index", i)
            range1 = self.builder.get_byte_range_constraint(flag, i, ord('0'), ord('9'))
            range2 = self.builder.get_byte_range_constraint(flag, i, ord('A'), ord('Z'))
            range3 = self.builder.get_byte_range_constraint(flag, i, ord('a'), ord('z'))
            range4 = self.builder.get_byte_range_constraint(flag, i, ord('_'), ord('_'))
            self.builder.add(Or(range1, Or(range2, Or(range3, range4))))
            assert self.builder.check()

        self.builder.dump_model()

        while self.builder.check():
            m = self.builder.solver.model()
            for d in m:
                if d.name() == "flag":
                    self.builder.add(flag != m[d].as_long())
                    s = hex(m[d].as_long())
                    print("Possible flag %s" % (bytearray.fromhex(s[2:])[::-1].decode('ascii')))
                    break


def main(arg1, arg2):
    if arg1 is not None and 4 < len(arg1) > 32:
        print('arg1 has wrong length (4-32)')
        return

    if arg2 is not None and len(arg2) != 32:
        print('arg2 has wrong length (32)')
        return

    vm = VM(arg1, arg2)
    vm.run()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        main("FLARE2019", None)
    elif len(sys.argv) == 2:
        main(sys.argv[1], None)
    else:
        main(sys.argv[1], sys.argv[2])
