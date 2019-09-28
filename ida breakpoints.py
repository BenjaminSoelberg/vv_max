'''
Not a fully updated list but good enough...
'''
# 11 mov
print "mov  r%d, 0x%s" % (cpu.rax / 32, binascii.hexlify(cpu.ymm0[::-1]))

# 15 perm
print "perm r%d, r%d, r%d (0x%s = 0x%s, 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 0),
    ida_bytes.get_byte(cpu.ebp + 1),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rax+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rcx+0x800, 32)[::-1])
)

# 12 shrd
print "shrd r%d, r%d, %d (0x%s = 0x%s >> %d)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(cpu.ymm1[::-1]),
    ida_bytes.get_byte(cpu.ebp + 0)
)

# 03 xor
print "xor  r%d, r%d, r%d (0x%s = 0x%s ^ 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 05 and
print "and  r%d, r%d, r%d (0x%s = 0x%s && 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

#13 shld
print "shld r%d, r%d, %d (0x%s = 0x%s << %d)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(cpu.ymm1[::-1]),
    ida_bytes.get_byte(cpu.ebp + 0)
)

# 05 or
print "or  r%d, r%d, r%d (0x%s = 0x%s || 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 16 cmp
print "vpcmpeqb r%d, r%d, r%d (0x%s = 0x%s eq 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 0B addd
print "addd r%d, r%d, r%d (0x%s = 0x%s + 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 07 addb
print "addb r%d, r%d, r%d (0x%s = 0x%s + 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 14 shuf
print "shuf r%d, r%d, r%d (0x%s = 0x%s <-> 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 01 vpmaddubsw - Multiply and Add Packed Signed and Unsigned Bytes
print "madb r%d, r%d, r%d (0x%s = 0x%s *+ 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

# 02 vpmaddwd - Multiply and Add Packed Integers
print "madw r%d, r%d, r%d (0x%s = 0x%s *+ 0x%s)" % (
    ida_bytes.get_byte(cpu.ebp + 2),
    ida_bytes.get_byte(cpu.ebp + 1),
    ida_bytes.get_byte(cpu.ebp + 0),
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)


# 00 Zero reg
print "mov r%d, 0" % (ida_bytes.get_byte(cpu.ebp + 0))

# print ip @ 000000013F371904
sys.stdout.write("0x%04X: " % (cpu.eax))

# Validate flag:
print "exit"
print
print "Validating flag:"
print "cmpb ymm0, r%d, r%d (0x%s = 0x%s eq 0x%s)" % (
    cpu.rcx / 32,
    cpu.rax / 32,
    binascii.hexlify(cpu.ymm0[::-1]),
    binascii.hexlify(get_bytes(cpu.rdx+cpu.rcx+0x800, 32)[::-1]),
    binascii.hexlify(get_bytes(cpu.r8+cpu.rax+0x800, 32)[::-1])
)

