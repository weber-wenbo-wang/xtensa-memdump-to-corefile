#!/usr/bin/python
import argparse
import pdb

# ELF Standard Constants
ELF_HDR_SIZE = 0x34

PHDR_TYPE_OFF = 0
PHDR_OFFSET_OFF = 4
PHDR_PADDR_OFF = 12
PHDR_FILESZ_OFF = 16
PHDR_MEMSZ_OFF = 20
PHDR_FLAGS_OFF = 24
PHDR_ALIGN_OFF = 28

PHDR_FLAG_READ = 0x04
PHDR_FLAG_WRITE = 0x02
PHDR_FLAG_EXE = 0x01

# ELF header types
PT_NOTE = 4

NT_PRSTATUS = 1

NOTE_NAMESZ_OFF = 0
NOTE_DESCSZ_OFF = 4
NOTE_TYPE_OFF = 8
NOTE_NAME_OFF = 12



# XTENSA specific constants 
# DMEM is 64K
DMEM_SIZE = 64 * 1024

def byte2num(a, s, l):
    num = 0
    for i in range(s+l-1, s-1, -1):
        num += a[i]
        if i != s:
            num <<= 8

    return num

def num2byte(a, s, l, n):
    for i in range(s, s+l):
        a[i] = n & 0xff
        n = n >> 8

# Push DMEM data 
EXTRA_HEADER_OFFSET = 0x2000

def assemble_core(felf, fdram, fcore):
    # Load ELF header
    hdr = bytearray(ELF_HDR_SIZE)
    hdr[:] = felf.read(ELF_HDR_SIZE)

    # Type = CORE
    hdr[0x10] = 0x04
    hdr[0x11] = 0x00

    # Remove Section Header
    num2byte(hdr, 0x20, 4, 0)
    num2byte(hdr, 0x2e, 2, 0)
    num2byte(hdr, 0x30, 2, 0)

    e_phoff = byte2num(hdr, 0x1c, 4)
    e_phentsize = byte2num(hdr, 0x2a, 2)
    e_phnum = byte2num(hdr, 0x2c, 2)

    # Add NOTE section
    e_core_phnum = e_phnum + 1
    num2byte(hdr, 0x2c, 2, e_core_phnum)

    fcore.write(hdr)

    assert(e_phoff >= ELF_HDR_SIZE)

    # pading
    for i in range(e_phoff - ELF_HDR_SIZE):
        fcore.write(0x00)


    # Load program header
    phdr = bytearray(e_phentsize * e_core_phnum)
    felf.seek(e_phoff)
    phdr[:] = felf.read(e_phentsize * e_core_phnum)

    dram_section_off = 0

    for i in range(e_phnum):
        ent = i * e_phentsize

        p_paddr = byte2num(phdr, ent + PHDR_PADDR_OFF, 4)
        p_flags = byte2num(phdr, ent + PHDR_FLAGS_OFF, 4)
        p_offset = byte2num(phdr, ent + PHDR_OFFSET_OFF, 4)

        if (p_paddr == 0x7ff80000) and (p_flags == (PHDR_FLAG_READ | PHDR_FLAG_WRITE)):
            # This is the section representing the DMEM
            dram_section_off = byte2num(phdr, ent + PHDR_OFFSET_OFF, 4)

            num2byte(phdr, ent + PHDR_FILESZ_OFF, 4, DMEM_SIZE)
            num2byte(phdr, ent + PHDR_MEMSZ_OFF, 4, DMEM_SIZE)

        elif p_flags == (PHDR_FLAG_READ | PHDR_FLAG_WRITE):
            # Memory size of any other RW section shall be tuncated to zero
            num2byte(phdr, ent + PHDR_MEMSZ_OFF, 4, 0)

        # Revise offset in file
        num2byte(phdr, ent + PHDR_OFFSET_OFF, 4, p_offset + EXTRA_HEADER_OFFSET)

    if not dram_section_off:
        print("Cannot find section inside program header with start address 0x7ff80000")
        assert(0)

    # Get more space between phdr and DMEM area
    dram_section_off += EXTRA_HEADER_OFFSET

    # Create NOTE section
    NOTE_NAMESZ = 8   # len('CORE')+4
    ent = e_phnum * e_phentsize
    prstatus_size = 1124
    note_size = NOTE_NAME_OFF + NOTE_NAMESZ + prstatus_size
    note_offset = fcore.tell() + e_core_phnum * e_phentsize + 32
    note = bytearray(note_size)

    num2byte(note, NOTE_NAMESZ_OFF, 4, NOTE_NAMESZ)
    num2byte(note, NOTE_DESCSZ_OFF, 4, prstatus_size)
    num2byte(note, NOTE_TYPE_OFF, 4, NT_PRSTATUS)
    note[NOTE_NAME_OFF:NOTE_NAME_OFF+4] = 'CORE'

    # why 0x410 - 0x3c8, this is a myth
    regset_addr = NOTE_NAME_OFF + NOTE_NAMESZ + (0x410 - 0x3c8)

    pc_addr = regset_addr
    note[pc_addr] = 0x3

    '''
    pdb.set_trace()
    index = 0
    start = NOTE_NAME_OFF + 8
    while start < note_size-1:
        note[start] = index % 256
        note[start+1] = index / 256
        index += 1
        start += 2
    '''

    num2byte(phdr, ent + PHDR_TYPE_OFF, 4, PT_NOTE)
    num2byte(phdr, ent + PHDR_OFFSET_OFF, 4, note_offset)
    num2byte(phdr, ent + PHDR_PADDR_OFF, 4, 0)
    num2byte(phdr, ent + PHDR_FILESZ_OFF, 4, note_size)
    num2byte(phdr, ent + PHDR_MEMSZ_OFF, 4, 0)
    num2byte(phdr, ent + PHDR_FLAGS_OFF, 4, 0)
    num2byte(phdr, ent + PHDR_ALIGN_OFF, 4, 0x1)

    fcore.write(phdr)

    print("After phdr: {0:d}".format(fcore.tell()))

    fcore.truncate(note_offset+ 1)
    fcore.seek(note_offset)

    fcore.write(note)

    # pading and move to the end
    fcore.truncate(dram_section_off + 1)
    fcore.seek(dram_section_off)

    print("DMEM start: {0:d}".format(dram_section_off))

    # Append DRAM image
    fcore.write(fdram.read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--core", type=str, required = True, help="core image dumped")
    parser.add_argument("-e", "--elf", type=str, required = True, help="ELF file")

    args = parser.parse_args()

    elf_file_name = args.elf
    dram_file_name = args.core
    core_file_name = "core.bin"

    felf = open(elf_file_name, "rb")
    fdram = open(dram_file_name, "rb")
    fcore = open(core_file_name, "wb+")

    assemble_core(felf, fdram, fcore)
    print("core.bin has been assembled, run xtensa-gdb NODE??.elf core.bin to analayze")

    felf.close()
    fdram.close()
    fcore.close()
