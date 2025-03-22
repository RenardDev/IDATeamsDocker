from dataclasses import dataclass
import ctypes
import mmap
import struct

# ------------------ PE Constants ------------------

IMAGE_DOS_SIGNATURE = b'MZ'
IMAGE_NT_SIGNATURE = b'PE\x00\x00'
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

# ------------------ ELF Constants ------------------

ELF_MAGIC = b'\x7FELF'
ELFCLASS32 = 1
ELFCLASS64 = 2
PT_LOAD = 1

# ------------------ PE Structures ------------------

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', ctypes.c_ushort),
        ('e_cblp', ctypes.c_ushort),
        ('e_cp', ctypes.c_ushort),
        ('e_crlc', ctypes.c_ushort),
        ('e_cparhdr', ctypes.c_ushort),
        ('e_minalloc', ctypes.c_ushort),
        ('e_maxalloc', ctypes.c_ushort),
        ('e_ss', ctypes.c_ushort),
        ('e_sp', ctypes.c_ushort),
        ('e_csum', ctypes.c_ushort),
        ('e_ip', ctypes.c_ushort),
        ('e_cs', ctypes.c_ushort),
        ('e_lfarlc', ctypes.c_ushort),
        ('e_ovno', ctypes.c_ushort),
        ('e_res', ctypes.c_ushort * 4),
        ('e_oemid', ctypes.c_ushort),
        ('e_oeminfo', ctypes.c_ushort),
        ('e_res2', ctypes.c_ushort * 10),
        ('e_lfanew', ctypes.c_int32)
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', ctypes.c_ushort),
        ('NumberOfSections', ctypes.c_ushort),
        ('TimeDateStamp', ctypes.c_uint32),
        ('PointerToSymbolTable', ctypes.c_uint32),
        ('NumberOfSymbols', ctypes.c_uint32),
        ('SizeOfOptionalHeader', ctypes.c_ushort),
        ('Characteristics', ctypes.c_ushort)
    ]

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ('Magic', ctypes.c_ushort),
        ('MajorLinkerVersion', ctypes.c_ubyte),
        ('MinorLinkerVersion', ctypes.c_ubyte),
        ('SizeOfCode', ctypes.c_uint32),
        ('SizeOfInitializedData', ctypes.c_uint32),
        ('SizeOfUninitializedData', ctypes.c_uint32),
        ('AddressOfEntryPoint', ctypes.c_uint32),
        ('BaseOfCode', ctypes.c_uint32),
        ('BaseOfData', ctypes.c_uint32),
        ('ImageBase', ctypes.c_uint32),
        ('SectionAlignment', ctypes.c_uint32),
        ('FileAlignment', ctypes.c_uint32),
        ('MajorOperatingSystemVersion', ctypes.c_ushort),
        ('MinorOperatingSystemVersion', ctypes.c_ushort),
        ('MajorImageVersion', ctypes.c_ushort),
        ('MinorImageVersion', ctypes.c_ushort),
        ('MajorSubsystemVersion', ctypes.c_ushort),
        ('MinorSubsystemVersion', ctypes.c_ushort),
        ('Win32VersionValue', ctypes.c_uint32),
        ('SizeOfImage', ctypes.c_uint32),
        ('SizeOfHeaders', ctypes.c_uint32),
        ('CheckSum', ctypes.c_uint32),
        ('Subsystem', ctypes.c_ushort),
        ('DllCharacteristics', ctypes.c_ushort),
        ('SizeOfStackReserve', ctypes.c_uint32),
        ('SizeOfStackCommit', ctypes.c_uint32),
        ('SizeOfHeapReserve', ctypes.c_uint32),
        ('SizeOfHeapCommit', ctypes.c_uint32),
        ('LoaderFlags', ctypes.c_uint32),
        ('NumberOfRvaAndSizes', ctypes.c_uint32)
    ]

class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
        ('Signature', ctypes.c_uint32),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32)
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic', ctypes.c_ushort),
        ('MajorLinkerVersion', ctypes.c_ubyte),
        ('MinorLinkerVersion', ctypes.c_ubyte),
        ('SizeOfCode', ctypes.c_uint32),
        ('SizeOfInitializedData', ctypes.c_uint32),
        ('SizeOfUninitializedData', ctypes.c_uint32),
        ('AddressOfEntryPoint', ctypes.c_uint32),
        ('BaseOfCode', ctypes.c_uint32),
        ('ImageBase', ctypes.c_uint64),
        ('SectionAlignment', ctypes.c_uint32),
        ('FileAlignment', ctypes.c_uint32),
        ('MajorOperatingSystemVersion', ctypes.c_ushort),
        ('MinorOperatingSystemVersion', ctypes.c_ushort),
        ('MajorImageVersion', ctypes.c_ushort),
        ('MinorImageVersion', ctypes.c_ushort),
        ('MajorSubsystemVersion', ctypes.c_ushort),
        ('MinorSubsystemVersion', ctypes.c_ushort),
        ('Win32VersionValue', ctypes.c_uint32),
        ('SizeOfImage', ctypes.c_uint32),
        ('SizeOfHeaders', ctypes.c_uint32),
        ('CheckSum', ctypes.c_uint32),
        ('Subsystem', ctypes.c_ushort),
        ('DllCharacteristics', ctypes.c_ushort),
        ('SizeOfStackReserve', ctypes.c_uint64),
        ('SizeOfStackCommit', ctypes.c_uint64),
        ('SizeOfHeapReserve', ctypes.c_uint64),
        ('SizeOfHeapCommit', ctypes.c_uint64),
        ('LoaderFlags', ctypes.c_uint32),
        ('NumberOfRvaAndSizes', ctypes.c_uint32)
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ('Signature', ctypes.c_uint32),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64)
    ]

class IMAGE_SECTION_HEADER(ctypes.Structure):
    _fields_ = [
        ('Name', ctypes.c_char * 8),
        ('Misc', ctypes.c_uint32),
        ('VirtualAddress', ctypes.c_uint32),
        ('SizeOfRawData', ctypes.c_uint32),
        ('PointerToRawData', ctypes.c_uint32),
        ('PointerToRelocations', ctypes.c_uint32),
        ('PointerToLinenumbers', ctypes.c_uint32),
        ('NumberOfRelocations', ctypes.c_ushort),
        ('NumberOfLinenumbers', ctypes.c_ushort),
        ('Characteristics', ctypes.c_uint32)
    ]

# ------------------ ELF Structures ------------------

class Elf32_Ehdr(ctypes.Structure):
    _fields_ = [
        ('e_ident', ctypes.c_char * 16),
        ('e_type', ctypes.c_ushort),
        ('e_machine', ctypes.c_ushort),
        ('e_version', ctypes.c_uint32),
        ('e_entry', ctypes.c_uint32),
        ('e_phoff', ctypes.c_uint32),
        ('e_shoff', ctypes.c_uint32),
        ('e_flags', ctypes.c_uint32),
        ('e_ehsize', ctypes.c_ushort),
        ('e_phentsize', ctypes.c_ushort),
        ('e_phnum', ctypes.c_ushort),
        ('e_shentsize', ctypes.c_ushort),
        ('e_shnum', ctypes.c_ushort),
        ('e_shstrndx', ctypes.c_ushort)
    ]

class Elf64_Ehdr(ctypes.Structure):
    _fields_ = [
        ('e_ident', ctypes.c_char * 16),
        ('e_type', ctypes.c_ushort),
        ('e_machine', ctypes.c_ushort),
        ('e_version', ctypes.c_uint32),
        ('e_entry', ctypes.c_uint64),
        ('e_phoff', ctypes.c_uint64),
        ('e_shoff', ctypes.c_uint64),
        ('e_flags', ctypes.c_uint32),
        ('e_ehsize', ctypes.c_ushort),
        ('e_phentsize', ctypes.c_ushort),
        ('e_phnum', ctypes.c_ushort),
        ('e_shentsize', ctypes.c_ushort),
        ('e_shnum', ctypes.c_ushort),
        ('e_shstrndx', ctypes.c_ushort)
    ]

class Elf32_Phdr(ctypes.Structure):
    _fields_ = [
        ('p_type', ctypes.c_uint32),
        ('p_offset', ctypes.c_uint32),
        ('p_vaddr', ctypes.c_uint32),
        ('p_paddr', ctypes.c_uint32),
        ('p_filesz', ctypes.c_uint32),
        ('p_memsz', ctypes.c_uint32),
        ('p_flags', ctypes.c_uint32),
        ('p_align', ctypes.c_uint32)
    ]

class Elf64_Phdr(ctypes.Structure):
    _fields_ = [
        ('p_type', ctypes.c_uint32),
        ('p_flags', ctypes.c_uint32),
        ('p_offset', ctypes.c_uint64),
        ('p_vaddr', ctypes.c_uint64),
        ('p_paddr', ctypes.c_uint64),
        ('p_filesz', ctypes.c_uint64),
        ('p_memsz', ctypes.c_uint64),
        ('p_align', ctypes.c_uint64)
    ]

# ------------------ Section DataClasses ------------------

@dataclass
class ELF_Segment:
    type: int
    vaddr: int
    memsz: int
    filesz: int
    offset: int
    flags: int

@dataclass
class PE_Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int

# ------------------ ManualMapper Class ------------------

class ManualMapper:
    def __init__(self, file_path):
        self.file_path = file_path
        self.raw_data = bytearray()
        self.memory = None
        self.base_address = 0
        self.image_size = 0
        self.sections = []
        self.is_pe = False
        self.is_elf = False
        self.image_base = 0

        self.page_size = 0x1000 # By default, 4KB page size

        with open(file_path, 'rb') as f:
            self.raw_data = bytearray(f.read())
    
    def load(self):
        if self.raw_data[:2] == IMAGE_DOS_SIGNATURE:
            self._map_pe()

        elif self.raw_data[:4] == ELF_MAGIC:
            self._map_elf()

        else:
            raise ValueError('Unsupported file format')

    # --------- PE Mapping Implementation ---------
    
    def _map_pe(self):
        self.is_pe = True

        dos_header = IMAGE_DOS_HEADER.from_buffer_copy(self.raw_data)

        nt_header_offset = dos_header.e_lfanew
        signature = self.raw_data[nt_header_offset:nt_header_offset + 4]
        if signature != IMAGE_NT_SIGNATURE:
            raise ValueError('Invalid PE signature')
        
        magic = ctypes.c_ushort.from_buffer_copy(self.raw_data, nt_header_offset + 4 + ctypes.sizeof(IMAGE_FILE_HEADER)).value
        if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            nt_headers = IMAGE_NT_HEADERS32.from_buffer_copy(self.raw_data[nt_header_offset:])
            optional_header = nt_headers.OptionalHeader
            self.image_base = optional_header.ImageBase

        elif magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            nt_headers = IMAGE_NT_HEADERS64.from_buffer_copy(self.raw_data[nt_header_offset:])
            optional_header = nt_headers.OptionalHeader
            self.image_base = optional_header.ImageBase

        else:
            raise ValueError('Unknown PE Optional Header Magic: 0x{:X}'.format(magic))
        
        self.image_size = (optional_header.SizeOfImage + self.page_size - 1) & ~(self.page_size - 1)

        self.memory = mmap.mmap(-1, self.image_size, access=mmap.ACCESS_WRITE)
        self.base_address = ctypes.addressof(ctypes.c_void_p.from_buffer(self.memory))
        
        # Copy headers
        size_of_headers = optional_header.SizeOfHeaders
        self.memory[0:size_of_headers] = self.raw_data[0:size_of_headers]
        
        # Read section headers
        num_sections = nt_headers.FileHeader.NumberOfSections

        # Section headers start immediately after NT header (4 + sizeof(IMAGE_FILE_HEADER) + SizeOfOptionalHeader)
        section_offset = nt_header_offset + 4 + ctypes.sizeof(IMAGE_FILE_HEADER) + nt_headers.FileHeader.SizeOfOptionalHeader
        
        section_header_size = ctypes.sizeof(IMAGE_SECTION_HEADER)
        for i in range(num_sections):
            offset = section_offset + i * section_header_size
            section = IMAGE_SECTION_HEADER.from_buffer_copy(self.raw_data[offset:])

            # Copy section data to allocated memory
            virt_addr = section.VirtualAddress
            virt_size = section.Misc
            raw_addr = section.PointerToRawData
            raw_size = section.SizeOfRawData

            if raw_size > 0:
                self.memory[virt_addr:virt_addr + raw_size] = self.raw_data[raw_addr:raw_addr + raw_size]

            # Zero out the remainder if VirtualSize > raw_size
            if virt_size > raw_size:
                self.memory[virt_addr + raw_size:virt_addr + virt_size] = b'\x00' * (virt_size - raw_size)

            self.sections.append(PE_Section(
                name=section.name.decode('utf-8', errors='ignore').rstrip('\x00'),
                virtual_address=virt_addr,
                virtual_size=virt_size,
                raw_address=raw_addr,
                raw_size=raw_size,
                characteristics=section.Characteristics
            ))

    # --------- ELF Mapping Implementation ---------

    def _map_elf(self):
        self.is_elf = True

        if self.raw_data[4] == ELFCLASS64:
            elf_header = Elf64_Ehdr.from_buffer_copy(self.raw_data)
            phdr_size = ctypes.sizeof(Elf64_Phdr)
            phdr_cls = Elf64_Phdr

        elif self.raw_data[4] == ELFCLASS32:
            elf_header = Elf32_Ehdr.from_buffer_copy(self.raw_data)
            phdr_size = ctypes.sizeof(Elf32_Phdr)
            phdr_cls = Elf32_Phdr

        else:
            raise ValueError('Invalid ELF class')

        mem_regions = []
        for i in range(elf_header.e_phnum):
            start = elf_header.e_phoff + i * phdr_size

            phdr = phdr_cls.from_buffer_copy(self.raw_data[start:])
            if phdr.p_type == PT_LOAD:
                mem_regions.append((phdr.p_vaddr, phdr.p_memsz, phdr.p_offset, phdr.p_filesz, phdr.p_flags))
        
        if not mem_regions:
            raise ValueError('No loadable segments found in ELF')

        max_addr = max(vaddr + memsz for vaddr, memsz, _, _, _ in mem_regions)
        self.image_size = (max_addr + self.page_size - 1) & ~(self.page_size - 1)

        self.memory = mmap.mmap(-1, self.image_size, access=mmap.ACCESS_WRITE)
        self.base_address = ctypes.addressof(ctypes.c_void_p.from_buffer(self.memory))

        for vaddr, memsz, offset, filesz, flags in mem_regions:
            if filesz > 0:
                data = self.raw_data[offset:offset + filesz]
                self.memory[vaddr:vaddr + filesz] = data

            if memsz > filesz:
                self.memory[vaddr + filesz:vaddr + memsz] = b'\x00' * (memsz - filesz)

            self.sections.append(ELF_Segment(
                type=PT_LOAD,
                vaddr=vaddr,
                memsz=memsz,
                filesz=filesz,
                offset=offset,
                flags=flags
            ))

    def modify(self, va: int, data: bytes):
        if self.is_pe:
            va -= self.image_base

        ctypes.memmove(self.base_address + va, data, len(data))

    def save(self, output_path: str):
        output = bytearray(self.raw_data)
        
        for sect in self.sections:
            if self.is_pe and isinstance(sect, PE_Section):
                data = bytes(self.memory[sect.virtual_address:sect.virtual_address + sect.raw_size])
                output[sect.raw_address:sect.raw_address + sect.raw_size] = data

            elif self.is_elf and isinstance(sect, ELF_Segment):
                data = bytes(self.memory[sect.vaddr:sect.vaddr + sect.filesz])
                output[sect.offset:sect.offset + sect.filesz] = data

        with open(output_path, 'wb') as f:
            f.write(output)

    def unmap(self):
        if self.memory:
            self.memory.close()
            self.memory = None
            self.base_address = 0

    def __del__(self):
        self.unmap()

# ------------------ Example Usage ------------------

def read_address(buffer, address, size, is_be = False):
    data = buffer[address:address + size]
    if size == 1:
        return struct.unpack('<b', data)[0] if not is_be else struct.unpack('>b', data)[0]
    elif size == 2:
        return struct.unpack('<h', data)[0] if not is_be else struct.unpack('>h', data)[0]
    elif size == 4:
        return struct.unpack('<i', data)[0] if not is_be else struct.unpack('>i', data)[0]
    elif size == 8:
        return struct.unpack('<q', data)[0] if not is_be else struct.unpack('>q', data)[0]
    return 0

def find_signature(buffer, size, signature, mask, pre_offset=0, offsets=[]):
    mask_bits = []
    for byte in mask:
        for i in range(8):
            mask_bits.append((byte >> (7 - i)) & 1)

    last_checked = max([i for i, bit in enumerate(mask_bits) if bit == 1], default=-1)
    if last_checked == -1:
        return 0

    mask_bits = mask_bits[:last_checked + 1]
    check_positions = [i for i, bit in enumerate(mask_bits) if bit]
    
    if len(signature) != len(check_positions):
        return 0

    for i in range(size - len(mask_bits) + 1):
        match = True
        for sig_idx, pos in enumerate(check_positions):
            if buffer[i + pos] != signature[sig_idx]:
                match = False
                break

        if match:
            address = i + pre_offset

            for inner_pre_offset, is_relative, insn_size, operand_offset, operand_size, offset in offsets:
                base = address + inner_pre_offset
                if is_relative:
                    value = read_address(buffer, base + operand_offset, operand_size)
                    address = base + insn_size + value + offset
                else:
                    value = read_address(buffer, base + operand_offset, operand_size)
                    address = value + offset

            return address

    return 0

#if __name__ == '__main__':
#    mapper = ManualMapper('..\\vault_server')
#    mapper.load()

#    address = find_signature(
#        mapper.memory, mapper.image_size,
#        ( 0xD2, 0x59, 0x5E, ),
#        ( 0b11100000, ),
#        -0x37,
#        (
#            ( 0x0, True, 0x2, 0x1, 0x1, 0x0 ),
#            ( 0x3e, True, 0x6, 0x2, 0x4, 0x0 ),
#            ( -0xb, True, 0x5, 0x1, 0x4, -0x22 )
#        )
#    )

#    print(f'{address:#x}')

#    mapper.save('modified.exe')
#    mapper.unmap()
