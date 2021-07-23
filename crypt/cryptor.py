#!/usr/bin/python3
import pefile
from sys import argv, stdout
import os
import mmap
from keystone import *
import struct
import argparse

KEY = 0x77

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("exe", type=str, help="target program")
arg_parser.add_argument('--range', dest="range", action='append', help='manual encryption range')
arg_parser.add_argument('--ranges', dest="ranges", nargs='+', help='manual encryption range')
args = arg_parser.parse_args(argv[1:])
ranges = args.ranges or args.range

def disable_aslr(pe):
	if int(pe.OPTIONAL_HEADER.DllCharacteristics) & 0x40:
		print("[+] disabling ASLR")
		pe.OPTIONAL_HEADER.DllCharacteristics = int(pe.OPTIONAL_HEADER.DllCharacteristics) ^ 0x40

def cui(pe):
	if int(pe.OPTIONAL_HEADER.Subsystem) != 3:
		print("[+] enable CUI Subsystem")
		pe.OPTIONAL_HEADER.Subsystem = 3

def get_qwords_size(addr):
	i = 0
	while True:
		if pe.get_qword_at_rva(addr+i) == 0:
			break
		i += 8
	return i

def get_dwords_size(addr):
	i = 0
	while True:
		if pe.get_dword_at_rva(addr+i) == 0:
			break
		i += 4
	return i

def get_string_size(addr):
	return len(pe.get_string_at_rva(addr).decode())

def resources(pe):
	ranges = []
	data = []
	if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
		for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
			for entry in resource.directory.entries:
				for subentry in entry.directory.entries:
					data.extend(range(subentry.data.struct.OffsetToData, subentry.data.struct.OffsetToData+subentry.data.struct.Size))
		res = pe.get_rva_from_offset(pe.DIRECTORY_ENTRY_RESOURCE.struct.dump_dict()['Characteristics']['Offset'])
		for section in pe.sections:
			if section.VirtualAddress < res < section.VirtualAddress + section.SizeOfRawData:
				ranges = set(range(section.VirtualAddress,section.VirtualAddress+section.SizeOfRawData)) ^ set(data)
				break
	return list(ranges)

def delayed_imports(pe):
	ranges = []
	if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
		for lib in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
			dll = lib.struct.szName
			iat = lib.struct.pIAT
			_int = lib.struct.pINT
			if is_x64(pe):
				ranges.extend(range(dll, dll+get_string_size(dll)+2))
				ranges.extend(range(iat, iat+get_qwords_size(iat)+2))
				ranges.extend(range(_int, _int+get_qwords_size(_int)+2))
			else:
				ranges.extend(range(dll, dll+get_string_size(dll)+2))
				ranges.extend(range(iat, iat+get_dwords_size(iat)+2))
				ranges.extend(range(_int, _int+get_dwords_size(_int)+2))
			for func in lib.imports:
				ranges.extend(range(func.struct_table.ForwarderString, \
					func.struct_table.ForwarderString+get_string_size(func.struct_table.ForwarderString+2)+3))
	return ranges

def imports(pe):
	ranges = []
	if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
		for lib in pe.DIRECTORY_ENTRY_IMPORT:
			ilt = lib.struct.OriginalFirstThunk
			dll = lib.struct.Name
			itd = lib.struct.FirstThunk
			if is_x64(pe):
				ranges.extend(range(ilt, ilt+get_qwords_size(ilt)+2))
				ranges.extend(range(dll, dll+get_string_size(dll)+2))
				ranges.extend(range(itd, itd+get_qwords_size(itd)+2))
			else:
				ranges.extend(range(ilt, ilt+get_dwords_size(ilt)+2))
				ranges.extend(range(dll, dll+get_string_size(dll)+2))
				ranges.extend(range(itd, itd+get_dwords_size(itd)+2))
			for func in lib.imports:
				ranges.extend(range(func.struct_table.ForwarderString, \
					func.struct_table.ForwarderString+get_string_size(func.struct_table.ForwarderString+2)+3))
	return ranges

def crypt(pe, key, ignore_ranges):
	crypt_ranges = []
	crypt_sections = set()
	PAD = 0x10
	for section in pe.sections:
		#if str(section.Name.strip(),"utf-8").find(".rsrc")!=-1:
		#	continue
		section_name = str(section.Name.strip(),"utf-8")
		addr = section.VirtualAddress
		end = section.VirtualAddress + section.SizeOfRawData
		encrypt = {}
		c = 0
		for byte in section.get_data():
			if not addr in ignore_ranges and addr < end-1:
				encrypt[addr] = byte
				stdout.write("[*] analysis section %s: 0x%08x\r" % (section_name, pe.OPTIONAL_HEADER.ImageBase+addr)); stdout.flush()
			else:
				if len(encrypt) >= PAD:
					for crypt_addr,crypt_byte in encrypt.items():
						stdout.write("[*] crypt section %s 0x%08x: 0x%02x ^ 0x%02x\r" % (section_name, pe.OPTIONAL_HEADER.ImageBase+crypt_addr, crypt_byte, key)); stdout.flush()
						pe.set_bytes_at_rva(crypt_addr, (crypt_byte ^ key).to_bytes(1,'little'))
						#pe.set_bytes_at_rva(crypt_addr, b'\x11')
						c += 1
					crypt_ranges.append([min(encrypt), max(encrypt)])
					crypt_sections.add(str(section.Name,"utf-8").strip())
				encrypt = {}
			addr += 1
		print(f"[+] crypted section {section_name} {c} bytes" + " "*20)
	return crypt_sections,crypt_ranges

def crypt_range(pe, key, _range):
    section_name = get_section(pe, _range[0])
    encrypt = {}
    addr = _range[0]
    for byte in pe.get_data(_range[0], _range[1]-_range[0]):
        encrypt[addr] = byte
        addr += 1
    for crypt_addr,crypt_byte in encrypt.items():
        stdout.write("[*] crypt section %s 0x%08x: 0x%02x ^ 0x%02x\r" % (section_name, pe.OPTIONAL_HEADER.ImageBase+crypt_addr, crypt_byte, key)); stdout.flush()
        pe.set_bytes_at_rva(crypt_addr, (crypt_byte ^ key).to_bytes(1,'little'))
    return section_name

def patch_IAT(pe):
    LoadLibraryA = []
    GetProcAddress = []
    for lib in pe.DIRECTORY_ENTRY_IMPORT:
        if lib.dll.lower() == b'kernel32.dll':
            for func in lib.imports:
                if not LoadLibraryA and len(func.name) == len("LoadLibraryA"):
                    LoadLibraryA = [func.address, func.name]
                    pe.set_bytes_at_rva(func.struct_table.Function+2, b"LoadLibraryA")
                    print(f"[+] IAT {hex(func.address)}: {func.name} -> LoadLibraryA")
                elif not GetProcAddress and len(func.name) == len("GetProcAddress"):
                    GetProcAddress = [func.address, func.name]
                    pe.set_bytes_at_rva(func.struct_table.Function+2, b"GetProcAddress")
                    print(f"[+] IAT {hex(func.address)}: {func.name} -> GetProcAddress")
    if not LoadLibraryA or not GetProcAddress:
        print("[!] IAT not found appropriate function")
        exit()
    return [LoadLibraryA, GetProcAddress]

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
    
    return section.SizeOfRawData

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

def get_section(pe, addr):
    for section in pe.sections:
        if section.VirtualAddress <= addr <= section.VirtualAddress + section.SizeOfRawData:
            return str(section.Name,"utf-8").strip()

addr = 0
def write_bytes(pe, _bytes):
    global addr
    pe.set_bytes_at_rva(addr, _bytes)
    addr += len(_bytes)

def write_instruction(pe, instruction):
    (opcode,_) = instruction
    write_bytes(pe, bytes(opcode))

def get_last_section(pe):
    for section in pe.sections:
        pass
    return section

def insert_decrypt_code32(exe, crypt_ranges, iat, section_size, orig_bytes):
    global addr
    pe = pefile.PE(exe)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    LoadLibraryA_PTR, overwritten_func1 = iat[0]
    GetProcAddress_PTR, overwritten_func2 = iat[1]

    LoadLibraryA = section_size - 0x400
    GetProcAddress = section_size - 0x404
    gets = section_size - 0x408
    hModule = section_size - 0x450
    key = section_size - 0x454
    stack = section_size - 0x490

    inject_section = get_last_section(pe)
    print("[*] inject section: %s 0x%x" % (inject_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress))

    addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    write_instruction(pe, ks.asm( "jmp 0x%x" % (inject_section.VirtualAddress-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ) )

    addr = inject_section.VirtualAddress
    write_instruction(pe, ks.asm("pushal") )
    write_instruction(pe, ks.asm("pushfd") )
    write_instruction(pe, ks.asm(f"mov eax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+stack}") )
    write_instruction(pe, ks.asm("push esp") )
    write_instruction(pe, ks.asm("pop edx") )
    write_instruction(pe, ks.asm("mov [eax], edx") )

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

    string = b"msvcrt.dll\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpLibFileName
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
    write_instruction(pe, ks.asm("call eax")) # LoadLibraryA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}], eax")) # hModule

    string = b"gets\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm("push edx")) # lpProcName
    write_instruction(pe, ks.asm(f"push [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}]")) # hModule
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call eax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+gets}], eax"))

    write_instruction(pe, ks.asm("push eax"))
    write_instruction(pe, ks.asm("push esp"))
    write_instruction(pe, ks.asm(f"mov eax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+gets}]"))
    write_instruction(pe, ks.asm("call eax"))
    write_instruction(pe, ks.asm("add esp, 4"))
    write_instruction(pe, ks.asm("pop edx"))
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+key}], edx"))

    for (start,end) in crypt_ranges:
    	write_instruction(pe, ks.asm(f"mov ecx, {end-start}"))
    	write_instruction(pe, ks.asm(f"mov ebx, {pe.OPTIONAL_HEADER.ImageBase+start}"))
    	write_instruction(pe, ks.asm(f"mov edx, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+key}]"))
    	a = addr
    	write_instruction(pe, ks.asm("xor byte ptr[ebx], dl"))
    	write_instruction(pe, ks.asm("inc ebx"))
    	write_instruction(pe, ks.asm(f"loop {a-addr}"))

    a = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for i in range(0,len(orig_bytes),4):
        write_instruction(pe, ks.asm(f"mov eax, {pe.OPTIONAL_HEADER.ImageBase+a}"))
        write_instruction(pe, ks.asm("mov dword ptr[eax], 0x%08x" % struct.unpack('<I', orig_bytes[i:i+4])[0]) )
        a += 4

    write_instruction(pe, ks.asm(f"mov eax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+stack}") )
    write_instruction(pe, ks.asm("mov esp, [eax]") )
    write_instruction(pe, ks.asm("popfd") )
    write_instruction(pe, ks.asm("popal") )

    write_instruction(pe, ks.asm( "jmp -0x%x" % (addr-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ) )

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(exe)

def insert_decrypt_code64(exe, crypt_ranges, iat, section_size, orig_bytes):
    global addr
    pe = pefile.PE(exe)
    ks = Ks(KS_ARCH_X86, KS_MODE_64)

    LoadLibraryA_PTR, overwritten_func1 = iat[0]
    GetProcAddress_PTR, overwritten_func2 = iat[1]

    LoadLibraryA = section_size - 0x400
    GetProcAddress = section_size - 0x408
    gets = section_size - 0x410
    hModule = section_size - 0x450
    key = section_size - 0x458
    stack = section_size - 0x490

    inject_section = get_last_section(pe)
    print("[*] inject section: %s 0x%x" % (inject_section.Name.strip(), pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress))

    addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    write_instruction(pe, ks.asm( "jmp 0x%x" % (inject_section.VirtualAddress-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ) )

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
    write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+stack}"))
    write_instruction(pe, ks.asm("push rsp"))
    write_instruction(pe, ks.asm("pop rdx"))
    write_instruction(pe, ks.asm("mov [rax], rdx"))

    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rax"))

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

    string = b"msvcrt.dll\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rcx")) # lpLibFileName
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+LoadLibraryA}]"))
    write_instruction(pe, ks.asm("call rax")) # LoadLibraryA()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}], rax")) # hModule

    string = b"gets\x00"
    write_instruction(pe, ks.asm(f"call +{5+len(string)}"))
    write_bytes(pe, string)
    write_instruction(pe, ks.asm("pop rdx")) # lpProcName
    write_instruction(pe, ks.asm(f"mov rcx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+hModule}")) # hModule
    write_instruction(pe, ks.asm("mov rcx, [rcx]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+GetProcAddress}]"))
    write_instruction(pe, ks.asm("call rax")) # GetProcAddress()
    write_instruction(pe, ks.asm(f"mov [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+gets}], rax"))

    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("push rax"))
    write_instruction(pe, ks.asm("lea rcx, [rsp+0x10]"))
    write_instruction(pe, ks.asm(f"mov rax, [{pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+gets}]"))
    write_instruction(pe, ks.asm("call rax"))
    write_instruction(pe, ks.asm("pop rax"))
    write_instruction(pe, ks.asm("pop rax"))
    write_instruction(pe, ks.asm("pop rdx"))
    write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+key}"))
    write_instruction(pe, ks.asm("mov [rax], rdx"))

    for (start,end) in crypt_ranges:
        write_instruction(pe, ks.asm(f"mov rcx, {end-start}"))
        write_instruction(pe, ks.asm(f"mov rbx, {pe.OPTIONAL_HEADER.ImageBase+start}"))
        write_instruction(pe, ks.asm(f"mov rdx, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+key}"))
        write_instruction(pe, ks.asm(f"mov rdx, [rdx]"))
        a = addr
        write_instruction(pe, ks.asm("xor byte ptr[rbx], dl"))
        write_instruction(pe, ks.asm("inc rbx"))
        write_instruction(pe, ks.asm(f"loop {a-addr}"))

    a = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for i in range(0,len(orig_bytes),4):
        write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+a}"))
        write_instruction(pe, ks.asm("mov dword ptr[rax], 0x%08x" % struct.unpack('<I', orig_bytes[i:i+4])[0]) )
        a += 4

    write_instruction(pe, ks.asm(f"mov rax, {pe.OPTIONAL_HEADER.ImageBase+inject_section.VirtualAddress+stack}"))
    write_instruction(pe, ks.asm("mov rsp, [rax]"))
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

    write_instruction(pe, ks.asm( "jmp -0x%x" % (addr-pe.OPTIONAL_HEADER.AddressOfEntryPoint) ))

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(exe)

def is_x64(pe):
	if pe.NT_HEADERS.FILE_HEADER.Machine == 0x014c:
		return False
	elif pe.NT_HEADERS.FILE_HEADER.Machine == 0x8664:
		return True

def parse_range(pe, arg):
    if arg.find("-") != -1:
        try:    return [int(arg.split("-")[0])-pe.OPTIONAL_HEADER.ImageBase, int(arg.split("-")[1])-pe.OPTIONAL_HEADER.ImageBase]
        except: return [int(arg.split("-")[0],16)-pe.OPTIONAL_HEADER.ImageBase, int(arg.split("-")[1],16)-pe.OPTIONAL_HEADER.ImageBase]
    elif arg.find(",") != -1:
        try:    return [int(arg.split(",")[0])-pe.OPTIONAL_HEADER.ImageBase, int(arg.split(",")[0])+int(arg.split(",")[1])-pe.OPTIONAL_HEADER.ImageBase]
        except: return [int(arg.split(",")[0],16)-pe.OPTIONAL_HEADER.ImageBase, int(arg.split(",")[0],16)+int(arg.split(",")[1],16)-pe.OPTIONAL_HEADER.ImageBase]

pe = pefile.PE(args.exe)
pe.FileInfo=[]
orig_bytes = pe.get_data(pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x20)
if not ranges:
    ch_perm_sections,crypt_ranges = crypt(pe, KEY, ignore_ranges=imports(pe)+delayed_imports(pe)+resources(pe))
else:
    ch_perm_sections = set([])
    crypt_ranges = []
    for _range in ranges:
        _range = parse_range(pe, _range)
        section_name = crypt_range(pe, KEY, _range)
        crypt_ranges.append(_range)
        ch_perm_sections.add(section_name)
    ch_perm_sections.add(get_section(pe,pe.OPTIONAL_HEADER.AddressOfEntryPoint))
iat = patch_IAT(pe)
ch_perm_sections.add(get_section(pe,iat[0][0]-pe.OPTIONAL_HEADER.ImageBase))
disable_aslr(pe)
cui(pe)
print("[*] %d crypted ranges" % len(crypt_ranges))
pe.write(args.exe)

section_size = add_section(args.exe, ".upx", 0x1000+len(crypt_ranges)*0x21, "rwx")
for section_name in ch_perm_sections:
    chg_section(args.exe, section_name, "w")
if is_x64(pe):
    insert_decrypt_code64(args.exe, crypt_ranges, iat, section_size, orig_bytes)
else:
	insert_decrypt_code32(args.exe, crypt_ranges, iat, section_size, orig_bytes)
