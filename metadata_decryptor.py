# Imports
import argparse
import os
import struct

from tqdm import tqdm
from colorama import Fore, Style, init
from elftools.elf.elffile import ELFFile

# Init colorama
init(autoreset=False)

# Set up argument parser
parser = argparse.ArgumentParser()

parser.add_argument("-s", action="store_true", help="Skip confirmation prompt", required=False)
parser.add_argument("-v", action="store_true", help="Verbose output", required=False)

# Define positional arguments for the files
parser.add_argument("--libunity", metavar="libunity", help="libunity.so file")
parser.add_argument("--output", metavar="output", help="Reference metadata file")

args = parser.parse_args()

confirmed = args.s

libunity_path: str = args.libunity
output_path: str = args.output

print(f"{Fore.CYAN}NOTE: Current working directory: {os.getcwd()}")

while (not confirmed or (not libunity_path and not output_path)):
    # libunity_path = args.libunity
    # output_path = args.output
    # Prompt the user to input missing file paths
    if not libunity_path and not confirmed:
        libunity_path = input(f"{Fore.CYAN}Input libunity.so file path: {Style.RESET_ALL}").replace("\"", "")
    if not output_path and not confirmed:
        output_path = input(f"{Fore.CYAN}Input decrypted metadata save path: {Style.RESET_ALL}").replace(
            "\"", "")

    # Check if libunity.so file path is valid
    if not os.path.isfile(libunity_path):
        print(f"{Fore.YELLOW}libunity.so file doesn't exist")
        libunity_path = ""
        continue

    elif open(libunity_path, "rb").read(4) != b'\x7fELF':
        bypass = input(f"{Fore.YELLOW}libunity.so file is not a valid ELF. Force continue? {Style.RESET_ALL}")
        if not bypass.lower() != "y" or not bool(bypass):
            continue

    print(f"{Fore.CYAN}Using next files:")
    print(f"    {Fore.CYAN}libunity.so - {Fore.LIGHTMAGENTA_EX + Style.BRIGHT + libunity_path + Style.RESET_ALL}")
    print(f"    {Fore.CYAN}Output - {Fore.LIGHTMAGENTA_EX + Style.BRIGHT + output_path + Style.RESET_ALL}")

    confirmed = input(f"{Fore.CYAN}Correct? {Style.RESET_ALL}").lower()[0] in ['1', 'y']
    if confirmed:
        print(f"{Fore.CYAN}Starting...")
        break

print(f"{Fore.CYAN}Starting search...")

# Open the file
libunity = open(libunity_path, "rb")
elf = ELFFile(libunity)
is64bit = elf.get_machine_arch() == "AArch64"

# Precompute LOAD segments once
load_segments = [
    (
        segment['p_vaddr'],
        segment['p_vaddr'] + segment['p_memsz'],
        segment['p_offset']
    )
    for segment in elf.iter_segments()
    if segment['p_type'] == 'PT_LOAD'
]

def map_vaddr_to_offset(va):
    for start, end, offset in load_segments:
        if start <= va < end:
            return va - start + offset

    print(f"{Fore.RED}Error: Virtual address {va} not found in any LOAD segment.")
    exit(-1)

# Get sections
data_section = elf.get_section_by_name(".data")
rodata_section = elf.get_section_by_name(".rodata")

print(f"{Fore.CYAN}Collecting and mapping relocation data...")

# Iterate over relocation sections
relocations = []
for section in elf.iter_sections():
    if section.header['sh_type'] not in ('SHT_REL', 'SHT_RELA'): continue
    print(f"{Fore.CYAN}Processing relocation section: {section.name}")
    total = section.header['sh_size'] // (24 if is64bit else 8)
    for relocation in tqdm(section.iter_relocations(), colour="green", unit="relocations", total=total): # type: ignore
        addr = relocation['r_offset']

        # Skip if not in the .data section
        if not data_section.header['sh_addr'] <= addr < data_section.header['sh_addr'] + data_section.header['sh_size']: # type: ignore
            continue

        if is64bit:
            pointer = relocation['r_addend']
        else:
            offset = map_vaddr_to_offset(addr)
            libunity.seek(offset)
            pointer = struct.unpack("<I", libunity.read(4))[0]
        
        if pointer != 0: relocations.append(pointer)

print(f"{Fore.CYAN}Iterating over relocations to find metadata pointer...")

candidates = []
for addr in tqdm(relocations, colour="green", unit="relocations"):
    libunity.seek(addr - 4)
    candidate = libunity.read(12)
    if candidate == b"\x81\x80\x80\x3B\0\0\0\0\0\0\0\0": # I hope these don't change
        candidates.append(addr)

# If more than 1 candidate is found, print a warning and continue
if len(candidates) == 0:
    print(f"{Fore.RED + Style.BRIGHT}Error: No candidate found.{Style.RESET_ALL}")
    exit()
elif len(candidates) == 1:
    metadataptr = candidates[0]
    print(f"{Fore.GREEN + Style.BRIGHT}Successfully found metadata pointer in the binary at {hex(metadataptr)}.{Style.RESET_ALL}")
else:
    print(f"{Fore.YELLOW + Style.BRIGHT}Warning: More than one candidate found. Continuing with the first one.{Style.RESET_ALL}")
    metadataptr = candidates[0]

# Extract the metadata bytes by reading from the binary until
# the start of an arbitrary amount of zeros or the end of the file.
libunity.seek(metadataptr)
metadata = libunity.read(50_000_000) # Read 50 megabytes, because the metadata is usually smaller than that.
index = metadata.find(b"\x00" * 256) # Find 256 bytes of zeros, which is usually the end of the metadata.
if index != -1:
    # Align index to 4-byte boundary.
    index += (4 - index % 4) % 4
    metadata = metadata[:index]
    print(f"{Fore.GREEN}Successfully found metadata end marker.")
    print(f"{Fore.GREEN}Metadata size: {len(metadata)} bytes.{Style.RESET_ALL}")
else:
    print(f"{Fore.RED + Style.BRIGHT}Error: Failed find the metadata end marker in the metadata.{Style.RESET_ALL}")

# Dump the intermediate metadata to a file for debugging purposes.
with open("intermediate_metadata.bin", "wb") as f:
    print(f"{Fore.CYAN}Dumping intermediate metadata to 'intermediate_metadata.bin' for debugging purposes.")
    f.write(metadata)

print(f"{Fore.CYAN}Starting decryption of the metadata...")

# Extract all fields except for magic and version.
fields = []
for i in range(8, 256, 4):
    fields.append(struct.unpack("<I", metadata[i:i+4])[0])

# Find all offsets in the metadata.
offset_candidates = []
for field in fields:
    if field % 4 == 0 and metadata[field-4:field] == b"\0\0\0\0":
        offset_candidates.append(field)

offset_candidates.sort()

print(f"{Fore.GREEN}Found {len(offset_candidates)} potential offsets.")

# Attempt to filter offsets
offsets_to_sizes: list[tuple[int, int]] = []
for possible_offset in offset_candidates:
    found = False

    # Skip duplicates
    for offset, size in offsets_to_sizes:
        if offset == possible_offset:
            found = True
            break
    if found:
        continue

    # Iterate in hopes of finding a size.
    for field in fields:
        found_field = False
        if field != possible_offset and field != 0 and field < len(metadata) / 3:
            # Iterate again to maybe find a matching offset.
            for next_offset in offset_candidates:
                for offset, size in offsets_to_sizes:
                    if offset == field:
                        found_field = True
                        break
                if found_field:
                    break
                if -4 <= field + possible_offset - next_offset <= 4 and possible_offset != next_offset:
                    offsets_to_sizes.append((possible_offset, field))
                    print(f"{Fore.CYAN}Offset {possible_offset} + {field} (={possible_offset + field}) is close to offset {next_offset}, adding it to the list of potential offsets.")
                    found = True
                    break
                elif -4 <= field + possible_offset - len(metadata) <= 4:
                    print(f"{Fore.CYAN}Hit the last offset {possible_offset} with size {field}, adding it to the list of potential offsets.")
                    offsets_to_sizes.append((possible_offset, field))
                    found = True
                    break
            if found:
                break
        else:
            continue
        if found_field:
            continue
        if found:
            break
    if not found and (possible_offset > len(metadata) / 2 or sum(offsets_to_sizes[-1]) == possible_offset - 4):
        print(f"{Fore.YELLOW}Offset {possible_offset} does not have a matching size, but it's a potential offset, precomputing size.")
        next_offset = offset_candidates[offset_candidates.index(possible_offset) + 1]
        offsets_to_sizes.append((possible_offset, next_offset - possible_offset - 4))
    elif not found:
        print(f"{Fore.YELLOW}Offset {possible_offset} does not have a matching size, skipping it.")

# Sort offsets to sizes by key
offsets_to_sizes = sorted(offsets_to_sizes, key=lambda item: item[0])

# If there are more or less than 29 offsets, something is wrong.
if len(offsets_to_sizes) == 29:
    print(f"{Fore.GREEN + Style.BRIGHT}Found 29 unique valid offsets in the metadata at: {offsets_to_sizes}.{Style.RESET_ALL}")
else:
    print(f"{Fore.YELLOW + Style.BRIGHT}Found {len(offsets_to_sizes)} offsets in the metadata at: {offsets_to_sizes}.{Style.RESET_ALL}")

print(f"{Fore.CYAN}Starting reconstruction using heuristic search...")

reconstructed_data = bytearray(b"\xAF\x1B\xB1\xFA\x1F\0\0\0\0\x01\00\00" + b"\0" * 244)
pos = -8
def add_size_to_header(size):
    global pos
    pos += 8
    reconstructed_data[12+pos:16+pos] = struct.pack("<I", size)
    reconstructed_data[16+pos:20+pos] = struct.pack("<I", struct.unpack("<I", reconstructed_data[8+pos:12+pos])[0] + size)

# And here's a shitload of heuristics to guess which offset is which field.
def apply_heuristics(callback, prefer_the_lowest_size, struct_sig: str):
    found = []
    for offset, size in offsets_to_sizes:
        data = metadata[offset:offset+size]

        entries = []
        valid = True

        if struct_sig:
            for i in range(0, len(data), 8):
                try:
                    fields = struct.unpack_from(struct_sig, data, i)
                    entries.append(fields)
                except struct.error:
                    valid = False
                    break
        
        if valid and callback(entries):
            found.append((offset, size))
    found.sort(key=lambda x: x[1])
    return found[0] if prefer_the_lowest_size else found[-1]

# Heuristic search for stringLiteral
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    
    entries = []
    valid = True

    for i in range(0, len(data), 8):
        try:
            entry_size, entry_index = struct.unpack_from("<II", data, i)
            entries.append((entry_size, entry_index))
        except struct.error:
            valid = False
            break

    if valid:
        expected_index = entries[0][1]
        for entry_size, entry_index in entries:
            if entry_index != expected_index:
                valid = False
                break
            expected_index += entry_size

    if valid:
        found = True
        print(f"{Fore.CYAN}Found stringLiteral at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for stringLiteral")

# Heuristic search for stringLiteralData (Not really a heuristic)
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]

    if data[0:8] == b"\x00\x00\x00\x01\x09\x00\x00\x01":
        found = True
        print(f"{Fore.CYAN}Found stringLiteralData at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for stringLiteralData")

# Heuristic search for string (Not really a heuristic again)
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]

    if data[0:15] == b"Assembly-CSharp":
        found = True
        print(f"{Fore.CYAN}Found string at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for string")

# Heuristic search for events
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    
    for i in range(0, len(data), 24):
        try:
            name_index, _, add, remove, _, _ = struct.unpack_from("<IIIIII", data, i)
            entries.append((name_index, add, remove))
        except struct.error:
            valid = False
            break

    if valid:
        wrong = 0
        last_name_index = entries[0][0]
        last_add = entries[0][1]
        last_remove = entries[0][2]
        for name_index, add, remove in entries:
            if name_index < last_name_index:
                wrong += 1
            if add > 1024 or remove > 1024:
                valid = False
                break
            last_name_index = name_index
        if wrong > 256: valid = False # Just to be sure

    if valid:
        found = True
        print(f"{Fore.CYAN}Found events at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for events")

# Heuristic search for properties
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 20):
        try:
            name_index, _, _, _, token = struct.unpack_from("<IIIII", data, i)
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        wrong = 0
        counter = 0
        last_token = entries[0]
        for token in entries:
            counter += 1
            if token - 385_875_968 != counter: # 0x00000017
                valid = False
                break
            # I hope that's enough
            if counter >= 1024:
                break
            last_token = token
        if wrong > 256: valid = False
    if valid:
        found = True
        print(f"{Fore.CYAN}Found properties at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for properties")

# Heuristic search for methods
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 36):
        try:
            _, _, _, _, _, _, token, _, _, _, _ = struct.unpack_from("<IIIIIIIHHHH", data, i)
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        wrong = 0
        counter = 0
        for token in entries:
            if token & 100663296 != 100663296: # 0x00000017
                valid = False
                break
    if valid:
        found = True
        print(f"{Fore.CYAN}Found methods at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        reconstructed_data += data
        offsets_to_sizes.remove((offset, size))
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for methods")

# Heuristic search for parameterDefaultValues
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 12):
        try:
            parameter_index, _, _ = struct.unpack_from("<III", data, i)
            entries.append(parameter_index)
        except struct.error:
            valid = False
            break

    if valid:
        last_parameter_index = entries[0]
        for parameter_index in entries:
            if last_parameter_index > parameter_index: # 0x00000017
                valid = False
                break
            last_parameter_index = parameter_index
    if valid:
        found = True
        print(f"{Fore.CYAN}Found parameterDefaultValues at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for parameterDefaultValues")

# Heuristic search for fieldDefaultValues (almost the same as previous, so the only thing we can do here is hope)
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 12):
        try:
            field_index, _, _ = struct.unpack_from("<III", data, i)
            entries.append(field_index)
        except struct.error:
            valid = False
            break

    if valid:
        last_field_index = entries[0]
        for field_index in entries:
            if last_field_index > field_index:
                valid = False
                break
            last_field_index = field_index
    if valid:
        found = True
        print(f"{Fore.CYAN}Found fieldDefaultValues at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for fieldDefaultValues")

# Heuristic search for fieldAndParameterDefaultValuesData (Not really a heuristic)
# TODO: Make it not garbage
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    
    if b"<color=#E9AF4D>{0}</color>" in data:
        found = True
        print(f"{Fore.CYAN}Found fieldAndParameterDefaultValues at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for fieldAndParameterDefaultValues")

# Heuristic search for fieldMarshaledSizes (almost the same as previous two, so the only thing we can do here is hope)
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 12):
        try:
            field_index, type_index, _ = struct.unpack_from("<III", data, i)
            entries.append((field_index, type_index))
        except struct.error:
            valid = False
            break

    if valid:
        last_field_index = entries[0][0]
        for field_index, type_index in entries:
            if last_field_index > field_index:
                valid = False
                break
            last_field_index = field_index
    if valid:
        found = True
        print(f"{Fore.CYAN}Found fieldMarshaledSizes at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for fieldMarshaledSizes")

# Heuristic search for parameters
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 12):
        try:
            _, token, _ = struct.unpack_from("<III", data, i)
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        for token in entries:
            if token & 134217728 != 134217728:
                valid = False
                break
    if valid:
        found = True
        print(f"{Fore.CYAN}Found parameters at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for parameters")

# Heuristic search for fields
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 12):
        try:
            _, _, token = struct.unpack_from("<III", data, i)
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        for token in entries:
            if token & 67108864 != 67108864:
                valid = False
                break
    if valid:
        found = True
        print(f"{Fore.CYAN}Found fields at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for fields")

# Heuristic search for genericParameters
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 16):
        try:
            owner_index, name_index, _, _, _, _ = struct.unpack_from("<IIHHHH", data, i)
            entries.append((owner_index, name_index))
        except struct.error:
            valid = False
            break

    if valid:
        last_owner_index = entries[0][0]
        first_name_index = entries[0][1]
        right_count = 0
        for owner_index, name_index in entries:
            if owner_index <= last_owner_index:
                right_count -= 1
            else:
                right_count += 1
            if name_index == first_name_index:
                right_count += 1
            last_owner_index = owner_index
            if right_count <= -16:
                valid = False
                break
            if right_count >= 128:
                break
    if valid:
        found = True
        print(f"{Fore.CYAN}Found genericParameters at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for genericParameters")

# Heuristic search for genericParameterContraints
found = False
offset_size_data: list[tuple[int, int, bytes]] = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            constraint = struct.unpack_from("<I", data, i)[0]
            entries.append(constraint)
        except struct.error:
            valid = False
            break

    if valid:
        for constraint in entries:
            # Bad
            if 1024576 < constraint or constraint < 256:
                valid = False
                break
    if valid:
        offset_size_data.append((offset, size, data))
if len(offset_size_data) > 0:
    offset, size, data = sorted(offset_size_data, key=lambda item: item[1])[0]
    print(f"{Fore.CYAN}Found genericParameterContraints at offset {offset} with size {size}. Adding to reconstructed_data.")
    add_size_to_header(size)
    offsets_to_sizes.remove((offset, size))
    reconstructed_data += data
else:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for genericParameterContraints")

# Heuristic search for genericContainers
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 16):
        try:
            owner_index, type_argc, is_method, _, = struct.unpack_from("<IIII", data, i)
            entries.append((owner_index, type_argc, is_method))
        except struct.error:
            valid = False
            break

    if valid:
        for owner_index, type_argc, is_method in entries:
            if not (is_method == 0 or is_method == 1) or type_argc > 128:
                valid = False
                break
    if valid:
        found = True
        print(f"{Fore.CYAN}Found genericContainers at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for genericContainers")

# Heuristic search for nestedTypes
found = False
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            type_definition_index = struct.unpack_from("<I", data, i)[0]
            entries.append(type_definition_index)
        except struct.error:
            valid = False
            break

    if valid:
        right_count = 0
        last_type_definition_index = 0
        attempts = 0
        exited_with_break = False
        for type_definition_index in entries:
            attempts += 1
            if type_definition_index > last_type_definition_index:
                right_count += 1
            else:
                right_count -= 1
            # Might change this later
            if right_count > 256:
                break
            if right_count < -4 or type_definition_index > 16777216 or attempts > 512:
                valid = False
                break
            last_type_definition_index = type_definition_index
    if valid:
        found = True
        print(f"{Fore.CYAN}Found nestedTypes at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for nestedTypes")

# Heuristic search for interfaces
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            constraint = struct.unpack_from("<I", data, i)[0]
            entries.append(constraint)
        except struct.error:
            valid = False
            break

    if valid:
        for constraint in entries:
            # Bad, should rework sometime soon
            if 1024576 < constraint or constraint < 256:
                valid = False
                break
    if valid:
        offset_size_data.append((offset, size, data))
if len(offset_size_data) > 0:
    offset, size, data = sorted(offset_size_data, key=lambda item: item[1], reverse=True)[0]
    print(f"{Fore.CYAN}Found interfaces at offset {offset} with size {size}. Adding to reconstructed_data.")
    add_size_to_header(size)
    offsets_to_sizes.remove((offset, size))
    reconstructed_data += data
else:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for interfaces")

# Heuristic search for vtableMethods (This is the only one that worked first try lmao)
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            constraint = struct.unpack_from("<I", data, i)[0]
            entries.append(constraint)
        except struct.error:
            valid = False
            break

    if valid:
        for encoded_method_index in entries:
            if encoded_method_index != 1 and encoded_method_index & 0xE0000000 == 0:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found vtableMethods at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for vtableMethods")

# Heuristic search for interfaceOffsets (This is the only one that worked first try lmao)
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 8):
        try:
            interface_type_index, interface_offset = struct.unpack_from("<II", data, i)
            entries.append((interface_type_index, interface_offset))
        except struct.error:
            valid = False
            break

    if valid:
        for interface_type_index, interface_offset in entries:
            if interface_offset > 256 or 256 > interface_type_index or interface_type_index > 65535:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found interfaceOffsets at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for interfaceOffsets")

# Heuristic search for typeDefinitions
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 88):
        try:
            token = struct.unpack_from("<III III I I IIIIIIII HHHHHHHH II", data, i)[25]
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        for token in entries:
            if token & 0x02000000 != 0x02000000:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found typeDefinitions at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for typeDefinitions")

# Heuristic search for images
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 40):
        try:
            token = struct.unpack_from("<IIIIIIIIII", data, i)[7]
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        entries = entries[:len(entries)-2]
        for token in entries:
            if token != 1:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found images at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for images")

# Heuristic search for assemblies
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 64):
        try:
            _, token = struct.unpack_from("<II", data, i)
            entries.append(token)
        except struct.error:
            valid = False
            break

    if valid:
        entries = entries[:len(entries)-2]
        for token in entries:
            if token & 0x20000000 != 0x20000000:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found assemblies at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for assemblies")

# Heuristic search for fieldRefs
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 8):
        try:
            type_index, field_index = struct.unpack_from("<II", data, i)
            entries.append((type_index, field_index))
        except struct.error:
            valid = False
            break

    if valid:
        last_type_index = entries[0][1]
        for type_index, field_index in entries:
            # Too vague
            if type_index < 256 or field_index > 2048:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found fieldRefs at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for fieldRefs")

# Heuristic search for referencedAssemblies
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            assembly = struct.unpack_from("<I", data, i)[0]
            entries.append(assembly)
        except struct.error:
            valid = False
            break

    if valid:
        mean_averege = sum(entries) / len(entries)
        for assembly in entries:
            # Maybe not the best approach
            if assembly > 256 or not 30 < mean_averege < 40:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found referencedAssemblies at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for referencedAssemblies")

# Heuristic search for attributeData
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]

    if b"Use Axlebolt.Standoff.Main.Pass.RewardPreview" in data:
        print(f"{Fore.CYAN}Found attributeData at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for attributeData")

# Heuristic search for attributeDataRange
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 8):
        try:
            token, index = struct.unpack_from("<II", data, i)
            entries.append((token, index))
        except struct.error:
            valid = False
            break

    if valid:
        right = 0
        last_index = entries[0][1]
        for token, index in entries:
            if token & 0xFF000000 == 0:
                right -= 10
            else:
                right += 2
            if index < last_index:
                right -= 2
            else:
                right += 1
            if right > 2048:
                break
            elif right < -16:
                valid = False
                break
    if valid:
        print(f"{Fore.CYAN}Found attributeDataRange at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for attributeDataRange")

# Heuristic search for unresolvedIndirectCallParameterTypes
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 4):
        try:
            parameter = struct.unpack_from("<I", data, i)[0]
            entries.append(parameter)
        except struct.error:
            valid = False
            break

    if valid:
        for parameter in entries:
            if parameter < 256 or parameter > 70000:
                valid = False
                break 
    if valid:
        print(f"{Fore.CYAN}Found unresolvedIndirectCallParameterTypes at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for unresolvedIndirectCallParameterTypes")

# Heuristic search for unresolvedIndirectCallParameterTypeRanges
found = False
offset_size_data = []
for offset, size in offsets_to_sizes:
    data = metadata[offset:offset+size]
    entries = []
    valid = True
    for i in range(0, len(data), 8):
        try:
            start, length = struct.unpack_from("<II", data, i)
            entries.append((start, length))
        except struct.error:
            valid = False
            break

    if valid:
        expected_start = entries[0][0]
        for start, length in entries:
            if start != expected_start:
                valid = False
                break
            expected_start += length
            
    if valid:
        print(f"{Fore.CYAN}Found unresolvedIndirectCallParameterTypeRanges at offset {offset} with size {size}. Adding to reconstructed_data.")
        add_size_to_header(size)
        offsets_to_sizes.remove((offset, size))
        reconstructed_data += data
        found = True
        break
if not found:
    print(f"{Fore.RED + Style.BRIGHT}Failed to apply heuristic search for unresolvedIndirectCallParameterTypeRanges")

# Finally write the last two zero sizes
add_size_to_header(0)
add_size_to_header(0)

# Manually fix the last size beacuse implementing a proper fix would take another year
reconstructed_data[252:256] = struct.pack("<I", len(metadata) - struct.unpack("<I", reconstructed_data[248:252])[0])

print(f"{Fore.MAGENTA + Style.BRIGHT}Output written to {output_path}") 
print(f"{Fore.GREEN}Successfully extracted and decrypted the metadata! I would be happy, if you starred my github "
      f"{Fore.BLUE}\033]8;;https://github.com/Michel-M-code/Metadata-Decryptor\33\\repository\033]8;;\033\\{Fore.LIGHTGREEN_EX + Style.BRIGHT}! (ctrl + click)\n"
      f"{Fore.CYAN}If anything goes wrong during the dump, feel free to open an issue on the said repository, this would help me to fix it quicker.{Style.RESET_ALL}")

# Write reconstructed_data to output
if os.path.isdir(output_path): output_path = output_path.rstrip("/").rstrip("\\") + "\\output-metadata.dat"
with open(output_path, "wb") as f:
    f.write(reconstructed_data)
