# Imports
import struct
import argparse
import math
from tqdm import tqdm
import colorama
from colorama import Fore, Style

# Init colorama
colorama.init(autoreset=True)

# Set up argument parser
parser = argparse.ArgumentParser()

# Set automatic (-a) and manual (-m) mode optional arguments
parser.add_argument("-m", action="store_true", help="Manual mode", required=False)
parser.add_argument("-a", action="store_true", help="Automatic mode", required=False)

# Define positional arguments for the files
parser.add_argument("--metadata", metavar="metadata", help="Metadata file")
parser.add_argument("--reference", metavar="reference", help="Reference metadata file")
parser.add_argument("--output", metavar="output", help="Reference metadata file")

args = parser.parse_args()

use_default_files = (args.metadata, args.reference, args.output).count(None) == 3

# Determine whether args are used and if automatic mode is selected
auto = None
if args.a:
    print(f"{Fore.CYAN}Using automatic mode.")
    auto = True
elif args.m:
    print(f"{Fore.CYAN}Using manual mode.")
    auto = False
elif args.a and args.m:
    raise ValueError("Cannot use both automatic (-a) and manual (-m) mode simultaneously.")

# Select mode
while auto is None:
    user_input = input(f"{Fore.CYAN}Select mode. Automatic or Manual: {Style.RESET_ALL}").strip().lower()
    
    if user_input[0] == 'a':
        auto = True
        print(f"{Fore.CYAN}Automatic mode selected.")
    elif user_input[0] == 'm':
        print(f"{Fore.CYAN}Manual mode selected.")
        auto = False
    else:
        print(f"{Fore.YELLOW}Invalid input.")

metadata_path = args.metadata
reference_metadata_path = args.reference
decrypted_metadata_path = args.output
confirmed = 0

while not confirmed and not metadata_path and not reference_metadata_path and not decrypted_metadata_path:
    if not metadata_path:
        metadata_path = input(f"{Fore.CYAN}Input encrypted metadata file path: {Style.RESET_ALL}")
    if not reference_metadata_path:
        reference_metadata_path = input(f"{Fore.CYAN}Input reference metadata file path: {Style.RESET_ALL}")
    if not decrypted_metadata_path:
        decrypted_metadata_path = input(f"{Fore.CYAN}Input decrypted metadata save file path: {Style.RESET_ALL}")


    print(f"{Fore.CYAN}Using next files:")
    print(f"    {Fore.CYAN}Encrypted - {Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}{metadata_path}")
    print(f"    {Fore.CYAN}Reference - {Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}{reference_metadata_path}")
    print(f"    {Fore.CYAN}Output - {Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}{decrypted_metadata_path}")

    while not confirmed:
        try:
            confirmed = bool(int(input(f"{Fore.CYAN}Correct? {Style.RESET_ALL}")))
        except ValueError:
            print(f"{Fore.YELLOW}Enter 0 or 1")

# Open files
metadata = open(metadata_path, "rb")
reference_metadata = open(reference_metadata_path, "rb")
decrypted_metadata = open(decrypted_metadata_path, "wb")


# Copy first 12 bytes.
decrypted_metadata.write(reference_metadata.read(12))
# In format (actual, reference): (difference, zero_difference_count)
pairs_to_differences = {}
# Skip 4 bytes
reference_metadata.read(4)
# Define the lowest reference offset.
lowest_reference_offset = struct.unpack("<I", reference_metadata.read(4))[0]


# Defines a function to compare bytes at offsets and returns the difference.
def compare_bytes_at_offsets(actual_offset, reference_offset, length) -> tuple:
    # Seek to offsets
    metadata.seek(max(actual_offset - length, 0))
    reference_metadata.seek(max(reference_offset - length, 0))

    difference = 0
    zero_difference_count = 0

    # Iterate over bytes to count difference and zeroes.
    for _ in range(length * 2):
        actual = struct.unpack("<b", metadata.read(1))[0]
        reference = struct.unpack("<b", reference_metadata.read(1))[0]

        difference += abs(actual - reference)

        if abs(actual - reference) == 0:
            zero_difference_count += 1

    return difference, zero_difference_count

# Parse every possible pair and check the difference.
for i in tqdm(range(62 * 31), ncols = 100, colour = "green", unit = "pairs", desc="Searching... "):
    # Second loop. Iterate over the rest of the values.
    j = i % 30
    i = i % 61

    # Go to positions
    metadata.seek(8 + i * 4)
    reference_metadata.seek(8 + j * 8)

    # Actual candidate for checking.
    candidate_actual = metadata.read(4)
    # Reference candidate for checking.
    candidate_reference = reference_metadata.read(4)

    candidate_actual_i = struct.unpack("<I", candidate_actual)[0]
    candidate_reference_i = struct.unpack("<I", candidate_reference)[0]
    if (candidate_actual == b"\x00\x00\x00\x00" or candidate_reference == b"\x00\x00\x00\x00"
            or candidate_actual == b"\x00\x01\x00\x00" or candidate_reference == b"\x00\x01\x00\x00"
            or candidate_actual_i <= lowest_reference_offset - 1024):
        continue
    
    pairs_to_differences[(candidate_actual_i, candidate_reference_i)] = compare_bytes_at_offsets(candidate_actual_i, candidate_reference_i, 1024)


values_found = []
sizes = []
last_actual_value_found = 256
last_reference_value_found = 256
wrong_count = 0

iterable = sorted(pairs_to_differences.items(),key=lambda x: (x[0][1] - x[1][1]), reverse=False)
iterable_tqdm_wrapper = tqdm(iterable, ncols = 100, colour = "green", unit = "pairs", desc=f"Reordering...")

# Write the decrypted metadata
for (actual, reference), (difference, zero_difference) in iterable_tqdm_wrapper:
    if actual not in values_found and reference not in values_found:
        # Calculate size
        size = actual - last_actual_value_found
        if auto:
            valid = 0 < actual - reference - last_actual_value_found + last_reference_value_found < 1_000_000
            if valid:
                # print(f"{Fore.GREEN}Pair Actual: {hex(actual)} ({actual:,}) Reference: {hex(reference)} ({reference:,}) with Size: {size:,} and Difference: {difference}")
                # print(f"Is probably valid. Writing to decrypted metadata{Style.RESET_ALL}")

                last_actual_value_found = actual
                last_reference_value_found = reference
                sizes.append(size)

                # Write the value.
                decrypted_metadata.write(b"\0\0\0\0")
                decrypted_metadata.write(struct.pack("<I", actual))

                values_found.append(actual)
                values_found.append(reference)
            else:
                wrong_count += 1
                if wrong_count > 30: break
                continue

        else:
            print(f"Actual: {actual:,} Reference: {reference:,} | Size: {size:,} | Difference: {difference} Zero Difference: {zero_difference}")

            # Ask the user if the value is valid.
            if bool(int(input("Valid? "))):
                last_actual_value_found = actual
                last_reference_value_found = reference
                sizes.append(size)

                # Write the value.
                decrypted_metadata.write(b"\0\0\0\0")
                decrypted_metadata.write(struct.pack("<I", actual))

                values_found.append(actual)
                values_found.append(reference)
    else:
        continue

if wrong_count > 30:
    print(f"{Fore.RED}DECRYPTION FAILED!")
    print(f"{Fore.YELLOW}Make sure you provided the right files, and if the decryption still fails, "
            "feel free to open an issue on my github: https://github.com/Michel-M-code/Metadata-Decryptor/issues/new")
    exit(-1)

print(wrong_count)

print(f"{Fore.CYAN}Fixing the last two offsets...")

# Fix last 2 offsets
decrypted_metadata.seek(240)
decrypted_metadata.write(struct.pack("<I", last_actual_value_found))
decrypted_metadata.seek(248)
decrypted_metadata.write(struct.pack("<I", last_actual_value_found))

print(f"{Fore.CYAN}Writing calculated sizes...")

# Write sizes
for i in range(len(sizes)):
    decrypted_metadata.seek(12 + i * 8)
    decrypted_metadata.write(struct.pack("<I", sizes[i]))

print(f"{Fore.CYAN}Fixing the last size...")

# Fix last size
metadata.seek(0)
decrypted_metadata.seek(252)
decrypted_metadata.write(struct.pack("<I", len(metadata.read()) - last_actual_value_found))

# Write everything past the header unchanged.
metadata.seek(256)
decrypted_metadata.seek(256)
decrypted_metadata.write(metadata.read())

print(f"{Fore.LIGHTGREEN_EX + Style.BRIGHT}The script had successfully decrypted metadata file!\nDecrypted file saved to {Fore.CYAN}{decrypted_metadata.name}")

# Close files.
metadata.close()
decrypted_metadata.close()
