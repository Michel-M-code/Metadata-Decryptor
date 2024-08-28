# Import struct for handling little endian data.
import struct
# Import argparse for handling command line arguments.
import argparse

# Set up argument parser
parser = argparse.ArgumentParser()

# Set automatic (-a) and manual (-m) mode optional arguments
parser.add_argument("-m", action="store_true", help="Manual mode", required=False)
parser.add_argument("-a", action="store_true", help="Automatic mode", required=False)

# Define positional arguments for the files
parser.add_argument("--metadata", metavar="metadata", help="Metadata file")
parser.add_argument("--reference_metadata", metavar="reference_metadata", help="Reference metadata file")

args = parser.parse_args()

is_parameterless = False

# Determine whether args are used and if automatic mode is selected
if args.a and args.m:
    raise ValueError("Cannot use both automatic (-a) and manual (-m) mode simultaneously.")
elif args.a:
    is_automatic = True
elif args.m:
    is_automatic = False
elif not args.a and not args.m:
    if args.metadata is None and args.reference_metadata is not None:
        raise FileNotFoundError(f"Metadata file '{args.metadata}' was not provided.")
    elif args.metadata is not None and args.reference_metadata is None:
        raise FileNotFoundError(f"Metadata file '{args.reference_metadata}' was not provided.")
    elif args.metadata is None and args.reference_metadata is None:
        is_parameterless = True
    user_input = input("Enter A for Automatic mode or M for Manual mode: ").strip().upper()
    if user_input == 'A':
        is_automatic = True
    elif user_input == 'M':
        is_automatic = False
    else:
        print("Invalid input. Please enter A for Automatic mode or M for Manual mode.")


# Open metadata file.
if is_parameterless:
    metadata = open("./global-metadata.dat", "rb")
else:
    metadata = open(args.metadata, "rb")
# Open reference metadata file for comparisons.
if is_parameterless:
    reference_metadata = open("./reference-global-metadata.dat", "rb")
else:
    reference_metadata = open(args.reference_metadata, "rb")
# Create decrypted metadata file.
decrypted_metadata = open("./decrypted-global-metadata.dat", "wb")

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


print("Searching...")

# Parse every possible pair and check the difference.
for i in range(62):
    # Second loop. Iterate over the rest of the values.
    for j in range(31):
        # Go to positions
        metadata.seek(8 + i * 4)
        reference_metadata.seek(8 + j * 8)

        if metadata.tell() > 252:
            print("Metadata value is greater than 252", metadata.tell())
        if reference_metadata.tell() > 252:
            print("Reference metadata value is greater than 252", metadata.tell())

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

        pairs_to_differences[
            (candidate_actual_i, candidate_reference_i, candidate_actual_i - candidate_reference_i)] = (
            compare_bytes_at_offsets(candidate_actual_i, candidate_reference_i, 1024))

print("Search done.")

values_found = []
sizes = []
last_actual_value_found = 256
last_reference_value_found = 256

# Write the decrypted metadata
for (actual, reference, margin), (difference, zero_difference) in sorted(pairs_to_differences.items(),
                                                                         key=lambda x: (x[0][1] - x[1][1]), reverse=False):

    if actual not in values_found and reference not in values_found:
        size = actual - last_actual_value_found
        if not is_automatic:
            print("═" * 150)
            print(
                f"Actual: {actual:,} Reference: {reference:,}  Size: {size:,} | Margin: {margin:,} | Difference: {difference} Zero Difference: {zero_difference}")
            if bool(int(input("Valid? "))):
                last_actual_value_found = actual
                sizes.append(size)
                values_found.append(actual)
                values_found.append(reference)
        if is_automatic:
            valid = actual - reference - last_actual_value_found + last_reference_value_found < 1_000_000
            if valid:
                print("═" * 150)
                print(
                    f"Actual: {actual:,} Reference: {reference:,}  Size: {size:,} | Margin: {margin:,} | Difference: {difference} Zero Difference: {zero_difference}")
                print("Valid: 1")
                last_actual_value_found = actual
                last_reference_value_found = reference
                sizes.append(size)
                values_found.append(actual)
                values_found.append(reference)
        else:
            if is_automatic:
                print("═" * 150)
                print(
                    f"Actual: {actual:,} Reference: {reference:,}  Size: {size:,} | Margin: {margin:,} | Difference: {difference} Zero Difference: {zero_difference}")
                print("Valid: 0")
            continue
    else:
        continue

    found = False
    for i in range(31):
        reference_metadata.seek(8 + i * 8)
        data = reference_metadata.read(4)
        if data == struct.pack("<I", reference):
            decrypted_metadata.seek(8 + i * 8)
            decrypted_metadata.write(struct.pack("<I", actual))
            found = True
            break

    if not found:
        print(f"Could not find reference value: {reference}")

# Fix last 2 offsets
decrypted_metadata.seek(240)
decrypted_metadata.write(struct.pack("<I", last_actual_value_found))
decrypted_metadata.seek(248)
decrypted_metadata.write(struct.pack("<I", last_actual_value_found))


# Write sizes
for i in range(len(sizes)):
    decrypted_metadata.seek(12 + i * 8)
    decrypted_metadata.write(struct.pack("<I", sizes[i]))

# Fix last size
metadata.seek(0)
decrypted_metadata.seek(252)
decrypted_metadata.write(struct.pack("<I", len(metadata.read()) - last_actual_value_found))

# Write everything past the header unchanged.
metadata.seek(256)
decrypted_metadata.seek(256)
decrypted_metadata.write(metadata.read())

# Close files.
metadata.close()
decrypted_metadata.close()
