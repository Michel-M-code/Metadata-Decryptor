# Metadata Decryptor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Python script to automatically extract and decrypt global-metadata.dat embedded in `libunity.so`. Made specifically for *Standoff 2*.

## Features

- **Automatic extraction** of the embedded `global-metadata.dat` pointer from the ELF relocation table.
- **Heuristic-based decryption** to reconstruct all metadata fields.
- **No reference metadata needed** to decrypt the current one.
- **A lot faster and easier** compared to manual decryption.
- **Cross‑platform** (any OS with Python 3.x and file‑system access).

## Prerequisites

- Python 3.x
- Install required packages via pip:

  ```bash
  pip install tqdm pyelftools
  ```

## Installation

1. Clone this repository (or download `metadata_decryptor.py`).
2. Ensure Python 3.x is on your `PATH`.
3. Install dependencies as shown above.

## Usage

> [!NOTE]
> Verbose (`-v`) flag is not yet implemented.

Run the script against a `libunity.so` binary that contains an embedded `global-metadata.dat`:

```bash
python metadata_decryptor.py --libunity path/to/libunity.so --output path/to/output-metadata.dat
```

- `--libunity`&nbsp;Path to the `libunity.so` ELF file.
- `--output`&nbsp;Destination path (file or directory) for the decrypted metadata.

**Example:**

```bash
python metadata_decryptor.py --libunity ./libunity.so --output ./decrypted-metadata.dat
```

On success, you’ll see a confirmation message and a file containing the reconstructed metadata.

## How It Works

1. **Locates metadata pointer** in the ELF relocation table by scanning for the known hex pattern.
2. **Reads raw metadata bytes** until a 256‑byte zero marker is found, signalizing it's end.
3. **Saves the intermediate metadata** to a file for debugging purposes.
4. **Identifies candidate offsets** by checking for 4‑byte alignment and four zero bytes before them.
5. **Filters offset–size pairs** by matching sums against other offsets.
6. **Uses heuristic search** to identify each offset and append each section in order.
7. **Writes the final output** to the specified path.

## Troubleshooting

- **`Error: No candidate found.`**  
  The relocation table didn’t yield the expected pattern. Make sure you selected the right files, and if the script still fails, open an issue.

- **Invalid ELF header**  
  Verify you pointed at the correct `libunity.so` (it must start with the ELF magic bytes).

- **Unexpected offsets count**  
  If the script finds ≠29 fields, the heuristics may need adjustment for the new version. Feel free to open an issue.

## Contribution

Contributions, issues, and feature requests are welcome!  
Feel free to fork the repo, open an issue, or submit a pull request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
