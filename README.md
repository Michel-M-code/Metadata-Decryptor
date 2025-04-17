# Metadata-Decryptor

> [!IMPORTANT]  
> I am aware of the current situation and I am working on resolving it as soon as possible.
> Please do not open any issues, they will be closed immediately.

This Python script decrypts and reorders the `global-metadata.dat` file for games that reorder metadata headers, like *Standoff 2*. The script provides both automatic and manual modes for validating reordered values by comparing an encrypted metadata file with a reference file.

## Features

- **Automatic Mode**: Automatically validates reordered values based on calculated differences.
- **Manual Mode**: Allows the user to manually verify each match to ensure accuracy.
- **Error Reporting**: Detects and notifies if decryption fails due to incorrect files or mismatches.

## Prerequisites

- **Python 3.12**
- **Required Python Modules**: Install `tqdm` and `colorama` by running:
  ```sh
  pip install tqdm colorama
  ```

- **Input Files**:
  - `global-metadata.dat` (latest, encrypted metadata file)
  - `reference-global-metadata.dat` (older metadata file that can be dumped correctly)

## Usage

> [!IMPORTANT]  
> If the decryption fails for new versions of Standoff 2, try to use the decrypted metadata from the version before as a reference input file.
> After 0.33.0 `libunity.so` and `libil2cpp.so` are merged. To dump, when prompted in the dumper, just select `libunity.so` instead of `libil2cpp.so`.

### Command-Line Arguments

The script can be run with or without arguments. If arguments are not provided, the script will prompt you for file paths and mode selection.

- `--metadata`: Path to the encrypted metadata file (e.g., `global-metadata.dat`).
- `--reference`: Path to the reference metadata file (e.g., `reference-global-metadata.dat`).
- `--output`: Path to save the decrypted metadata file.
- `-a`: Automatic mode (validates reordered values automatically).
- `-m`: Manual mode (user confirms each match interactively).

### Examples

#### Example 1: Automatic Mode

To decrypt metadata automatically, use the following command:
```sh
python MetadataDecryptor.py --metadata global-metadata.dat --reference reference-global-metadata.dat --output decrypted-global-metadata.dat -a
```

#### Example 2: Manual Mode

If you want to review each match manually, use:
```sh
python MetadataDecryptor.py --metadata global-metadata.dat --reference reference-global-metadata.dat --output decrypted-global-metadata.dat -m
```

### Running Without Command-Line Arguments

If you run the script without specifying arguments, it will prompt you to input paths for the encrypted and reference metadata files, as well as the output file path. You will also be asked to choose between automatic and manual modes.

### Detailed Explanation

#### Process Overview

1. **File Validation**: The script compares `global-metadata.dat` and `reference-global-metadata.dat`, calculating differences between values at specified offsets to detect and align reordered header values.
2. **Modes**:
   - **Automatic Mode**: The script automatically validates matches based on calculated differences and confidence metrics.
   - **Manual Mode**: The script prompts the user to confirm each match, displaying detailed information for manual verification.
   
#### Output Information

For each pair, the script outputs details like:
- **Actual**: This is the candidate value from `global-metadata.dat` that will be written to the output file if confirmed.
- **Reference**: This is the corresponding value from the older reference metadata file.
- **Size**: The calculated size of the current section based on the last confirmed offset.
- **Difference**: Byte-wise difference between the `Actual` and `Reference` values over a range.
- **Zero Difference**: Count of exact matches (zero difference) between the `Actual` and `Reference` bytes in the comparison range.

### Error Handling

If the script detects too many mismatches (more than 30 in automatic mode), it will terminate and prompt you to:
- Verify the paths and files specified.
- Check that the `reference-global-metadata.dat` file is compatible and correctly decrypted.

If decryption fails consistently, consider opening an issue on GitHub for support.

### Troubleshooting

- **Incorrect File Paths**: Ensure the file paths are correctly specified, or input them when prompted.
- **Failed Decryption**: Verify that the reference metadata file is compatible with the latest version.
- **Unsuccessful Dumping**: Confirm that the decrypted metadata file was generated correctly.

## Contributing

Feel free to contribute by reporting issues, suggesting enhancements, or submitting pull requests. Contributions are welcome!

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
