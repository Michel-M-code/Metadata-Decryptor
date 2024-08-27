# Metadata-Decryptor

This is a Python script designed to fix `global-metadata.dat` files that fail during metadata initialization or cannot be dumped. It's specifically useful for games that reorder values in the `global-metadata.dat` header, such as Standoff 2.

## Usage/Examples

### Prerequisites

- Python 3.12
- A metadata file with a reordered header that cannot be dumped
- An older version of the metadata file that is correct and can be dumped

### Example

#### Step 1: Getting the Files

To use this script, you need two versions of the `global-metadata.dat` file:
- **Latest version**: The file with the reordered header that you cannot dump.
- **Older, working version**: A file from an earlier version of the game that can be dumped correctly.

If you don't know which game version started shuffling the header values, you may need to try different versions of the metadata file. You can theoretically use metadata from another game, but it must be compatible, unencrypted, and not corrupted. 

For this example, we'll use the game *Standoff 2*. At the time of writing, the latest version of *Standoff 2* is `0.29.1`, which cannot be dumped directly due to the reordered header. The older version `0.27.3` can be dumped and will serve as our reference.

#### Step 2: Preparing the Files

1. **Download the required game versions**: You need both the latest version of the game and the older version.
2. **Extract the `global-metadata.dat` files**: Once you've downloaded the required versions, extract the `global-metadata.dat` files from each version. 
3. **Organize the files**: Place both metadata files in the same folder as the script. The latest version should remain named `global-metadata.dat`, and the older version should be renamed to `reference-global-metadata.dat`.

#### Step 3: Running the Script

Once your files are prepared, you can run the script. Here's how it works:

1. **Searching for Values**: The script will compare the values at various offsets in both metadata files. It checks for similarities and differences in the data, trying to match the reordered values in the latest file with their correct counterparts in the older reference file.
2. **Displaying Potential Matches**: After processing, the script will output a list of potential matches that it found. For each match, you will be asked to confirm if it is valid. Here’s what the output might look like:

═════════════════════════════════════════════════════════════════ 
Actual: 197,464 Reference: 197,728 Size: 197,208 | Margin: -264 | Difference: 51654 | Zero Difference: 1229
Valid?

**Explanation of the Output**:

- **Actual**: This is the candidate value from the latest `global-metadata.dat` file that the script thinks is correct.
- **Reference**: This is the corresponding value from the older `reference-global-metadata.dat` file that the script used for comparison.
- **Size**: This is the size of the current section, calculated by subtracting the last confirmed offset from the current `Actual` value.
- **Margin**: This shows the difference between the `Actual` value and the `Reference` value. In most cases, the margin should be small, but it can sometimes be negative, as shown here.
- **Difference**: This is a measure of how different the bytes are at the `Actual` and `Reference` offsets. A lower difference indicates a closer match.
- **Zero Difference**: This counts the number of times the byte difference between `Actual` and `Reference` is zero. A higher number here is a good indicator that the match is correct.

3. **Validating the Match**: Based on the information provided, you will decide whether the match is valid or not. In this example, although the `Margin` is negative, the `Zero Difference` is high and the `Difference` is relatively low, indicating that this is likely a valid match. If you believe the match is correct, you would type `1` to confirm.

4. **Iterating Through the Matches**: The script will continue to search for matches, and you'll be prompted to confirm or reject each one until the header is fully reconstructed.

#### Step 4: Finalizing the Decryption

Once all matches are confirmed, the script will finalize the `decrypted-global-metadata.dat` file by fixing the last offsets and sizes. It will then write the remaining portion of the metadata file unchanged. Your `global-metadata.dat` file should now be repaired and ready for use.

### Troubleshooting

- **Inaccurate Matches**: If you find that the matches presented by the script seem inaccurate, double-check that your reference metadata file is correct and compatible with the latest version.
- **Dump Failure**: If the decrypted metadata file still fails to dump, verify that the metadata was not encrypted in the first place and that you followed the steps correctly.

### Contributing

Feel free to contribute to the project by submitting issues, suggesting improvements, or creating pull requests. Your feedback and contributions are welcome!

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
