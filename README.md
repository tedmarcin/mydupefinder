# mydupefinder
A command-line tool to detect and optionally remove duplicate files based on their hash values (MD5 or SHA-256). This tool uses the Crypto++ library for hashing and the C++17 filesystem library for directory traversal.

## Features

- **MD5 or SHA-256**: Choose your hashing algorithm via command-line flags (`-md5` or `-sha256`).
- **Recursive Directory Scan**: Traverses all files in the specified directory or directories.
- **Dummy Test Mode**: Optionally perform a dummy test run without actually deleting any files.
- **Manual or Automatic Deletion**: Choose whether to keep one file and delete the rest automatically, or manually pick the file you want to keep.
- **Logging**: Generates a timestamped log file detailing all actions taken.

## Installation in a linux Shell

1. Clone this repository:
   git clone https://github.com/<your-username>/mydupefinder.git
2. cd mydupefinder
3. g++ -std=c++17 -O2 mydupefinder.cpp -o mydupefinder -lcryptopp


Usage
./mydupefinder [options] <directory> [<directory> ...]

Options
-md5

Use MD5 hashing algorithm.
-sha256

Use SHA-256 hashing algorithm (default).
-help or --help

Display usage information.
Example
# Scan a single directory using SHA-256 (default):
./mydupefinder /path/to/directory

# Scan multiple directories using MD5:
./mydupefinder -md5 /path/to/dir1 /path/to/dir2 /path/to/dir3

# Show help:
./mydupefinder -help
After running the tool, you will be prompted to select directories from which duplicates should be removed, choose whether to perform a dummy test, and optionally confirm manual deletions. A log file named log_YYYYMMDDHHMMSS.txt will be created in the current working directory with details of the actions taken.
