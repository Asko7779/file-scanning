
> Intermediate level file scanner, scans a desired directory/file for a malicious hash and flags it.  
> _Note: This tool is still in development and may occasionally be glitchy._

---

## Features

- 🗂️ Scan individual files or whole directories for malicious hashes
- ⚡ Fast, efficient, and written in pure C
- 🛡️ Flags files that match known malicious hashes
- 📝 Easy to configure and extend hash lists
- 🐧 Linux-first, should be portable to other platforms with minimal changes

---

## Getting Started

### Prerequisites

- GCC or compatible C compiler
- Make (optional, for easier builds)
- Linux (tested), but should work on other POSIX systems

### Build

```bash
git clone https://github.com/Asko7779/file-scanning.git
cd file-scanning
gcc -o file-scanner main.c   # Or use the included Makefile: make
```

### Usage

```bash
./file-scanner [options] <path>
```

- `<path>`: File or directory to scan
- **Options:**
  - `-r` : Recursive scan (for directories)
  - `-v` : Verbose output
  - `-h` : Show help

**Example:**

```bash
./file-scanner -r /home/user/documents
```

---

## How It Works

1. Loads a list of known malicious hashes (edit `hashes.txt` to update).
2. Scans the target file or recursively scans directories.
3. Computes hash for each file and compares to the known list.
4. Flags any file matching a malicious hash.

---

## Configuration

- **Hashes List:**  
  Update the `hashes.txt` file to add or remove malicious hashes.
- **Settings:**  
  Edit constants in `main.c` for advanced customization.

---

## Troubleshooting

- **Not finding files:**  
  Ensure you have the correct permissions and the path exists.
- **False positives/negatives:**  
  Update your `hashes.txt` or verify your hash calculation logic.
- **Crashes or glitches:**  
  Please [open an issue](https://github.com/Asko7779/file-scanning/issues) with details.

---

## Contribution

Pull requests and suggestions are welcome!  
Fork the repo and submit your changes via PR.

---

## License

[MIT License](LICENSE)

---

## Acknowledgements

- Inspired by open-source security tools and the need for simple file scanning utilities in C
