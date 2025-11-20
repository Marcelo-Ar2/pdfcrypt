# pdfcrypt

A simple and secure command-line tool to encrypt and decrypt PDF files using AES-128 or AES-256 encryption (powered by pikepdf).

## Features

- Encrypt PDFs using AES-128 or AES-256
- Decrypt password-protected PDFs (with correct password)
- Intuitive and clean CLI interface
- Prevents accidental overwriting of existing files (use `--force` to overwrite)
- Validates input and output paths
- Includes `--version` flag and detailed help message
- Ideal for scripting or personal security workflows

---

## Installation

### Install locally from source

```bash
git clone https://github.com/Marcelo-Ar2/pdfcrypt
cd pdfcrypt
pip install .
```


## Usage

### Encrypt a PDF (AES-128)

```bash
pdfcrypt -i input.pdf -o encrypted.pdf -p mypassword
```

### Encrypt a PDF (AES-256)

```bash
pdfcrypt -i input.pdf -o encrypted.pdf -p mypassword -s 256
```

### Decrypt a PDF

```bash
pdfcrypt -i encrypted.pdf -o decrypted.pdf -p mypassword -d
```
### Force overwrite

```bash
pdfcrypt -i input.pdf -o encrypted.pdf -p mypassword --force
```

### Show version

```bash
pdfcrypt --version
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-i, --input` | Path to the input PDF file *(required)* |
| `-o, --output` | Path to the output PDF file *(required)* |
| `-p, --password` | Password for encryption or decryption *(required)* |
| `-d, --decrypt` | Decrypt the input PDF |
| `-e, --encrypt` | Encrypt the input PDF (default) |
| `-s, --strength` | AES strength: `128` or `256` (default: 128) |
| `-v, --version` | Show version number |
| `-h, --help` | Show help message |


## Requirements

- Python 3.8+
- pikepdf >= 9.0.0


## Troubleshooting

### "The file is not a valid PDF"
The input file may be corrupted or not a PDF.

### "Incorrect password or decryption failed"
The provided password does not match the PDF.

### "Input file does not exist"
Make sure the path is correct and the file is accessible.

### Windows: Installation fails due to missing Visual C++ Build Tools
Install "Microsoft C++ Build Tools" from the official site.


## License

MIT License. See `LICENSE` file for details.

