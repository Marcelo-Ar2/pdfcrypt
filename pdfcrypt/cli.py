import argparse
import pikepdf
import os
from . import __version__


def create_password_protected_pdf(input_pdf, output_pdf, password, strength="256"):

    # Check if input file exists before attempting to open
    if not os.path.exists(input_pdf):
        print(f"[X] Input file does not exist: {input_pdf}")
        return

    try:
        with pikepdf.open(input_pdf) as pdf:

            # Encryption strength mapping
            if strength == "256":
                # R=6 -> AES-256
                encryption = pikepdf.Encryption(user=password, owner=password, R=6)
            else:
                # R=4 -> AES-128
                encryption = pikepdf.Encryption(user=password, owner=password, R=4)

            pdf.save(output_pdf, encryption=encryption)

        print(f"[✓] Encrypted PDF saved as {output_pdf} (AES-{strength})")

    except FileNotFoundError:
        print(f"[X] The file {input_pdf} was not found.")

    except pikepdf.PdfError as e:
        print(f"[X] PDF error: {e}")

    except Exception as e:
        print(f"[X] Unexpected error: {e}")


def decrypt_pdf(input_pdf, output_pdf, password):
    # Check if file exists before attempting to open
    if not os.path.exists(input_pdf):
        print(f"[X] Input file does not exist: {input_pdf}")
        return

    try:
        with pikepdf.open(input_pdf, password=password) as pdf:
            pdf.save(output_pdf)

        print(f"[✓] Decrypted PDF saved as {output_pdf}")

    except pikepdf.PasswordError:
        print("[X] Incorrect password or decryption failed.")

    except FileNotFoundError:
        print(f"[X] The file {input_pdf} was not found.")

    except pikepdf.PdfError:
        print("[X] The file is not a valid PDF.")

    except Exception as e:
        print(f"[X] Unexpected error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt a PDF using pikepdf"
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        metavar="INPUT.pdf",
        help="Path to the input PDF"
    )

    parser.add_argument(
        "-o", "--output",
        required=True,
        metavar="OUTPUT.pdf",
        help="Path where the processed PDF will be saved"
    )

    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Password used for encryption or decryption"
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Decrypt the input PDF"
    )
    mode_group.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Encrypt the input PDF (default)"
    )


    parser.add_argument(
        "-s", "--strength",
        choices=["128", "256"],
        default="128",
        help="Encryption strength: 128 (AES-128) or 256 (AES-256). Default: 128."
    )

    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite output file if it already exists"
    )

    parser.add_argument(
    "-v", "--version",
    action="version",
    version=f"pdfcrypt {__version__}",
    help="Show the version number and exit"
    )


    args = parser.parse_args()

    # Default mode = encrypt
    if not args.decrypt and not args.encrypt:
        args.encrypt = True


    if not args.output.lower().endswith(".pdf"):
        print("[!] Output file does not end with .pdf\n"
              "[!] Adding extention automatically.")
        args.output += ".pdf"
    
    if os.path.exists(args.output) and not args.force:
        print(f"[X] Output file '{args.output}' already exists. Use --force to overwrite.")
        return

    if args.decrypt:
        decrypt_pdf(args.input, args.output, args.password)
    else:
        create_password_protected_pdf(args.input, args.output, args.password, args.strength)


if __name__ == "__main__":
    main()
