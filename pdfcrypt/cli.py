import argparse
import pikepdf


def create_password_protected_pdf(input_pdf, output_pdf, password, strength="256"):
    """
    Encrypt a PDF using pikepdf (AES-128 or AES-256)
    """
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
    """
    Decrypt a password-protected PDF using pikepdf
    """
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
        help="Path to the input PDF"
    )

    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Path to the output PDF"
    )

    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Password for encryption or decryption"
    )

    parser.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Decrypt the input PDF instead of encrypting it"
    )

    parser.add_argument(
        "-s", "--strength",
        choices=["128", "256"],
        default="128",
        help="Encryption strength (128 or 256). Default is 128."
    )

    args = parser.parse_args()

    if args.decrypt:
        decrypt_pdf(args.input, args.output, args.password)
    else:
        create_password_protected_pdf(args.input, args.output, args.password, args.strength)


if __name__ == "__main__":
    main()
