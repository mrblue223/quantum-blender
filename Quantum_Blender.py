import click
import os
import json
import base64
import sys
import hashlib
import time
import logging
from datetime import datetime, timezone
from typing import Optional
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─────────────────────────────────────────────
#  Safe ML-DSA Verify Wrapper
# ─────────────────────────────────────────────
def _mldsa_verify(pk: bytes, sig: bytes, msg: bytes) -> None:
    """
    Safe wrapper around ml_dsa_65.verify().

    pqcrypto 0.4.x bug: verify() always returns False regardless of whether
    the signature is valid. This wrapper checks the return value explicitly
    AND falls back to comparing a fresh signature if the return value is
    ambiguous, making it robust across all pqcrypto versions.

    Raises ValueError on invalid signature.
    Returns None on success.
    """
    try:
        result = ml_dsa_65.verify(pk, sig, msg)
    except Exception as e:
        # Future versions may raise on failure — treat as invalid
        raise ValueError(f"Signature invalid: {e}") from e

    if result is True:
        return  # Newer pqcrypto returning True = valid

    if result is None:
        return  # Newer pqcrypto returning None = valid (no exception)

    # result is False — pqcrypto 0.4.x bug: always returns False.
    # We cannot trust this value. Perform a structural sanity check:
    # re-sign a known message with a fresh key and verify the library
    # can at least distinguish keys — if verify() is truly broken
    # we mark ALL verifications as untrustworthy and raise.
    _pk2, _sk2 = ml_dsa_65.generate_keypair()
    _sig2 = ml_dsa_65.sign(_sk2, b"__probe__")
    _r2 = ml_dsa_65.verify(_pk2, _sig2, b"__probe__")
    if _r2 is False:
        # Library is broken — cannot verify. Raise to alert the caller.
        raise ValueError(
            "ml_dsa_65.verify() is non-functional in this pqcrypto build "
            "(always returns False). Upgrade pqcrypto to a version where "
            "verify() raises on failure or returns True on success. "
            "Signature could not be validated."
        )
    # If probe passed but original returned False, signature is invalid
    raise ValueError("Signature verification failed (invalid signature)")


def pqcrypto_verify_working() -> bool:
    """
    Returns True if ml_dsa_65.verify() can distinguish valid from invalid.
    Used by tests to skip/xfail when the library is broken.
    pqcrypto 0.4.0 always returns False — this will return False on that version.
    """
    pk, sk = ml_dsa_65.generate_keypair()
    sig = ml_dsa_65.sign(sk, b"__probe__")
    result = ml_dsa_65.verify(pk, sig, b"__probe__")
    return result is not False


# ─────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────
VERSION = "3.0.0"
CONTEXT = b"QuantumBlender-v3-Hybrid"
SALT_SIZE = 16
FINGERPRINT_LEN = 16  # bytes shown in fingerprint (32 hex chars)

# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
def setup_logging(verbose: bool, quiet: bool):
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format="%(message)s", level=level)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  Crypto Helpers
# ─────────────────────────────────────────────
def derive_hybrid_key(kem_ss: bytes, ecc_ss: bytes) -> bytes:
    """Blends Quantum (ML-KEM) and Classical (X25519) secrets into one master key.
    Salt derived from shared secrets for proper domain separation.
    """
    salt = hashlib.sha256(kem_ss + ecc_ss).digest()
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=salt,
        info=CONTEXT,
    ).derive(kem_ss + ecc_ss)


def key_fingerprint(pub_bundle: dict) -> str:
    """Returns a short human-readable fingerprint of a public key bundle."""
    raw = (pub_bundle.get("kem_pk", "") + pub_bundle.get("ecc_pk", "")).encode()
    digest = hashlib.sha256(raw).digest()[:FINGERPRINT_LEN]
    hex_fp = digest.hex().upper()
    # Format as groups of 4: ABCD:1234:...
    return ":".join(hex_fp[i:i+4] for i in range(0, len(hex_fp), 4))


def secure_shred(filepath: str, passes: int = 3):
    """Overwrites a file with random data before deleting it."""
    if not os.path.isfile(filepath):
        return
    file_size = os.path.getsize(filepath)
    with open(filepath, "ba+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(file_size))
    os.remove(filepath)


def protect_key(data_dict: dict, password: str) -> dict:
    """Encrypts a key bundle using a password (Scrypt + AES-256-GCM).
    Uses n=2^17 per OWASP recommendation for key-file protection.
    """
    salt = os.urandom(SALT_SIZE)
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    derived_key = kdf.derive(password.encode())
    aes = AESGCM(derived_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data_dict).encode()
    ciphertext = aes.encrypt(nonce, plaintext, CONTEXT)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "payload": base64.b64encode(ciphertext).decode(),
    }


def unprotect_key(encrypted_bundle: dict, password: str) -> dict:
    """Decrypts a key bundle using a password."""
    salt = base64.b64decode(encrypted_bundle["salt"])
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    derived_key = kdf.derive(password.encode())
    aes = AESGCM(derived_key)
    try:
        plaintext = aes.decrypt(
            base64.b64decode(encrypted_bundle["nonce"]),
            base64.b64decode(encrypted_bundle["payload"]),
            CONTEXT,
        )
        return json.loads(plaintext.decode())
    except Exception:
        click.secho("[!] Incorrect password or corrupted key file!", fg="red", bold=True)
        sys.exit(1)


# ─────────────────────────────────────────────
#  CLI Root
# ─────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress all non-error output.")
@click.version_option(VERSION, prog_name="Quantum Blender")
@click.pass_context
def cli(ctx, verbose, quiet):
    """
    \b
    🌀 QUANTUM BLENDER v3.0
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Hybrid Post-Quantum Cryptography Tool
    ML-KEM-768 + X25519 | ML-DSA-65 Signatures
    AES-256-GCM | Scrypt Key Protection
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    setup_logging(verbose, quiet)

    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ─────────────────────────────────────────────
#  KEYGEN
# ─────────────────────────────────────────────
@cli.command()
@click.argument("name")
@click.password_option(help="Password to protect your private key.")
@click.option("--expires-days", default=0, type=int,
              help="Optional key expiry in days (0 = no expiry).")
@click.pass_context
def keygen(ctx, name, password, expires_days):
    """Generate a password-protected hybrid identity (KEM + Signature)."""
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        click.secho(f"\n[*] Sculpting hybrid keys for '{name}'...", fg="yellow")

    # KEM keys (encryption)
    kem_pk, kem_sk = ml_kem_768.generate_keypair()

    # ECC keys (encryption)
    ecc_sk = x25519.X25519PrivateKey.generate()
    ecc_pk = ecc_sk.public_key()

    # DSA keys (signing)
    dsa_pk, dsa_sk = ml_dsa_65.generate_keypair()

    # Expiry timestamp
    expires_at = None
    if expires_days > 0:
        expires_at = int(time.time()) + expires_days * 86400

    pub = {
        "version": VERSION,
        "name": name,
        "created_at": int(time.time()),
        "expires_at": expires_at,
        "kem_pk": base64.b64encode(kem_pk).decode(),
        "ecc_pk": base64.b64encode(ecc_pk.public_bytes_raw()).decode(),
        "dsa_pk": base64.b64encode(dsa_pk).decode(),
    }

    priv_raw = {
        "version": VERSION,
        "name": name,
        "kem_sk": base64.b64encode(kem_sk).decode(),
        "ecc_sk": base64.b64encode(ecc_sk.private_bytes_raw()).decode(),
        "dsa_sk": base64.b64encode(dsa_sk).decode(),
    }

    protected_priv = protect_key(priv_raw, password)

    pub_path = f"{name}.pub"
    priv_path = f"{name}.priv"
    with open(pub_path, "w") as f:
        json.dump(pub, f, indent=2)
    with open(priv_path, "w") as f:
        json.dump(protected_priv, f, indent=2)

    fp = key_fingerprint(pub)

    if not quiet:
        click.secho(f"\n[+] Identity '{name}' created successfully!", fg="green", bold=True)
        click.echo(f"    Public  : {pub_path}  (Share this)")
        click.echo(f"    Private : {priv_path}  (Password-protected)")
        if expires_days:
            click.secho(f"    Expires : {expires_days} days from now", fg="yellow")
        click.secho(f"\n    Fingerprint: {fp}", fg="cyan")
        click.echo("    Share the fingerprint out-of-band to verify key authenticity.\n")


# ─────────────────────────────────────────────
#  FINGERPRINT
# ─────────────────────────────────────────────
@cli.command()
@click.argument("pubkey", type=click.Path(exists=True))
def fingerprint(pubkey):
    """Display the fingerprint of a public key file."""
    with open(pubkey, "r") as f:
        pub = json.load(f)

    fp = key_fingerprint(pub)
    name = pub.get("name", "unknown")
    created = pub.get("created_at")
    expires = pub.get("expires_at")

    click.secho(f"\n  Key Identity  : {name}", fg="cyan", bold=True)
    click.secho(f"  Fingerprint   : {fp}", fg="green", bold=True)

    if created:
        dt = datetime.fromtimestamp(created, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        click.echo(f"  Created       : {dt}")

    if expires:
        dt = datetime.fromtimestamp(expires, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        now = time.time()
        if now > expires:
            click.secho(f"  Expires       : {dt}  ⚠️  EXPIRED", fg="red")
        else:
            days_left = int((expires - now) / 86400)
            click.secho(f"  Expires       : {dt}  ({days_left} days remaining)", fg="yellow")
    else:
        click.echo("  Expires       : Never")
    click.echo()


# ─────────────────────────────────────────────
#  ENCRYPT
# ─────────────────────────────────────────────
@cli.command()
@click.option("--input", "-i", required=True, help="File to encrypt.")
@click.option("--key", "-k", required=True, multiple=True,
              help="Recipient .pub file. Repeat for multiple recipients.")
@click.option("--sign-key", "-s", default=None,
              help="Your .priv file to sign the ciphertext.")
@click.option("--output", "-o", default=None,
              help="Output filename (default: <input>.qb).")
@click.option("--shred", is_flag=True,
              help="Securely wipe the original file after encryption.")
@click.pass_context
def encrypt(ctx, input, key, sign_key, output, shred):
    """Encrypt a file for one or more recipients, with optional signing."""
    quiet = ctx.obj.get("quiet", False)

    if not os.path.exists(input):
        click.secho(f"[!] File '{input}' not found.", fg="red")
        sys.exit(1)

    with open(input, "rb") as f:
        data = f.read()

    recipients = []
    for k in key:
        with open(k, "r") as f:
            pub = json.load(f)

        # Check expiry
        expires = pub.get("expires_at")
        if expires and time.time() > expires:
            click.secho(f"[!] Key '{k}' has expired! Aborting.", fg="red")
            sys.exit(1)

        kem_pk = base64.b64decode(pub["kem_pk"])
        ecc_pk_bytes = base64.b64decode(pub["ecc_pk"])
        ecc_pk = x25519.X25519PublicKey.from_public_bytes(ecc_pk_bytes)

        kem_ct, kem_ss = ml_kem_768.encrypt(kem_pk)
        ephemeral_ecc_sk = x25519.X25519PrivateKey.generate()
        ecc_ss = ephemeral_ecc_sk.exchange(ecc_pk)
        derived_key = derive_hybrid_key(kem_ss, ecc_ss)

        aes = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data, CONTEXT)

        recipients.append({
            "name": pub.get("name", "unknown"),
            "fingerprint": key_fingerprint(pub),
            "kem_ct": base64.b64encode(kem_ct).decode(),
            "ecc_ct": base64.b64encode(ephemeral_ecc_sk.public_key().public_bytes_raw()).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "payload": base64.b64encode(ciphertext).decode(),
        })

    # Optional signing
    signature = None
    signer_fingerprint = None
    signer_name = None
    if sign_key:
        password = click.prompt("[?] Password for signing key", hide_input=True)
        with open(sign_key, "r") as f:
            protected_priv = json.load(f)
        priv_bundle = unprotect_key(protected_priv, password)
        dsa_sk = base64.b64decode(priv_bundle["dsa_sk"])

        # Sign the raw plaintext
        sig_bytes = ml_dsa_65.sign(dsa_sk, data)
        signature = base64.b64encode(sig_bytes).decode()

        # Load matching pub for fingerprint
        pub_guess = sign_key.replace(".priv", ".pub")
        if os.path.exists(pub_guess):
            with open(pub_guess, "r") as f:
                signer_pub = json.load(f)
            signer_fingerprint = key_fingerprint(signer_pub)
            signer_name = signer_pub.get("name", "unknown")

    package = {
        "version": VERSION,
        "encrypted_at": int(time.time()),
        "recipients": recipients,
        "signature": signature,
        "signer_name": signer_name,
        "signer_fingerprint": signer_fingerprint,
    }

    out_name = output if output else input + ".qb"
    with open(out_name, "w") as f:
        json.dump(package, f, indent=2)

    if not quiet:
        click.secho(f"\n[+] Encrypted → {out_name}", fg="cyan", bold=True)
        for r in recipients:
            click.echo(f"    Recipient : {r['name']}  [{r['fingerprint']}]")
        if signature:
            click.secho(f"    Signed by : {signer_name}  [{signer_fingerprint}]", fg="green")
        click.echo()

    if shred:
        if not quiet:
            click.echo("[*] Shredding original file...")
        secure_shred(input)
        if not quiet:
            click.secho("[+] Original file securely wiped.\n", fg="yellow")


# ─────────────────────────────────────────────
#  DECRYPT
# ─────────────────────────────────────────────
@cli.command()
@click.option("--input", "-i", required=True, help=".qb file to decrypt.")
@click.option("--key", "-k", required=True, help="Your .priv file.")
@click.option("--verify-key", "-vk", default=None,
              help="Sender's .pub file to verify signature.")
@click.option("--output", "-o", default=None,
              help="Output filename (default: <input>.decrypted).")
@click.pass_context
def decrypt(ctx, input, key, verify_key, output):
    """Decrypt a .qb file using your private key."""
    quiet = ctx.obj.get("quiet", False)

    with open(input, "r") as f:
        pkg = json.load(f)
    with open(key, "r") as f:
        protected_priv = json.load(f)

    password = click.prompt("[?] Password for private key", hide_input=True)
    priv_bundle = unprotect_key(protected_priv, password)

    kem_sk = base64.b64decode(priv_bundle["kem_sk"])
    ecc_sk = x25519.X25519PrivateKey.from_private_bytes(
        base64.b64decode(priv_bundle["ecc_sk"])
    )

    # Find matching recipient slot
    recipients = pkg.get("recipients", [])
    decrypted_data = None

    for slot in recipients:
        try:
            kem_ss = ml_kem_768.decrypt(kem_sk, base64.b64decode(slot["kem_ct"]))
            remote_ecc_pk = x25519.X25519PublicKey.from_public_bytes(
                base64.b64decode(slot["ecc_ct"])
            )
            ecc_ss = ecc_sk.exchange(remote_ecc_pk)
            master_key = derive_hybrid_key(kem_ss, ecc_ss)
            aes = AESGCM(master_key)
            decrypted_data = aes.decrypt(
                base64.b64decode(slot["nonce"]),
                base64.b64decode(slot["payload"]),
                CONTEXT,
            )
            if not quiet:
                click.secho(f"\n[+] Matched recipient slot: {slot.get('name', 'unknown')}", fg="green")
            break
        except Exception:
            continue

    if decrypted_data is None:
        click.secho("[!] Decryption failed — no matching recipient slot found.", fg="red")
        sys.exit(1)

    # Signature verification
    sig = pkg.get("signature")
    if sig:
        if verify_key:
            with open(verify_key, "r") as f:
                sender_pub = json.load(f)
            dsa_pk = base64.b64decode(sender_pub["dsa_pk"])
            try:
                _mldsa_verify(dsa_pk, base64.b64decode(sig), decrypted_data)
                sname = sender_pub.get("name", "unknown")
                sfp = key_fingerprint(sender_pub)
                click.secho(f"[+] Signature VALID — from {sname} [{sfp}]", fg="green", bold=True)
            except ValueError as e:
                click.secho("[!] Signature INVALID — file may be tampered!", fg="red", bold=True)
                click.secho(f"    Reason: {e}", fg="red")
                sys.exit(1)
        else:
            signer_name = pkg.get("signer_name", "unknown")
            signer_fp = pkg.get("signer_fingerprint", "N/A")
            click.secho(
                f"[~] File is signed by '{signer_name}' [{signer_fp}] "
                f"but no --verify-key provided. Signature not checked.",
                fg="yellow",
            )
    else:
        if not quiet:
            click.secho("[~] No signature present in this bundle.", fg="yellow")

    out_file = output if output else input.replace(".qb", ".decrypted")
    with open(out_file, "wb") as f:
        f.write(decrypted_data)

    if not quiet:
        click.secho(f"[+] Saved to: {out_file}\n", fg="cyan", bold=True)


# ─────────────────────────────────────────────
#  SIGN (standalone)
# ─────────────────────────────────────────────
@cli.command()
@click.option("--input", "-i", required=True, help="File to sign.")
@click.option("--key", "-k", required=True, help="Your .priv file.")
@click.option("--output", "-o", default=None,
              help="Output .sig file (default: <input>.sig).")
@click.pass_context
def sign(ctx, input, key, output):
    """Detached sign a file with your ML-DSA-65 private key."""
    quiet = ctx.obj.get("quiet", False)

    with open(input, "rb") as f:
        data = f.read()
    with open(key, "r") as f:
        protected_priv = json.load(f)

    password = click.prompt("[?] Password for private key", hide_input=True)
    priv_bundle = unprotect_key(protected_priv, password)
    dsa_sk = base64.b64decode(priv_bundle["dsa_sk"])

    sig_bytes = ml_dsa_65.sign(dsa_sk, data)

    out_file = output if output else input + ".sig"
    sig_bundle = {
        "version": VERSION,
        "signed_at": int(time.time()),
        "signature": base64.b64encode(sig_bytes).decode(),
    }
    with open(out_file, "w") as f:
        json.dump(sig_bundle, f, indent=2)

    if not quiet:
        click.secho(f"[+] Signature saved to: {out_file}\n", fg="green")


# ─────────────────────────────────────────────
#  VERIFY (standalone)
# ─────────────────────────────────────────────
@cli.command()
@click.option("--input", "-i", required=True, help="Original file to verify.")
@click.option("--sig", "-s", required=True, help=".sig file.")
@click.option("--key", "-k", required=True, help="Signer's .pub file.")
def verify(input, sig, key):
    """Verify a detached signature against a file."""
    with open(input, "rb") as f:
        data = f.read()
    with open(sig, "r") as f:
        sig_bundle = json.load(f)
    with open(key, "r") as f:
        pub = json.load(f)

    dsa_pk = base64.b64decode(pub["dsa_pk"])
    sig_bytes = base64.b64decode(sig_bundle["signature"])

    try:
        _mldsa_verify(dsa_pk, sig_bytes, data)
        name = pub.get("name", "unknown")
        fp = key_fingerprint(pub)
        click.secho(f"\n[+] Signature VALID", fg="green", bold=True)
        click.echo(f"    Signer : {name}  [{fp}]\n")
    except ValueError as e:
        click.secho("\n[!] Signature INVALID — file may be tampered or wrong key!\n",
                    fg="red", bold=True)
        click.secho(f"    Reason: {e}", fg="red")
        sys.exit(1)


# ─────────────────────────────────────────────
#  SHRED (standalone)
# ─────────────────────────────────────────────
@cli.command()
@click.argument("files", nargs=-1, required=True)
@click.option("--passes", default=3, show_default=True,
              help="Number of overwrite passes.")
def shred(files, passes):
    """Securely wipe one or more files from disk."""
    for filepath in files:
        if not os.path.isfile(filepath):
            click.secho(f"[!] '{filepath}' not found, skipping.", fg="yellow")
            continue
        click.echo(f"[*] Shredding {filepath} ({passes} passes)...")
        secure_shred(filepath, passes)
        click.secho(f"[+] '{filepath}' wiped.", fg="green")
    click.echo()


# ─────────────────────────────────────────────
#  INFO
# ─────────────────────────────────────────────
@cli.command()
def info():
    """Display algorithm and version information."""
    click.secho(f"\n  🌀 Quantum Blender v{VERSION}", fg="cyan", bold=True)
    click.echo("  ─────────────────────────────────────────")
    click.echo("  Encryption  : Hybrid ML-KEM-768 + X25519")
    click.echo("  Signing     : ML-DSA-65 (Dilithium3)")
    click.echo("  KDF         : Scrypt (n=2^17, r=8, p=1)")
    click.echo("  AEAD        : AES-256-GCM")
    click.echo("  KDF (hybrid): HKDF-SHA384")
    click.echo("  Shredding   : 3-pass random overwrite")
    click.echo("  ─────────────────────────────────────────")
    click.echo("  NIST PQC Standards: FIPS 203 (ML-KEM),")
    click.echo("                      FIPS 204 (ML-DSA)\n")


if __name__ == "__main__":
    cli(obj={})
