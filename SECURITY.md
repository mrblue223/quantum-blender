# Security Policy

## Reporting a Vulnerability
Do NOT open a public GitHub issue for security bugs.
Open a private advisory at: https://github.com/YOUR_USERNAME/quantum-blender/security/advisories/new

## Known Issues
- **pqcrypto 0.4.0**: `ml_dsa_65.verify()` is non-functional (always returns False).
  `_mldsa_verify()` detects this and raises ValueError instead of silently accepting.
  All signature verification calls will fail until upstream is fixed.
- **secure_shred()**: Best-effort only on SSDs and journaling filesystems
  (ext4, APFS, NTFS) — wear-leveling may retain data in unaddressable blocks.
