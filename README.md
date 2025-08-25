
 * CMAC Verifier for NTAG424 DNA SUN Mode
 *
 * This module provides secure verification of NFC tag authenticity using AES-128-CMAC
 * authentication for NTAG424 DNA chips operating in SUN (Secure Unique NFC) mode.
 *
 * ## NFC Scan URL Format
 * The NFC scan always produces a URL with query parameters in this format:
 * `?uid=xxxxxxxxxxxxxx&ctr=xxxxxx&mac=xxxxxxxxxxxxxxxx`
 *
 * ## Parameter Specifications
 * - uid: 14 hex characters (7 bytes) - Unique identifier of the NFC tag
 * - ctr: 6 hex characters (3 bytes) - Counter value that increments with each scan
 * - mac: 16 hex characters (8 bytes) - Truncated CMAC for verification
 * - aesKeyHex: 32 hex characters (16 bytes) - AES-128 encryption key
 *
 * ## CMAC Message Construction
 * The message authenticated by CMAC consists of:
 * [UID (7 bytes)] + [CT (3 bytes)] + [CTR (3 bytes)]
 *
 * Where CT is a constant: 0x88 0x04 0x00
 *
 * ## Security Features
 * - Uses RFC 4493 compliant AES-128-CMAC implementation
 * - Strict input validation for all parameters
 * - Constant-time comparison for MAC verification
 * - No dependency on potentially vulnerable external CMAC libraries
 *
