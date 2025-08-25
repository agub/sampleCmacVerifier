/**
 * @version 1.0.0
 * @since 2025-08-25
 */

import crypto from 'crypto'

interface VerificationResult {
	verified: boolean
	expectedMac?: string
	reason?: string
}

/**
 * Converts hex string to Uint8Array
 * @param hex - Hex string (without 0x prefix)
 * @returns Uint8Array representation
 */
function hexToBytes(hex: string): Uint8Array {
	if (hex.length % 2 !== 0) {
		throw new Error('Invalid hex string length')
	}
	const bytes = new Uint8Array(hex.length / 2)
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
	}
	return bytes
}

/**
 * Converts Uint8Array to hex string
 * @param bytes - Uint8Array to convert
 * @returns Uppercase hex string
 */
function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('')
		.toUpperCase()
}

/**
 * Validates hex string format
 * @param value - String to validate
 * @param expectedLength - Expected length in hex characters
 * @param name - Name for error messages
 * @returns Error message or null if valid
 */
function validateHexString(
	value: string,
	expectedLength: number,
	name: string
): string | null {
	if (!value) {
		return `Missing ${name}`
	}

	if (value.length !== expectedLength) {
		return `${name} must be ${expectedLength} hex characters (${
			expectedLength / 2
		} bytes), got ${value.length} chars`
	}

	const hexPattern = new RegExp(`^[0-9A-Fa-f]{${expectedLength}}$`)
	if (!hexPattern.test(value)) {
		return `${name} must be ${expectedLength} hex characters`
	}

	return null
}

/**
 * Validates all input parameters
 * @param uid - UID hex string (14 chars)
 * @param ctr - Counter hex string (6 chars)
 * @param mac - MAC hex string (16 chars)
 * @param aesKeyHex - AES key hex string (32 chars)
 * @returns Error message or null if all valid
 */
function validateInputs(
	uid: string,
	ctr: string,
	mac: string,
	aesKeyHex: string
): string | null {
	// Validate UID (7 bytes = 14 hex chars)
	const uidError = validateHexString(uid, 14, 'UID')
	if (uidError) return uidError

	// Validate CTR (3 bytes = 6 hex chars)
	const ctrError = validateHexString(ctr, 6, 'CTR')
	if (ctrError) return ctrError

	// Validate MAC (8 bytes = 16 hex chars)
	const macError = validateHexString(mac, 16, 'MAC')
	if (macError) return macError

	// Validate AES key (16 bytes = 32 hex chars)
	const keyError = validateHexString(aesKeyHex, 32, 'AES key')
	if (keyError) return keyError

	return null
}

/**
 * Computes AES-128-CMAC using Node.js crypto API
 * Implementation based on RFC 4493
 * @param key - 16-byte AES key
 * @param message - Message to authenticate
 * @returns Full 16-byte CMAC
 */
function computeCMAC(key: Uint8Array, message: Uint8Array): Uint8Array {
	// AES block size is 16 bytes
	const BLOCK_SIZE = 16

	// Step 1: Generate subkeys K1 and K2
	const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
	cipher.setAutoPadding(false)

	// L = AES-128(K, 0^128)
	const zeroBlock = new Uint8Array(BLOCK_SIZE)
	const L = new Uint8Array(cipher.update(zeroBlock))

	// Generate K1 and K2 subkeys
	const K1 = leftShift(L)
	if (L[0] & 0x80) {
		K1[BLOCK_SIZE - 1] ^= 0x87 // XOR with Rb
	}

	const K2 = leftShift(K1)
	if (K1[0] & 0x80) {
		K2[BLOCK_SIZE - 1] ^= 0x87 // XOR with Rb
	}

	// Step 2: Process message
	const messageLength = message.length
	const numBlocks = Math.ceil(messageLength / BLOCK_SIZE)

	if (numBlocks === 0) {
		// Empty message case
		const finalBlock = new Uint8Array(BLOCK_SIZE)
		finalBlock[0] = 0x80 // Padding
		xorBytes(finalBlock, K2) // XOR with K2

		const finalCipher = crypto.createCipheriv('aes-128-ecb', key, null)
		finalCipher.setAutoPadding(false)
		return new Uint8Array(finalCipher.update(finalBlock))
	}

	// Process all complete blocks except the last
	let X = new Uint8Array(BLOCK_SIZE) // Initialize to zero

	for (let i = 0; i < numBlocks - 1; i++) {
		const block = message.slice(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE)
		xorBytes(X, block)

		const blockCipher = crypto.createCipheriv('aes-128-ecb', key, null)
		blockCipher.setAutoPadding(false)
		X = new Uint8Array(blockCipher.update(X))
	}

	// Process the last block
	const lastBlockStart = (numBlocks - 1) * BLOCK_SIZE
	const lastBlock = message.slice(lastBlockStart)

	let finalBlock: Uint8Array

	if (lastBlock.length === BLOCK_SIZE) {
		// Complete last block - XOR with K1
		finalBlock = new Uint8Array(lastBlock)
		xorBytes(finalBlock, K1)
	} else {
		// Incomplete last block - pad and XOR with K2
		finalBlock = new Uint8Array(BLOCK_SIZE)
		finalBlock.set(lastBlock)
		finalBlock[lastBlock.length] = 0x80 // Add padding
		xorBytes(finalBlock, K2)
	}

	xorBytes(X, finalBlock)

	const finalCipher = crypto.createCipheriv('aes-128-ecb', key, null)
	finalCipher.setAutoPadding(false)
	return new Uint8Array(finalCipher.update(X))
}

/**
 * Left shift a byte array by 1 bit
 * @param input - Input byte array
 * @returns New left-shifted byte array
 */
function leftShift(input: Uint8Array): Uint8Array {
	const output = new Uint8Array(input.length)
	let carry = 0

	for (let i = input.length - 1; i >= 0; i--) {
		const newCarry = (input[i] & 0x80) >>> 7
		output[i] = ((input[i] << 1) | carry) & 0xff
		carry = newCarry
	}

	return output
}

/**
 * XOR two byte arrays in place (modifies the first array)
 * @param a - First array (will be modified)
 * @param b - Second array
 */
function xorBytes(a: Uint8Array, b: Uint8Array): void {
	for (let i = 0; i < Math.min(a.length, b.length); i++) {
		a[i] ^= b[i]
	}
}

/**
 * Main verification function for NTAG424 DNA CMAC
 * @param uid - UID as 14 hex characters (7 bytes)
 * @param ctr - Counter as 6 hex characters (3 bytes)
 * @param mac - MAC as 16 hex characters (8 bytes, truncated CMAC)
 * @param aesKeyHex - AES-128 key as 32 hex characters (16 bytes)
 * @returns Verification result object
 */
export function verifyTag(
	uid: string,
	ctr: string,
	mac: string,
	aesKeyHex: string
): VerificationResult {
	try {
		// Validate all inputs
		const validationError = validateInputs(uid, ctr, mac, aesKeyHex)
		if (validationError) {
			return {
				verified: false,
				reason: validationError,
			}
		}

		// Convert hex strings to bytes
		const uidBytes = hexToBytes(uid)
		const ctrBytes = hexToBytes(ctr)
		const keyBytes = hexToBytes(aesKeyHex)

		// Construct CMAC message: UID (7 bytes) + CT (3 bytes) + CTR (3 bytes)
		const CT = new Uint8Array([0x88, 0x04, 0x00]) // Constant CT bytes
		const message = new Uint8Array(
			uidBytes.length + CT.length + ctrBytes.length
		)

		let offset = 0
		message.set(uidBytes, offset)
		offset += uidBytes.length
		message.set(CT, offset)
		offset += CT.length
		message.set(ctrBytes, offset)

		// Compute full CMAC
		const fullCmac = computeCMAC(keyBytes, message)

		// Truncate to first 8 bytes (16 hex chars)
		const truncatedCmac = fullCmac.slice(0, 8)
		const expectedMac = bytesToHex(truncatedCmac)

		// Compare with provided MAC (case-insensitive)
		const verified = expectedMac.toLowerCase() === mac.toLowerCase()

		return {
			verified,
			expectedMac,
			reason: verified
				? undefined
				: `MAC mismatch. Expected: ${expectedMac}, Got: ${mac.toUpperCase()}`,
		}
	} catch (error) {
		return {
			verified: false,
			reason: `Verification error: ${
				error instanceof Error ? error.message : 'Unknown error'
			}`,
		}
	}
}

