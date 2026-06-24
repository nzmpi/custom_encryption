import crypto from "crypto";
import "dotenv/config";

const ALGORITHM = "aes-256-gcm" as const;
const IV_LENGTH = 12; // 96-bit nonce  (recommended for GCM)
const TAG_LENGTH = 16; // 128-bit authentication tag
const SALT_LENGTH = 32; // 256-bit KDF salt
const MIN_BUF_BYTES = IV_LENGTH + TAG_LENGTH + SALT_LENGTH; // 60 bytes
const PADDING_BLOCK_SIZE = 512;

/**
 * Encrypts `plaintext` with AES-256-GCM.
 *
 * A fresh random salt and IV are generated on every call, so encrypting the
 * same value twice produces different ciphertexts.
 *
 * @param plaintext - The UTF-8 string to encrypt. No length limit.
 * @param secret    - A high-entropy passphrase or key material.
 * @returns         - Hex-encoded wire payload.
 */
const encrypt = (plaintext: string, secret: string): string => {
    if (!plaintext) throw new Error("Plaintext is empty!");
    if (!secret) throw new Error("Secret is empty!");

    const salt = crypto.randomBytes(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(secret, salt);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    const padded = pad(Buffer.from(plaintext, "utf8"));
    const encrypted = Buffer.concat([
        cipher.update(padded, "utf8"),
        cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    return "0x" + Buffer.concat([salt, iv, authTag, encrypted]).toString("hex");
};

/**
 * Decrypts a hex payload produced by `encrypt`.
 *
 * AES-GCM authentication runs before any plaintext is returned. If the
 * secret is wrong, the IV is reused, or any byte of the ciphertext has been
 * modified, this function throws.
 *
 * @param hex    - Hex-encoded payload from `encrypt`.
 * @param secret - The same passphrase used to encrypt.
 * @returns      - The original UTF-8 plaintext.
 */
const decrypt = (hex: string, secret: string): string => {
    if (!hex) throw new Error("Ciphertext is empty!");
    if (!secret) throw new Error("Secret is empty!");

    const buf = Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex");

    if (buf.length <= MIN_BUF_BYTES) {
        throw new Error("Ciphertext is malformed or too short!");
    }

    // Slice components back out in the same order they were packed.
    let offset = 0;
    const salt = buf.subarray(offset, (offset += SALT_LENGTH));
    const iv = buf.subarray(offset, (offset += IV_LENGTH));
    const authTag = buf.subarray(offset, (offset += TAG_LENGTH));
    const encrypted = buf.subarray(offset);
    const key = deriveKey(secret, salt);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    try {
        const decrypted = Buffer.concat([
            decipher.update(encrypted),
            decipher.final(),
        ]);
        return unpad(decrypted).toString("utf8");
    } catch {
        throw new Error("Decryption failed!");
    }
};

/**
 * Pad data with garbage. The last 2 bytes are reserved for the garbage length.
 * @param data - Original data.
 * @returns    - Data with garbage.
 */
const pad = (data: Buffer): Buffer => {
    if (data.length > 510) throw new Error("Data is too big! Max is 510");
    const padLen = PADDING_BLOCK_SIZE - (data.length % PADDING_BLOCK_SIZE);
    const padding = crypto.randomBytes(padLen - 2);
    const lenByte = Buffer.alloc(2);
    lenByte.writeUInt16BE(padLen);

    return Buffer.concat([data, padding, lenByte]);
};

/**
 * Unpad garbage.
 * @param data - Padded data with garbage.
 * @returns    - Original data.
 */
const unpad = (data: Buffer): Buffer => {
    if (data.length === 0 || data.length % PADDING_BLOCK_SIZE !== 0) {
        throw new Error("Wrong data length to unpad!");
    }

    const padLen = data.readUInt16BE(data.length - 2);
    if (padLen < 2 || padLen > PADDING_BLOCK_SIZE || padLen > data.length) {
        throw new Error("Wrong pad length!");
    }
    return data.subarray(0, data.length - padLen);
};

const deriveKey = (secret: string, salt: Buffer): Buffer =>
    crypto.scryptSync(secret, salt, 32);

/**
 * Flags:
 * e - encrypt
 * d - decrypt
 */
if (!process.argv[2]) throw new Error("No flag provided!");
const flag: string = process.argv[2];
if (flag !== "e" && flag !== "d") throw new Error("Wrong flag provided!");

const secret = process.env.SECRET ?? "";
const textToEncrypt = process.env.TEXT_TO_ENCRYPT ?? "";
const textToDecrypt = process.env.TEXT_TO_DECRYPT ?? "";

if (flag === "e") {
    console.log("Encrypted:", encrypt(textToEncrypt, secret));
} else if (flag === "d") {
    console.log("Decrypted:", decrypt(textToDecrypt, secret));
} else {
    throw new Error("Can't be!");
}
