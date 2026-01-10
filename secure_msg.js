const crypto = require('crypto');

class SecurityLayer {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
    }

    generateKeys() {
        console.log("[SecurityLayer] Generating RSA 2048-bit Key Pair...");
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
        });
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        console.log("[SecurityLayer] Keys Generated Successfully.");
    }

    calculateMD5(message) {
        return crypto.createHash('md5').update(message).digest('hex');
    }

    encryptPacket(message) {
        if (!this.publicKey) throw new Error("Public key not loaded.");

        // 1. Integrity Check (MD5)
        const msgHash = this.calculateMD5(message);

        // 2. Payload Construction
        const payload = `${message}::HASH::${msgHash}`;
        console.log(`[Sender] MD5 Hash of original message: ${msgHash}`);

        // 3. Encryption
        // Node.js crypto.publicEncrypt uses OAEP padding by default with RSA_PKCS1_OAEP_PADDING
        const buffer = Buffer.from(payload, 'utf8');
        const encrypted = crypto.publicEncrypt(
            {
                key: this.publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            buffer
        );

        return encrypted.toString('base64');
    }

    decryptPacket(ciphertextB64) {
        if (!this.privateKey) throw new Error("Private key not loaded.");

        try {
            const buffer = Buffer.from(ciphertextB64, 'base64');
            const decrypted = crypto.privateDecrypt(
                {
                    key: this.privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256",
                },
                buffer
            );

            const decryptedPayload = decrypted.toString('utf8');

            if (decryptedPayload.includes("::HASH::")) {
                const parts = decryptedPayload.split("::HASH::");
                // Handle case where message itself might contain the delimiter (unlikely but safe)
                const receivedHash = parts.pop();
                const message = parts.join("::HASH::");

                const calculatedHash = this.calculateMD5(message);

                console.log(`[Receiver] Calculated Hash: ${calculatedHash}`);
                console.log(`[Receiver] Received Hash:   ${receivedHash}`);

                if (calculatedHash === receivedHash) {
                    console.log("[Receiver] INTEGRITY CHECK PASSED (MD5 Matches)");
                    return message;
                } else {
                    return "ERROR: INTEGRITY CHECK FAILED! Message may have been tampered with.";
                }
            } else {
                return "ERROR: Invalid packet format.";
            }

        } catch (error) {
            return `Decryption Failed: ${error.message}`;
        }
    }
}

function main() {
    console.log("--- Assignment: Secure Messaging with SSH Keys & MD5 (Node.js) ---");

    const secLayer = new SecurityLayer();

    // 1. Setup Keys
    secLayer.generateKeys();

    // 2. User Input
    const originalMessage = "Confidential Assignment Data From Node.js";
    console.log(`\n[App] Original Message: '${originalMessage}'`);

    // 3. Simulate Network Transmission
    console.log("\n--- Sending Message ---");
    const encryptedPacket = secLayer.encryptPacket(originalMessage);
    console.log(`[Network] Encrypted Packet (Base64):\n${encryptedPacket.substring(0, 60)}...[truncated]`);

    // 4. Simulate Receiver
    console.log("\n--- Receiving Message ---");
    const decryptedMessage = secLayer.decryptPacket(encryptedPacket);
    console.log(`[App] Final Decrypted Message: '${decryptedMessage}'`);
}

main();
