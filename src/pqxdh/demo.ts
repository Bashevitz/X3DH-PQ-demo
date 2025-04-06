/**
 * Demo implementation of the Post-Quantum Extended Triple Diffie-Hellman (PQXDH) key exchange protocol
 * with Double Ratchet messaging encryption.
 * This demo shows how two parties (Alice and Bob) can establish a secure communication channel
 * using the PQXDH protocol, which provides forward secrecy, post-compromise security, and quantum resistance
 * through the use of Crystals-Kyber 1024.
 */

import { PQXDH } from "./PQXDH";
import { CryptoUtils } from "../utils/crypto";

/**
 * Main function demonstrating the PQXDH key exchange process and Double Ratchet messaging between two parties.
 * The process involves:
 * 1. Initializing PQXDH sessions for both parties
 * 2. Exchanging public bundles
 * 3. Generating and comparing safety numbers
 * 4. Multiple message exchanges with key ratcheting
 */
async function main() {
  console.log("Starting PQXDH Demo with Double Ratchet Messaging...\n");

  // Initialize PQXDH sessions for both parties
  // Each party generates their identity key, signed pre-key, one-time pre-keys, and Kyber key pair
  const alice = await PQXDH.create();
  const bob = await PQXDH.create();

  console.log("Alice and Bob have initialized their PQXDH sessions\n");

  // Bob shares his public bundle with Alice
  // This bundle contains Bob's identity key, signed pre-key, one-time pre-keys, and Kyber public key
  const bobBundle = bob.getPublicBundle();
  console.log("Bob has shared his public bundle with Alice\n");

  // Alice shares her public bundle with Bob
  // This bundle contains Alice's identity key, signed pre-key, one-time pre-keys, and Kyber public key
  const aliceBundle = alice.getPublicBundle();
  console.log("Alice has shared her public bundle with Bob\n");

  // Generate and compare safety numbers
  // This helps Alice and Bob verify they're communicating with the correct person
  const aliceSafetyNumber = CryptoUtils.generateSafetyNumber(
    aliceBundle.identityKey,
    bobBundle.identityKey
  );
  const bobSafetyNumber = CryptoUtils.generateSafetyNumber(
    bobBundle.identityKey,
    aliceBundle.identityKey
  );

  console.log("Safety Number Verification:");
  console.log("Alice's safety number:", aliceSafetyNumber);
  console.log("Bob's safety number:", bobSafetyNumber);
  console.log(
    "Safety numbers match:",
    aliceSafetyNumber === bobSafetyNumber,
    "\n"
  );

  // ! If these don't match throughout the conversation,
  // ! the communication is compromised and MITM is suspected

  // Simulate a conversation with multiple messages and key ratcheting
  const messages = [
    "Hello Bob! This is a quantum-resistant secret message.",
    "Hi Alice! Thanks for the message. How are you?",
    "I'm doing great! Working on some quantum-resistant encryption.",
    "That's fascinating! Tell me more about it.",
    "It's using PQXDH with Double Ratchet for perfect forward secrecy.",
  ];

  console.log("Starting encrypted conversation with key ratcheting...\n");

  for (let i = 0; i < messages.length; i++) {
    const isAlice = i % 2 === 0;
    const sender = isAlice ? alice : bob;
    const recipient = isAlice ? bob : alice;
    const senderBundle = isAlice ? aliceBundle : bobBundle;
    const recipientBundle = isAlice ? bobBundle : aliceBundle;
    const message = messages[i];

    console.log("\n");
    console.log("--------------------------------");
    console.log(`${isAlice ? "Alice" : "Bob"} is sending a message...`);
    console.log("Original message:", message);

    // Encrypt the message
    const encryptedMessage = await sender.encryptMessage(
      recipientBundle,
      message
    );
    console.log("Message encrypted with new ratcheted key");

    // Decrypt the message
    const decryptedMessage = await recipient.decryptMessage(
      senderBundle,
      encryptedMessage.encryptedMessage,
      encryptedMessage.ephemeralKey,
      encryptedMessage.usedPreKeyIndex,
      encryptedMessage.kyberCiphertext
    );

    console.log("Message decrypted successfully");
    console.log("Decrypted message:", decryptedMessage);
    console.log("Messages match:", message === decryptedMessage);
    console.log("Key ratcheting completed for this message");
    console.log("--------------------------------\n");
  }

  console.log("Conversation completed successfully!");
  console.log(
    "All messages were encrypted and decrypted with perfect forward secrecy"
  );
  console.log(
    "Each message used a new ratcheted key, ensuring security even if previous keys are compromised"
  );
}

// Run the demo
main().catch(console.error);
