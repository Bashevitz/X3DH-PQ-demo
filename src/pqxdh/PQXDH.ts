import { MlKem1024 } from "mlkem";
import { CryptoUtils } from "../utils/crypto";

export interface IdentityKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface PreKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface SignedPreKeyPair extends PreKeyPair {
  signature: string;
}

export interface PQXDHSession {
  identityKey: IdentityKeyPair;
  preKeys: PreKeyPair[];
  signedPreKey: SignedPreKeyPair;
  kyberKeyPair: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
}

export class PQXDH {
  private session: PQXDHSession;
  private kyber: MlKem1024;

  private constructor(session: PQXDHSession) {
    this.kyber = new MlKem1024();
    this.session = session;
  }

  public static async create(): Promise<PQXDH> {
    const kyber = new MlKem1024();
    const session = await PQXDH.initializeSession(kyber);
    return new PQXDH(session);
  }

  private static async initializeSession(
    kyber: MlKem1024
  ): Promise<PQXDHSession> {
    const identityKey = CryptoUtils.generateKeyPair();
    const preKeys = Array(10)
      .fill(null)
      .map(() => CryptoUtils.generatePreKey());
    const signedPreKey = CryptoUtils.generateSignedPreKey(
      identityKey.privateKey
    );

    // Generate Kyber key pair
    const [kyberPublicKey, kyberPrivateKey] = await kyber.generateKeyPair();

    return {
      identityKey,
      preKeys,
      signedPreKey,
      kyberKeyPair: {
        publicKey: kyberPublicKey,
        privateKey: kyberPrivateKey,
      },
    };
  }

  public getPublicBundle(): {
    identityKey: string;
    preKeys: string[];
    signedPreKey: { publicKey: string; signature: string };
    kyberPublicKey: Uint8Array;
  } {
    return {
      identityKey: this.session.identityKey.publicKey,
      preKeys: this.session.preKeys.map((pk) => pk.publicKey),
      signedPreKey: {
        publicKey: this.session.signedPreKey.publicKey,
        signature: this.session.signedPreKey.signature,
      },
      kyberPublicKey: this.session.kyberKeyPair.publicKey,
    };
  }

  public async encryptMessage(
    recipientBundle: {
      identityKey: string;
      preKeys: string[];
      signedPreKey: { publicKey: string; signature: string };
      kyberPublicKey: Uint8Array;
    },
    message: string
  ): Promise<{
    encryptedMessage: string;
    ephemeralKey: string;
    usedPreKeyIndex: number;
    kyberCiphertext: Uint8Array;
  }> {
    // Generate ephemeral key
    const ephemeralKey = CryptoUtils.generateKeyPair();

    // Use the first available pre-key
    const usedPreKeyIndex = 0;
    const usedPreKey = recipientBundle.preKeys[usedPreKeyIndex];

    // Calculate all DH values
    const dh1 = CryptoUtils.deriveSharedSecret(
      this.session.identityKey.privateKey,
      recipientBundle.identityKey
    );

    const dh2 = CryptoUtils.deriveSharedSecret(
      ephemeralKey.privateKey,
      recipientBundle.identityKey
    );

    const dh3 = CryptoUtils.deriveSharedSecret(
      ephemeralKey.privateKey,
      usedPreKey
    );

    const dh4 = CryptoUtils.deriveSharedSecret(
      ephemeralKey.privateKey,
      recipientBundle.signedPreKey.publicKey
    );

    // Generate Kyber shared secret and ciphertext
    const [kyberCiphertext, kyberSharedSecret] = await this.kyber.encap(
      recipientBundle.kyberPublicKey
    );

    // Combine all shared secrets with application info
    const sharedSecret = CryptoUtils.combineSharedSecrets([
      dh1,
      dh2,
      dh3,
      dh4,
      Buffer.from(kyberSharedSecret).toString("base64"),
    ]);

    // Encrypt the message
    const encryptedMessage = CryptoUtils.encrypt(message, sharedSecret);

    return {
      encryptedMessage,
      ephemeralKey: ephemeralKey.publicKey,
      usedPreKeyIndex,
      kyberCiphertext,
    };
  }

  public async decryptMessage(
    senderBundle: {
      identityKey: string;
      preKeys: string[];
      signedPreKey: { publicKey: string; signature: string };
      kyberPublicKey: Uint8Array;
    },
    encryptedMessage: string,
    ephemeralKey: string,
    usedPreKeyIndex: number,
    kyberCiphertext: Uint8Array
  ): Promise<string> {
    const usedPreKey = this.session.preKeys[usedPreKeyIndex];

    // Calculate all DH values in the same order as encryption
    const dh1 = CryptoUtils.deriveSharedSecret(
      this.session.identityKey.privateKey,
      senderBundle.identityKey
    );

    const dh2 = CryptoUtils.deriveSharedSecret(
      this.session.identityKey.privateKey,
      ephemeralKey
    );

    const dh3 = CryptoUtils.deriveSharedSecret(
      usedPreKey.privateKey,
      ephemeralKey
    );

    const dh4 = CryptoUtils.deriveSharedSecret(
      this.session.signedPreKey.privateKey,
      ephemeralKey
    );

    // Decapsulate Kyber ciphertext to get shared secret
    const kyberSharedSecret = await this.kyber.decap(
      kyberCiphertext,
      this.session.kyberKeyPair.privateKey
    );

    // Combine all shared secrets with application info in the same order
    const sharedSecret = CryptoUtils.combineSharedSecrets([
      dh1,
      dh2,
      dh3,
      dh4,
      Buffer.from(kyberSharedSecret).toString("base64"),
    ]);

    // Decrypt the message
    return CryptoUtils.decrypt(encryptedMessage, sharedSecret);
  }
}
