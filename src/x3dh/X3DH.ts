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

export interface X3DHSession {
  identityKey: IdentityKeyPair;
  preKeys: PreKeyPair[];
  signedPreKey: SignedPreKeyPair;
}

export class X3DH {
  private session: X3DHSession;

  constructor() {
    this.session = this.initializeSession();
  }

  private initializeSession(): X3DHSession {
    const identityKey = CryptoUtils.generateKeyPair();
    const preKeys = Array(10)
      .fill(null)
      .map(() => CryptoUtils.generatePreKey());
    const signedPreKey = CryptoUtils.generateSignedPreKey(
      identityKey.privateKey
    );

    return {
      identityKey,
      preKeys,
      signedPreKey,
    };
  }

  public getPublicBundle(): {
    identityKey: string;
    preKeys: string[];
    signedPreKey: { publicKey: string; signature: string };
  } {
    return {
      identityKey: this.session.identityKey.publicKey,
      preKeys: this.session.preKeys.map((pk) => pk.publicKey),
      signedPreKey: {
        publicKey: this.session.signedPreKey.publicKey,
        signature: this.session.signedPreKey.signature,
      },
    };
  }

  public encryptMessage(
    recipientBundle: {
      identityKey: string;
      preKeys: string[];
      signedPreKey: { publicKey: string; signature: string };
    },
    message: string
  ): {
    encryptedMessage: string;
    ephemeralKey: string;
    usedPreKeyIndex: number;
  } {
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

    // Combine all shared secrets with application info
    const sharedSecret = CryptoUtils.combineSharedSecrets([dh1, dh2, dh3, dh4]);

    // Encrypt the message
    const encryptedMessage = CryptoUtils.encrypt(message, sharedSecret);

    return {
      encryptedMessage,
      ephemeralKey: ephemeralKey.publicKey,
      usedPreKeyIndex,
    };
  }

  public decryptMessage(
    senderBundle: {
      identityKey: string;
      preKeys: string[];
      signedPreKey: { publicKey: string; signature: string };
    },
    encryptedMessage: string,
    ephemeralKey: string,
    usedPreKeyIndex: number
  ): string {
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

    // Combine all shared secrets with application info in the same order
    const sharedSecret = CryptoUtils.combineSharedSecrets([dh1, dh2, dh3, dh4]);

    // Decrypt the message
    return CryptoUtils.decrypt(encryptedMessage, sharedSecret);
  }
}
