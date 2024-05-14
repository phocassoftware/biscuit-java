package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import net.i2p.crypto.eddsa.EdDSAEngine;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

/**
 * Abstract class for representing a key pair.
 */
public abstract class KeyPair {

    public enum KeyType {
        Ed25519,
        P256,
    }

    public abstract byte[] toBytes();

    public abstract String toHex();

    public abstract PrivateKey private_key();

    public abstract PublicKey public_key() throws NoSuchAlgorithmException, InvalidKeySpecException;

    public static String getHashAlgorithm(KeyType keyType) {
        switch (keyType) {
            case Ed25519:
                return Ed25519KeyPair.ed25519.getHashAlgorithm();
            case P256:
                return P256KeyPair.HASH_ALGORITHM;
            default:
                throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }
    }

    public static KeyPair generateKeyPair(SecureRandom secureRandom, KeyType keyType) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        switch (keyType) {
            case Ed25519:
                return new Ed25519KeyPair(secureRandom);
            case P256:
                return new P256KeyPair(secureRandom);
            default:
                throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }
    }

    public static KeyPair generateKeyPair(byte[] bytes, KeyType keyType) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        switch (keyType) {
            case Ed25519:
                return new Ed25519KeyPair(bytes);
            case P256:
                return new P256KeyPair(bytes);
            default:
                throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }
    }

    public static Optional<Signature> signatureForAlgorithm(Schema.PublicKey.Algorithm algorithm) throws NoSuchAlgorithmException {
        var sgr = Optional.<Signature>empty();
        if (algorithm == Schema.PublicKey.Algorithm.Ed25519) {
            sgr = Optional.of(new EdDSAEngine(MessageDigest.getInstance(getHashAlgorithm(KeyPair.KeyType.Ed25519))));
        } else if (algorithm == Schema.PublicKey.Algorithm.P256) {
            sgr = Optional.of(Signature.getInstance(getHashAlgorithm(KeyPair.KeyType.P256)));
        }
        return sgr;
    }
}
