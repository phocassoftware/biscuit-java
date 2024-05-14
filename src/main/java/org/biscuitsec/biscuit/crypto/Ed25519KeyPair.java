package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.biscuitsec.biscuit.token.builder.Utils;

import java.security.PrivateKey;
import java.security.SecureRandom;

public class Ed25519KeyPair extends KeyPair {
    public final EdDSAPrivateKey private_key;
    public final EdDSAPublicKey public_key;

    private static final int ED25519_PUBLIC_KEYSIZE = 32;
    private static final int ED25519_PRIVATE_KEYSIZE = 64;
    private static final int ED25519_SEED_SIZE = 32;

    protected static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);

    public Ed25519KeyPair() {
        this(new SecureRandom());
    }

    public Ed25519KeyPair(final SecureRandom rng) {
        byte[] b = new byte[32];
        rng.nextBytes(b);

        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(b, ed25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);

        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), ed25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);

        this.private_key = privKey;
        this.public_key = pubKey;
    }

    public Ed25519KeyPair(byte[] b) {
        EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(b, ed25519);
        EdDSAPrivateKey privKey = new EdDSAPrivateKey(privKeySpec);

        EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKey.getA(), ed25519);
        EdDSAPublicKey pubKey = new EdDSAPublicKey(pubKeySpec);

        this.private_key = privKey;
        this.public_key = pubKey;
    }

    public Ed25519KeyPair(String hex) {
        this(Utils.hexStringToByteArray(hex));
    }

    @Override
    public byte[] toBytes() {
        return this.private_key.getSeed();
    }

    @Override
    public String toHex() {
        return Utils.byteArrayToHexString(this.toBytes());
    }

    @Override
    public PrivateKey private_key() {
        return private_key;
    }

    @Override
    public PublicKey public_key() {
        return new PublicKey(Schema.PublicKey.Algorithm.Ed25519, this.public_key);
    }

    public static java.security.PublicKey public_key(byte[] data) {
        return new EdDSAPublicKey(new EdDSAPublicKeySpec(data, ed25519));
    }
}
