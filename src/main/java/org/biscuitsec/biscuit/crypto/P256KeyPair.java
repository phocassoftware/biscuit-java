package org.biscuitsec.biscuit.crypto;

import biscuit.format.schema.Schema;
import org.biscuitsec.biscuit.token.builder.Utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class P256KeyPair extends KeyPair {

    private final java.security.KeyPair keyPair;

    protected static final String HASH_ALGORITHM = "SHA256withECDSA";

    public P256KeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        this(new SecureRandom());
    }

    public P256KeyPair(byte[] seed) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var kpg = KeyPairGenerator.getInstance("EC");
        var spec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(spec, new SecureRandom(seed));
        keyPair = kpg.generateKeyPair();
    }

    public P256KeyPair(SecureRandom rng) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        var kpg = KeyPairGenerator.getInstance("EC");
        var spec = new ECGenParameterSpec("secp256r1");
        kpg.initialize(spec, rng);
        keyPair = kpg.generateKeyPair();
    }

    public P256KeyPair(String hex) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        this(Utils.hexStringToByteArray(hex));
    }

    @Override
    public byte[] toBytes() {
        return keyPair.getPrivate().getEncoded();
    }

    @Override
    public String toHex() {
        return Utils.byteArrayToHexString(this.toBytes());
    }

    @Override
    public PrivateKey private_key() {
        return keyPair.getPrivate();
    }

    @Override
    public PublicKey public_key() throws NoSuchAlgorithmException, InvalidKeySpecException {
        return new PublicKey(Schema.PublicKey.Algorithm.P256, this.keyPair.getPublic().getEncoded());
    }

    public static java.security.PublicKey public_key(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(data, HASH_ALGORITHM));
    }
}
