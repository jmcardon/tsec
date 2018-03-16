package tsec.cipher.symmetric.bouncy.internal;


import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

import java.nio.charset.StandardCharsets;

/**
 * The actual XChaCha20 Engine, intended for use with the
 * XChaChaPoly1305 construction provided in tsec.
 *
 * This class draws inspiration from:
 * Libsodium xchacha implementation
 * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c
 *
 * Daniel J. Bernstein's Awesome XSalsa20 Paper:
 * https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 *
 * Tink's XChacha and Snuffle (How they organized their setKey, setSigma and quarterround)
 * https://github.com/google/tink/blob/master/java/src/main/java/com/google/crypto/tink/subtle/XChaCha20Poly1305.java
 *
 * Differences between Tink and this:
 * - No ByteBuffer allocs. Only using the functions provided by BouncyCastle's `Pack`, which are
 * essentially only loops. Those utilities allow the endian functions to be made in a nicer way.
 * - Still using the bouncycastle ChaCha for everything else. Might as well, unless I pretend to write
 * the whole primitive out a-la tink.
 * - `setKey` in terms of an int array, which is done beforehand by the implementation.
 *
 * If I'm incurring a bouncy dependency, it's simply not to rewrite the entire primitives myself.
 *
 *
 */
public class XChaCha20Engine extends ChaChaEngine {

    public String getAlgorithmName() {
        return "XChaCha20";
    }

    public final static int BLOCK_SIZE_BYTES = 64;
    public final static int NONCE_SIZE_BYTES = 24;
    public final static int KEY_SIZE_BYTES = 32;

    protected int getNonceSize() {
        return NONCE_SIZE_BYTES;
    }

    public final static int BLOCK_SIZE_INTS = 16;
    public final static int NONCE_SIZE_INTS = 6;
    public final static int KEY_SIZE_INTS = 8;


    static final int[] SIGMA =
            Pack.littleEndianToInt("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4);

    public XChaCha20Engine(){
        super(20);
    }


    /**
     * To reader: This one is a pretty deep rabbithole, so here we go:
     * DJB's initial Chacha representation:
     * https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c
     * RFC Paper:
     * https://tools.ietf.org/html/rfc7539
     *
     * XChacha20IETF is the ChaCha20 function defined over the same specification used in the XSalsa20 Paper,
     * simply applied to the ChaCha20 function. That is, the construction of the initial state for the
     * ChaCha20 IETF spec is applied. That being:
     * - Words 0 to 3 are the Sigma constant
     * - Words 4 to 11 are the key
     * - Words 12 to 15 are for counter (12) and nonce (13-15).
     *
     * HChacha20 is constructed Similar to XSalsa20 (See HSalsa20 Doc).
     *
     * We apply HSalsa20 over the key and 4 bytes of our little endian packed nonce. From there,
     * we derive a key to apply to the IETF variant of ChaCha20.
     *
     * Words 0 to 11 are set the same way as before. Word 12, our counter, is set to 1 after the
     * HChaCha20 application, and we then set the last three words with our remainder of our nonce
     * (with the first position zeroed out).
     *
     *
     */
    protected void setKey(byte[] keyBytes, byte[] ivBytes) {
        super.setKey(keyBytes, ivBytes);

        if (keyBytes == null || keyBytes.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
        }

        if (ivBytes == null || ivBytes.length != NONCE_SIZE_BYTES) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 192 bit nonce");
        }

        int[] nonceInt = Pack.littleEndianToInt(ivBytes, 0, 6);

        int[] chachaKey = hChaCha20Internal(keyBytes, nonceInt);
        setSigma(engineState);
        setKey(engineState, chachaKey);
        engineState[12] = 1; // Counter
        engineState[13] = 0;
        engineState[14] = nonceInt[4];
        engineState[15] = nonceInt[5];
    }

    private static void setSigma(int[] state) {
        System.arraycopy(SIGMA, 0, state, 0, SIGMA.length);
    }

    private static void setKey(int[] state, int[] key) {
        System.arraycopy(key, 0, state, 4, KEY_SIZE_INTS);
    }

    private static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = rotl(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = rotl(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = rotl(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = rotl(x[b] ^ x[c], 7);
    }

    private static void doubleRound(final int[] state) {
        for (int i = 0; i < 10; i++) {
            quarterRound(state, 0, 4, 8, 12);
            quarterRound(state, 1, 5, 9, 13);
            quarterRound(state, 2, 6, 10, 14);
            quarterRound(state, 3, 7, 11, 15);
            quarterRound(state, 0, 5, 10, 15);
            quarterRound(state, 1, 6, 11, 12);
            quarterRound(state, 2, 7, 8, 13);
            quarterRound(state, 3, 4, 9, 14);
        }
    }

    private static void setIntNonce(int[] state, int[] nonce) {
        System.arraycopy(nonce, 0, state, 12, 4);
    }

    /**
     * Extremely similar to the XSalsa20 Construction applied to
     * ChaCha20:
     *
     * - Sigma, key and nonce are set the same way.
     * - We apply doubleRound over the state
     * - return the little endian packed result.
     *
     * Note: This implementation foregoes extra checks as it is only meant to
     * be called _after_ checking the correct key size in
     * `set key`
     *
     * @param key our key, in bytes
     * @param nonceInt our nonce, in little endian format.
     * @return the hchacha20 output, as an integer array packed in
     * little endian format.
     */
    private static int[] hChaCha20Internal(final byte[] key, final int[] nonceInt) {
        int[] x = new int[BLOCK_SIZE_INTS];
        int[] intKey = Pack.littleEndianToInt(key, 0, 8);

        setSigma(x);
        setKey(x, intKey);
        setIntNonce(x, nonceInt);
        doubleRound(x);
        System.arraycopy(x, 12, x, 4, 4);
        return x;
    }

    public static byte[] hChaCha20Byte(final byte[] key, final int[] nonceInt) {
        return Pack.intToLittleEndian(hChaCha20Internal(key, nonceInt));
    }

    public static byte[] hChaCha20(final byte[] key, final byte[] nonce){
        if (key == null || key.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("HChaCha20 requires a 256 bit key");
        }
        if (nonce == null || nonce.length < 16) {
            throw new IllegalArgumentException("HChaCha20 requires a 256 bit key");
        }

        int[] x = new int[BLOCK_SIZE_INTS];
        int[] intKey = Pack.littleEndianToInt(key, 0, KEY_SIZE_INTS);
        int[] nonceInt = Pack.littleEndianToInt(nonce, 0, 4);
        setSigma(x);
        setKey(x, intKey);
        setIntNonce(x, nonceInt);
        doubleRound(x);
        System.arraycopy(x, 12, x, 4, 4);
        return Pack.intToLittleEndian(x);
    }

}
