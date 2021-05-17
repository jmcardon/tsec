package tsec.cipher.symmetric.bouncy.internal;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Pack;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * An internal class to use in tsec for the
 * ChaCha20 defined in https://tools.ietf.org/html/rfc7539.
 *
 * This construction uses a different nonce setup compared to the
 * regular ChaCha20 engine. As a result, I had to override a bunch of shit in the first place.
 * In particular, I had to override the initialization since the original construction
 * literally zeroes out word 13 from the initial block state, making the construction of the
 * nonce placement for the IETF version wrong, as well as the the fact that since it carries
 * internal state, it throws an exception from a private variable that checks for initialization despite me not having
 * any access to it whatsoever.
 *
 * This is not meant to be used outside of our invocations within our
 * Chacha20Poly1305IETF functions in tsec. If you choose to use this, it's at your own risk, and you're
 * better off copy pasting the code somewhere.
 *
 * A good chunk of code had to be copy pasted, but a significant amount was adapted to
 * conform to the spec.
 *
 */
public class ChaCha20IETFEngine implements StreamCipher {
    public String getAlgorithmName() {
        return "ChaCha20IETF";
    }

    static final int[] SIGMA =
            Pack.littleEndianToInt("expand 32-byte k".getBytes(StandardCharsets.US_ASCII), 0, 4);

    public ChaCha20IETFEngine() {
    }

    public final static int NONCE_SIZE_BYTES = 12;
    public final static int BLOCK_SIZE_INTS = 16;
    public final static int NONCE_SIZE_INTS = 3;
    public final static int KEY_SIZE_INTS = 8;
    public final static int KEY_SIZE_BYTES = 32;
    private final static int STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes
    private final static int ROUNDS = 20;

    private int index = 0;
    private byte[] keyStream = new byte[STATE_SIZE * 4]; // expanded state, 64 bytes
    protected int[] engineState = new int[STATE_SIZE]; // state
    protected int[] x = new int[STATE_SIZE]; // internal buffer

    public void wipe(){
        Arrays.fill(keyStream, (byte)0);
        Arrays.fill(engineState, 0);
        Arrays.fill(x, 0);
    }

    private static void setSigma(int[] state) {
        System.arraycopy(SIGMA, 0, state, 0, SIGMA.length);
    }

    private static void setKey(int[] state, int[] key) {
        System.arraycopy(key, 0, state, 4, KEY_SIZE_INTS);
    }

    private void ietfSetup(byte[] keyBytes, byte[] ivBytes) {
        if (keyBytes == null || keyBytes.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
        }

        if (ivBytes == null || ivBytes.length != NONCE_SIZE_BYTES) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 96 bit nonce");
        }

        int[] nonceInt = Pack.littleEndianToInt(ivBytes, 0, NONCE_SIZE_INTS);
        int[] keyInts = Pack.littleEndianToInt(keyBytes, 0, KEY_SIZE_INTS);

        setSigma(engineState);
        setKey(engineState, keyInts);
        engineState[12] = 0; // Counter
        engineState[13] = nonceInt[0];
        engineState[14] = nonceInt[1];
        engineState[15] = nonceInt[2];
    }

    public byte returnByte(byte in) {
        throw new IllegalArgumentException("Not used");
    }

    @Override
    public void reset() {
        throw new IllegalArgumentException("Not used");
    }

    /**
     * Initialise our ChaCha20 IETF cipher.
     * Similar to the ChaCha, whether it's encrypting or decrypting
     * is entirely symmetric so there is no boolean parameter with it.
     * <p>
     * We require this difference, as ChaCha20IETF engine has a different
     * Iv construction than the classic ChaCha20 spec. See the reference implementation
     * by the legend DJB
     * https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c#L72
     *
     * @param params the parameters required to set up the cipher.
     * @throws IllegalArgumentException if the params argument is
     *                                  inappropriate.
     */
    public void init(boolean unused, CipherParameters params) {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must include an IV");
        }

        ParametersWithIV ivParams = (ParametersWithIV) params;

        byte[] iv = ivParams.getIV();
        if (iv == null || iv.length != NONCE_SIZE_BYTES) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires exactly " + NONCE_SIZE_BYTES
                    + " bytes of IV");
        }

        CipherParameters keyParam = ivParams.getParameters();

        ietfSetup(((KeyParameter) keyParam).getKey(), iv);
        index = 0;
        ChaChaEngine.chachaCore(ROUNDS, engineState, x);
        Pack.intToLittleEndian(x, keyStream, 0);
    }


    /**
     * A necessary override, since the older `processBytes` checks for
     * `initialized` private variable defined in
     * Salsa20Engine, thus not allowing custom initialization of the engine
     * in an efficient way :|
     */
    public int processBytes(
            byte[] in,
            int inOff,
            int len,
            byte[] out,
            int outOff) {

        for (int i = 0; i < len; i++) {
            out[i + outOff] = (byte) (keyStream[index] ^ in[i + inOff]);
            index = (index + 1) & 63;

            if (index == 0) {
                advanceCounter();
                generateKeyStream(keyStream);
            }
        }

        return len;
    }

    private void generateKeyStream(byte[] output) {
        ChaChaEngine.chachaCore(ROUNDS, engineState, x);
        Pack.intToLittleEndian(x, output, 0);
    }

    private void advanceCounter() {
        if (++engineState[12] == 0) {
            ++engineState[13];
        }
    }

}
