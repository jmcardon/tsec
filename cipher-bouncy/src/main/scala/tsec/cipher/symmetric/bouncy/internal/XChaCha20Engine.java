package tsec.cipher.symmetric.bouncy.internal;


import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.util.Pack;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.nio.charset.StandardCharsets;

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

    static int[] toIntArray(ByteBuffer in) {
        IntBuffer intBuffer = in.order(ByteOrder.LITTLE_ENDIAN).asIntBuffer();
        int[] ret = new int[intBuffer.remaining()];
        intBuffer.get(ret);
        return ret;
    }


    protected void setKey(byte[] keyBytes, byte[] ivBytes) {
        super.setKey(keyBytes, ivBytes);

        if (keyBytes == null) {
            throw new IllegalArgumentException(getAlgorithmName() + " doesn't support re-init with null key");
        }

        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires a 256 bit key");
        }

        int[] nonceInt = Pack.littleEndianToInt(ivBytes, 0, 6);

        int[] chachaKey = hChaCha20Internal(keyBytes, nonceInt);
        setSigma(engineState);
        setKey(engineState, chachaKey);
        engineState[14] = nonceInt[4];
        engineState[15] = nonceInt[5];
        engineState[12] = 1;
        engineState[13] = 0;
    }

    private static void setSigma(int[] state) {
        System.arraycopy(SIGMA, 0, state, 0, SIGMA.length);
    }

    private static void setKey(int[] state, final byte[] key) {
        int[] keyInt = Pack.littleEndianToInt(key, 0, KEY_SIZE_INTS);
        System.arraycopy(keyInt, 0, state, 4, KEY_SIZE_INTS);
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

    private static void shuffleState(final int[] state) {
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

    private  static int[] hChaCha20Internal(final byte[] key, final int[] nonceInt) {
        if (key.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException();
        }
        if (nonceInt.length < 4) {
            throw new IllegalArgumentException();
        }

        int[] x = new int[BLOCK_SIZE_INTS];
        int[] intKey = Pack.littleEndianToInt(key, 0, 8);

        setSigma(x);
        setKey(x, intKey);
        setIntNonce(x, nonceInt);
        shuffleState(x);
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
        shuffleState(x);
        System.arraycopy(x, 12, x, 4, 4);
        return Pack.intToLittleEndian(x);
    }

}
