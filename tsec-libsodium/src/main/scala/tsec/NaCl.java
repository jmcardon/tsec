/**
 * Forked from the kalium version,  by
 * Bruno Oliveira, and individual contributors
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tsec;

import jnr.ffi.LibraryLoader;
import jnr.ffi.Platform;
import jnr.ffi.annotations.In;
import jnr.ffi.annotations.Out;
import jnr.ffi.byref.LongLongByReference;
import jnr.ffi.types.u_int64_t;
import jnr.ffi.types.size_t;

public class NaCl {

    public static Sodium sodium() {
        Sodium sodium = SingletonHolder.SODIUM_INSTANCE;
        checkVersion(sodium);
        return sodium;
    }

    private static final String LIBRARY_NAME = libraryName();

    private static String libraryName() {
        switch (Platform.getNativePlatform().getOS()) {
            case WINDOWS:
                return "libsodium";
            default:
                return "sodium";
        }
    }

    private static final class SingletonHolder {
        public static final Sodium SODIUM_INSTANCE =
                LibraryLoader.create(Sodium.class)
                        .search("/usr/local/lib")
                        .search("/opt/local/lib")
                        .search("lib")
                        .load(LIBRARY_NAME);

    }

    public static final Integer[] MIN_SUPPORTED_VERSION =
            new Integer[] { 1, 0, 3 };

    private static boolean versionSupported = false;

    private static final void checkVersion(Sodium lib) {
        if (!versionSupported) {
            String[] version = lib.sodium_version_string().split("\\.");
            versionSupported = version.length >= 3 &&
                    MIN_SUPPORTED_VERSION[0] <= new Integer(version[0]) &&
                    MIN_SUPPORTED_VERSION[1] <= new Integer(version[1]) &&
                    MIN_SUPPORTED_VERSION[2] <= new Integer(version[2]);
        }
        if (!versionSupported) {
            String message = String.format("Unsupported libsodium version: %s. Please update",
                    lib.sodium_version_string());
            throw new UnsupportedOperationException(message);
        }
    }

    private NaCl() {
    }

    public interface Sodium {

        /**
         * This function isn't thread safe. Be sure to call it once, and before
         * performing other operations.
         *
         * Check libsodium's documentation for more info.
         */
        int sodium_init();

        String sodium_version_string();

        //--------------------------------------------------------------------
        // Argon2 password hashing
        int crypto_pwhash_SALTBYTES = 16;
        int crypto_pwhash_STRBYTES = 128;
        int crypto_pwhash_OPSLIMIT_SENSITIVE = 4;
        int crypto_pwhash_MEMLIMIT_SENSITIVE = 1073741824;

        int crypto_pwhash(@Out byte[] out, @In @u_int64_t int outLen,
                          @In byte[] passwd, @In @u_int64_t int passwdLen,
                          @In byte[] salt, @In @u_int64_t long opsLimit,
                          @In @size_t long memLimit, @In @u_int64_t int alg);

        int crypto_pwhash_str(@Out byte[] out, @In byte[] passwd, @In @u_int64_t long passwdLen,
                              @In @u_int64_t long opsLimit,
                              @In @size_t long memLimit);

        int crypto_pwhash_str_verify(@In byte[] str, @In byte[] passwd,
                                     @In @u_int64_t int passwdLen);

        // ---------------------------------------------------------------------
        // Generating Random Data

        void randombytes(@Out byte[] buffer, @In @u_int64_t int size);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authenticated encryption

        /**
         * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32;

        /**
         * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES
         */
        @Deprecated
        int XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES = 32;

        int CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES = 24;

        int crypto_secretbox_xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        int crypto_secretbox_xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: Authentication

        /**
         * @deprecated use CRYPTO_AUTH_HMACSHA512256_BYTESS
         */
        @Deprecated
        int HMACSHA512256_BYTES = 32;

        /**
         * @deprecated use CRYPTO_AUTH_HMACSHA512256_KEYBYTESS
         */
        @Deprecated
        int HMACSHA512256_KEYBYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_BYTES = 32;

        int CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32;

        int crypto_auth_hmacsha512256(
                @Out byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        int crypto_auth_hmacsha512256_verify(
                @In byte[] mac, @In byte[] message, @In @u_int64_t int sizeof,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Secret-key cryptography: AEAD

        int CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32;

        int CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8;

        int CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16;

        int crypto_aead_chacha20poly1305_keygen(@Out byte[] keyBytes);

        int crypto_aead_chacha20poly1305_encrypt(
                @Out byte[] ct, @Out LongLongByReference ctLength,
                @In byte[] message, @In @u_int64_t int messageLength,
                @In byte[] additionalData, @In @u_int64_t int adLength,
                @In byte[] nsec, @In byte[] npub, @In byte[] key);

        int crypto_aead_chacha20poly1305_decrypt(
                @Out byte[] message, @Out LongLongByReference messageLength,
                @In byte[] nsec, @In byte[] ct, @In @u_int64_t int ctLength,
                @In byte[] additionalData, @In @u_int64_t int adLength,
                @In byte[] npub, @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Authenticated encryption

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES
         */
        @Deprecated
        int PUBLICKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTESS
         */
        @Deprecated
        int SECRETKEY_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES
         */
        @Deprecated
        int NONCE_BYTES = 24;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTESS
         */
        @Deprecated
        int ZERO_BYTES = 32;

        /**
         * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES
         */
        @Deprecated
        int BOXZERO_BYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES -
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24;

        int CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32;

        int crypto_box_curve25519xsalsa20poly1305_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey);

        int crypto_box_curve25519xsalsa20poly1305_beforenm(
                @Out byte[] sharedkey, @In byte[] publicKey,
                @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_afternm(
                @Out byte[] ct, @In byte[] msg, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        int crypto_box_curve25519xsalsa20poly1305_open(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] publicKey, @In byte[] privateKey);

        int crypto_box_curve25519xsalsa20poly1305_open_afternm(
                @Out byte[] message, @In byte[] ct, @In @u_int64_t int length,
                @In byte[] nonce, @In byte[] shared);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Public-key signatures

        /**
         * @deprecated use the documented CRYPTO_SIGN_ED25519_BYTES.
         */
        @Deprecated
        int SIGNATURE_BYTES = 64;

        int CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32;

        int CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64;

        int CRYPTO_SIGN_ED25519_BYTES = 64;

        int crypto_sign_ed25519_seed_keypair(
                @Out byte[] publicKey, @Out byte[] secretKey, @In byte[] seed);

        int crypto_sign_ed25519(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] message, @In @u_int64_t int length,
                @In byte[] secretKey);

        int crypto_sign_ed25519_open(
                @Out byte[] buffer, @Out LongLongByReference bufferLen,
                @In byte[] sigAndMsg, @In @u_int64_t int length,
                @In byte[] key);

        // ---------------------------------------------------------------------
        // Public-key cryptography: Sealed boxes

        int CRYPTO_BOX_SEALBYTES =
                CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES +
                        CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES;

        int crypto_box_seal(
                @Out byte[] ct, @In byte[] message, @In @u_int64_t int length,
                @In byte[] publicKey);

        int crypto_box_seal_open(
                @Out byte[] message, @In byte[] c, @In @u_int64_t int length,
                @In byte[] publicKey, @In byte[] privateKey);

        // ---------------------------------------------------------------------
        // Hashing: Generic hashing

        /**
         * @deprecated use CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX. Note that
         * the Libsodium standard value is '32' and not '64' as defined here.
         */
        @Deprecated
        int BLAKE2B_OUTBYTES = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16;

        int CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64;

        int crypto_generichash_blake2b(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen);

        int crypto_generichash_blake2b_salt_personal(
                @Out byte[] buffer, @In @u_int64_t int outLen,
                @In byte[] message, @u_int64_t int messageLen, @In byte[] key,
                @In @u_int64_t int keyLen, @In byte[] salt,
                @In byte[] personal);

        // ---------------------------------------------------------------------
        // Hashing: Short-input hashing

        // TODO

        // ---------------------------------------------------------------------
        // Password hashing

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        /**
         * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
         */
        @Deprecated
        int PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;


        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288;

        int CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;

        int crypto_pwhash_scryptsalsa208sha256(
                @Out byte[] buffer, @In @u_int64_t int outlen,
                @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In byte[] salt,
                @In @u_int64_t long opslimit, @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str(
                @Out byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen, @In @u_int64_t long opslimit,
                @In @u_int64_t long memlimit);

        int crypto_pwhash_scryptsalsa208sha256_str_verify(
                @In byte[] buffer, @In byte[] passwd,
                @In @u_int64_t int passwdlen);

        // ---------------------------------------------------------------------
        // Advanced: AES256-GCM

        int CRYPTO_AEAD_AES256GCM_KEYBYTES = 32;

        int CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12;

        int CRYPTO_AEAD_AES256GCM_ABYTES = 16;

        /**
         * @return 1 if the current CPU supports the AES256-GCM implementation,
         *         and 0 if it doesn't.
         */
        int crypto_aead_aes256gcm_is_available();

        int crypto_aead_aes256gcm_encrypt(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In byte[] key);

        int crypto_aead_aes256gcm_decrypt(
                @Out byte[] msg, @Out LongLongByReference msgLen, @In byte[] nsec,
                @In byte[] ct, @In @u_int64_t int ctLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] npub, @In byte[] key);

        int crypto_aead_aes256gcm_statebytes();

        int crypto_aead_aes256gcm_beforenm(
                @Out byte[] state, @In byte[] key);

        int crypto_aead_aes256gcm_encrypt_afternm(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In @Out byte[] state);

        int crypto_aead_aes256gcm_decrypt_afternm(
                @Out byte[] ct, @Out LongLongByReference ctLen, @In byte[] msg,
                @In @u_int64_t int msgLen, @In byte[] ad,
                @In @u_int64_t int adLen, @In byte[] nsec, @In byte[] npub,
                @In @Out byte[] state);

        // ---------------------------------------------------------------------
        // Advanced: SHA-2

        /**
         * @deprecated use CRYPTO_HASH_SHA256_BYTES
         */
        int SHA256BYTES = 32;

        /**
         * @deprecated use CRYPTO_HASH_SHA512_BYTES
         */
        int SHA512BYTES = 64;

        int CRYPTO_HASH_SHA256_BYTES = 32;

        int crypto_hash_sha256(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        int CRYPTO_HASH_SHA512_BYTES = 64;

        int crypto_hash_sha512(
                @Out byte[] buffer, @In byte[] message,
                @In @u_int64_t int sizeof);

        // ---------------------------------------------------------------------
        // Advanced: HMAC-SHA-2

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: One-time authentication

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Diffie-Hellman

        int CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32;

        int CRYPTO_SCALARMULT_CURVE25519_BYTES = 32;

        int crypto_scalarmult_curve25519(
                @Out byte[] result, @In byte[] intValue, @In byte[] point);

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: ChaCha20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: Salsa20

        int CRYPTO_STREAM_KEYBYTES = 32;

        int CRYPTO_STREAM_NONCEBYTES = 24;

        int crypto_stream_xor(
                @Out byte[] result, @In byte[] message,
                @In @u_int64_t int mlen,
                @In byte[] nonce, @In byte[] key);

        // ---------------------------------------------------------------------
        // Advanced: Stream ciphers: XSalsa20

        // TODO

        // ---------------------------------------------------------------------
        // Advanced: Ed25519 to Curve25519

        //Argon2 stuff


    }

    /**
     * This is a Java synchronized wrapper around libsodium's init function.
     * LibSodium's init function is not thread-safe.
     *
     * Check libsodium's documentation for more info.
     */
    public static synchronized int init() {
        return sodium().sodium_init();
    }
}