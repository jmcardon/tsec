/* sodium.i */
%module Sodium

%include "typemaps.i"
%include "stdint.i"
%include "arrays_java.i"
%include "carrays.i"
%include "various.i"
%include "java.swg"
%include "typemaps.i"

/* Basic mappings */
%apply int {unsigned long long};
%apply long[] {unsigned long long *};
%apply int {size_t};
%apply int {uint32_t};
%apply long {uint64_t};

/*
Long typemap: Requires testing
%typemap(jni) unsigned long long, const unsigned long long & "jlong"
%typemap(jtype) unsigned long long, const unsigned long long & "long"
%typemap(jstype) unsigned long long, const unsigned long long & "long"
%typemap(jboxtype) unsigned long long, const unsigned long long & "Long"
%typemap(in) unsigned long long {
   $1 = ($1_ltype)$input;
}
%typemap(directorout) unsigned long long
%{ $result = ($1_ltype)$input; %}

%typemap(directorin, descriptor="J") unsigned long long  "$input = (jlong) $1;"
%typemap(javain) unsigned long long"$javainput"
%typemap(javadirectorin) unsigned long long  "$jniinput"
%typemap(javadirectorout) unsigned long long "$javacall"
%typemap(out) unsigned long long  %{ $result = (jlong)$1; %}
%typemap(freearg) unsigned long long "" --The default freearg should be fine
*/

/* unsigned char */
%typemap(jni) unsigned char *       "jbyteArray"
%typemap(jtype) unsigned char *     "byte[]"
%typemap(jstype) unsigned char *    "byte[]"
%typemap(in) unsigned char *{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) unsigned char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) unsigned char *"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char *""

/* unsigned char array */
%typemap(jni) unsigned char [ANY]       "jbyteArray"
%typemap(jtype) unsigned char [ANY]     "byte[]"
%typemap(jstype) unsigned char [ANY]    "byte[]"
%typemap(in) unsigned char [ANY]{
    $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) unsigned char [ANY]{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) unsigned char [ANY]"$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) unsigned char [ANY]""

/* uint8_t */
%typemap(jni) uint8_t *"jbyteArray"
%typemap(jtype) uint8_t *"byte[]"
%typemap(jstype) uint8_t *"byte[]"
%typemap(in) uint8_t *{
    $1 = (uint8_t *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) uint8_t *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) uint8_t *"$javainput"
%typemap(freearg) uint8_t *""

/* Strings */
%typemap(jni) char *"jbyteArray"
%typemap(jtype) char *"byte[]"
%typemap(jstype) char *"byte[]"
%typemap(in) char *{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *"$javainput"
%typemap(freearg) char *""


/* char types */
%typemap(jni) char *BYTE "jbyteArray"
%typemap(jtype) char *BYTE "byte[]"
%typemap(jstype) char *BYTE "byte[]"
%typemap(in) char *BYTE {
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char *BYTE {
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char *BYTE "$javainput"
/* Prevent default freearg typemap from being used */
%typemap(freearg) char *BYTE ""

/* Fixed size strings/char arrays */
%typemap(jni) char [ANY]"jbyteArray"
%typemap(jtype) char [ANY]"byte[]"
%typemap(jstype) char [ANY]"byte[]"
%typemap(in) char [ANY]{
    $1 = (char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) char [ANY]{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) char [ANY]"$javainput"
%typemap(freearg) char [ANY]""


/* =============================================================================

    TYPEMAPS FOR CRYPTO_*_STATE DATATYPES

============================================================================= */

/*
  Crypto secret stream
*/
%typemap(jni) crypto_secretstream_xchacha20poly1305_state *"jbyteArray"
%typemap(jtype) crypto_secretstream_xchacha20poly1305_state *"byte[]"
%typemap(jstype) crypto_secretstream_xchacha20poly1305_state *"byte[]"
%typemap(in) crypto_secretstream_xchacha20poly1305_state *{
    $1 = (crypto_secretstream_xchacha20poly1305_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_secretstream_xchacha20poly1305_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_secretstream_xchacha20poly1305_state *"$javainput"
%typemap(freearg) crypto_secretstream_xchacha20poly1305_state *""


/*
    crypto_generichash_state
*/
%typemap(jni) crypto_generichash_state *"jbyteArray"
%typemap(jtype) crypto_generichash_state *"byte[]"
%typemap(jstype) crypto_generichash_state *"byte[]"
%typemap(in) crypto_generichash_state *{
    $1 = (crypto_generichash_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_generichash_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_generichash_state *"$javainput"
%typemap(freearg) crypto_generichash_state *""

/*
    crypto_generichash_blake2b_state
*/
%typemap(jni) crypto_generichash_blake2b_state*"jbyteArray"
%typemap(jtype) crypto_generichash_blake2b_state *"byte[]"
%typemap(jstype) crypto_generichash_blake2b_state *"byte[]"
%typemap(in) crypto_generichash_blake2b_state *{
    $1 = (crypto_generichash_blake2b_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_generichash_blake2b_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_generichash_blake2b_state *"$javainput"
%typemap(freearg) crypto_generichash_blake2b_state *""

/*
    crypto_hash_sha256_state
*/
%typemap(jni) crypto_hash_sha256_state *"jbyteArray"
%typemap(jtype) crypto_hash_sha256_state *"byte[]"
%typemap(jstype) crypto_hash_sha256_state *"byte[]"
%typemap(in) crypto_hash_sha256_state *{
    $1 = (crypto_hash_sha256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_hash_sha256_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_hash_sha256_state *"$javainput"
%typemap(freearg) crypto_hash_sha256_state *""

/*
    crypto_hash_sha512_state
*/
%typemap(jni) crypto_hash_sha512_state *"jbyteArray"
%typemap(jtype) crypto_hash_sha512_state *"byte[]"
%typemap(jstype) crypto_hash_sha512_state *"byte[]"
%typemap(in) crypto_hash_sha512_state *{
    $1 = (crypto_hash_sha512_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_hash_sha512_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_hash_sha512_state *"$javainput"
%typemap(freearg) crypto_hash_sha512_state *""

/*
    crypto_onetimeauth_state
*/
%typemap(jni) crypto_onetimeauth_state *"jbyteArray"
%typemap(jtype) crypto_onetimeauth_state *"byte[]"
%typemap(jstype) crypto_onetimeauth_state *"byte[]"
%typemap(in) crypto_onetimeauth_state *{
    $1 = (crypto_onetimeauth_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_onetimeauth_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_onetimeauth_state *"$javainput"
%typemap(freearg) crypto_onetimeauth_state *""

/*
    crypto_onetimeauth_poly1305_state
*/
%typemap(jni) crypto_onetimeauth_poly1305_state *"jbyteArray"
%typemap(jtype) crypto_onetimeauth_poly1305_state *"byte[]"
%typemap(jstype) crypto_onetimeauth_poly1305_state *"byte[]"
%typemap(in) crypto_onetimeauth_poly1305_state *{
    $1 = (crypto_onetimeauth_poly1305_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_onetimeauth_poly1305_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_onetimeauth_poly1305_state *"$javainput"
%typemap(freearg) crypto_onetimeauth_poly1305_state *""

/*
    crypto_auth_hmacsha256_state
*/
%typemap(jni) crypto_auth_hmacsha256_state *"jbyteArray"
%typemap(jtype) crypto_auth_hmacsha256_state *"byte[]"
%typemap(jstype) crypto_auth_hmacsha256_state *"byte[]"
%typemap(in) crypto_auth_hmacsha256_state *{
    $1 = (crypto_auth_hmacsha256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_auth_hmacsha256_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_auth_hmacsha256_state *"$javainput"
%typemap(freearg) crypto_auth_hmacsha256_state *""

/*
    crypto_auth_hmacsha512_state
*/
%typemap(jni) crypto_auth_hmacsha512_state *"jbyteArray"
%typemap(jtype) crypto_auth_hmacsha512_state *"byte[]"
%typemap(jstype) crypto_auth_hmacsha512_state *"byte[]"
%typemap(in) crypto_auth_hmacsha512_state *{
    $1 = (crypto_auth_hmacsha512_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_auth_hmacsha512_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_auth_hmacsha512_state *"$javainput"
%typemap(freearg) crypto_auth_hmacsha512_state *""

/*
    crypto_auth_hmacsha512_state
*/
%typemap(jni) crypto_auth_hmacsha512256_state *"jbyteArray"
%typemap(jtype) crypto_auth_hmacsha512256_state *"byte[]"
%typemap(jstype) crypto_auth_hmacsha512256_state *"byte[]"
%typemap(in) crypto_auth_hmacsha512256_state *{
    $1 = (crypto_auth_hmacsha512256_state *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}
%typemap(argout) crypto_auth_hmacsha512256_state *{
    JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}
%typemap(javain) crypto_auth_hmacsha512256_state *"$javainput"
%typemap(freearg) crypto_auth_hmacsha512256_state *""



/* *****************************************************************************

    HIGH-LEVEL LIBSODIUM API'S

***************************************************************************** */


%{
 /* Put header files here or function declarations like below */
#include "sodium.h"

%}

/*
    Runtime API
*/
int sodium_init(void);

const char *sodium_version_string(void);

/* void randombytes(unsigned char * const buf, const unsigned long long buf_len); */
void randombytes(unsigned char *dst_buf,
                 unsigned long long buf_len);

/*
    randombytes API
*/
uint32_t randombytes_random(void);

uint32_t randombytes_uniform(const uint32_t upper_bound);

/*void randombytes_buf(void * const buf, const size_t size);*/
void randombytes_buf(unsigned char * const buff,
                     const unsigned long long buff_len);

int randombytes_close(void);

void randombytes_stir(void);

/*
    helpers API
*/
/*int sodium_memcmp(const void * const b1_,
                  const void * const b2_,
                  size_t len);*/

void sodium_increment(unsigned char *src_dst_number,
                      const size_t number_len);

/*
    crypto_secretbox API
*/
size_t crypto_secretbox_keybytes(void);
size_t crypto_secretbox_noncebytes(void);
size_t crypto_secretbox_macbytes(void);

size_t crypto_secretbox_zerobytes(void);
size_t crypto_secretbox_boxzerobytes(void);

const char *crypto_secretbox_primitive(void);

int crypto_secretbox_easy(unsigned char *dst_cipher,
                          const unsigned char *src_plain,
                          unsigned long long plain_len,
                          const unsigned char *nonce,
                          const unsigned char *secret_key);

int crypto_secretbox_open_easy(unsigned char *dst_plain,
                               const unsigned char *src_cipher,
                               unsigned long long cipher_len,
                               const unsigned char *nonce,
                               const unsigned char *secret_key);

/*
 crypto secretstream stuff
*/
int crypto_secretstream_xchacha20poly1305_init_push
   (crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

int crypto_secretstream_xchacha20poly1305_push
   (crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen, unsigned char tag);

int crypto_secretstream_xchacha20poly1305_init_pull
   (crypto_secretstream_xchacha20poly1305_state *state,
    const unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

int crypto_secretstream_xchacha20poly1305_pull
   (crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *m, unsigned long long *mlen_p, unsigned char *tag_p,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen);

/*
    crypto_secretbox_detached API
*/
int crypto_secretbox_detached(unsigned char *dst_cipher,
                              unsigned char *mac,
                              const unsigned char *src_plain,
                              unsigned long long plain_len,
                              const unsigned char *nonce,
                              const unsigned char *secretkey);

int crypto_secretbox_open_detached(unsigned char *dst_plain,
                                   const unsigned char *src_cipher,
                                   const unsigned char *mac,
                                   unsigned long long cipher_len,
                                   const unsigned char *nonce,
                                   const unsigned char *secretkey);

/*
    crypto_scalarmult API, for crypto_box keys
*/
size_t crypto_scalarmult_bytes(void);
size_t crypto_scalarmult_scalarbytes(void);
const char *crypto_scalarmult_primitive(void);

int crypto_scalarmult_base(unsigned char *q,
                           const unsigned char *n);

int crypto_scalarmult(unsigned char *q,
                      const unsigned char *n,
                      const unsigned char *p);

/*
    crypto_box API
*/
size_t crypto_box_seedbytes(void);
size_t crypto_box_publickeybytes(void);
size_t crypto_box_secretkeybytes(void);
size_t crypto_box_noncebytes(void);
size_t crypto_box_macbytes(void);

const char *crypto_box_primitive(void);

int crypto_box_keypair(unsigned char *dst_public_Key,
                       unsigned char *dst_private_key);

int crypto_box_seed_keypair(unsigned char *dst_public_key,
                            unsigned char *dst_private_key,
                            const unsigned char *src_seed);

int crypto_scalarmult_base(unsigned char *dst_group_element,
                           const unsigned char *src_n_multiplier);

int crypto_box_easy(unsigned char *dst_cipher,
                    const unsigned char *src_plain,
                    unsigned long long plain_len,
                    const unsigned char *nonce,
                    const unsigned char *remote_public_key,
                    const unsigned char *local_private_key);

int crypto_box_open_easy(unsigned char *dst_plain,
                         const unsigned char *src_cipher,
                         unsigned long long cipher_len,
                         const unsigned char *nonce,
                         const unsigned char *remote_public_key,
                         const unsigned char *local_private_key);

int crypto_box_detached(unsigned char *dst_cipher,
                        unsigned char *dst_mac,
                        const unsigned char *src_plain,
                        unsigned long long plain_len,
                        const unsigned char *nonces,
                        const unsigned char *remote_public_key,
                        const unsigned char *local_private_key);

int crypto_box_open_detached(unsigned char *dst_plain,
                             const unsigned char *src_cipher,
                             const unsigned char *src_mac,
                             unsigned long long cipher_len,
                             const unsigned char *nonce,
                             const unsigned char *remote_public_key,
                             const unsigned char *local_private_key);

/*
    crypto_box*nm* API
*/
size_t crypto_box_beforenmbytes(void);

int crypto_box_beforenm(unsigned char *dst_shared_key,
                        const unsigned char *remote_public_key,
                        const unsigned char *local_private_key);

int crypto_box_easy_afternm(unsigned char *dst_cipher,
                            const unsigned char *src_plain,
                            unsigned long long plain_len,
                            const unsigned char *nonce,
                            const unsigned char *shared_key);

int crypto_box_open_easy_afternm(unsigned char *dst_plain,
                                 const unsigned char *src_cipher,
                                 unsigned long long cipher_len,
                                 const unsigned char *nonce,
                                 const unsigned char *shared_key);

int crypto_box_detached_afternm(unsigned char *dst_cipher,
                                unsigned char *dst_mac,
                                const unsigned char *src_plain,
                                unsigned long long plain_len,
                                const unsigned char *nonce,
                                const unsigned char *shared_key);

int crypto_box_open_detached_afternm(unsigned char *dst_plain,
                                     const unsigned char *src_cipher,
                                     const unsigned char *src_mac,
                                     unsigned long long cipher_len,
                                     const unsigned char *nonce,
                                     const unsigned char *shared_key);

/*
    crypto_box_seal API
*/
size_t crypto_box_sealbytes(void);

int crypto_box_seal(unsigned char *dst_cipher,
                    const unsigned char *src_plain,
                    unsigned long long plain_len,
                    const unsigned char *remote_public_key);

int crypto_box_seal_open(unsigned char *dst_plain,
                         const unsigned char *src_cipher,
                         unsigned long long cipher_len,
                         const unsigned char *local_public_key,
                         const unsigned char *local_private_key);


/*
    crypto_box NaCl-compatible API
*/
size_t crypto_box_zerobytes(void);
size_t crypto_box_boxzerobytes(void);

int crypto_box(unsigned char *dst_cipher,
               const unsigned char *src_msg,
               unsigned long long msg_len,
               const unsigned char *src_nonce,
               const unsigned char *src_pub,
               const unsigned char *src_secret);


int crypto_box_open(unsigned char *dst_msg,
                    const unsigned char *src_cipher,
                    unsigned long long cipher_len,
                    const unsigned char *src_nonce,
                    const unsigned char *src_pub,
                    const unsigned char *src_secret);

int crypto_box_afternm(unsigned char *dst_cipher,
                       const unsigned char *src_msg,
                       unsigned long long msg_len,
                       const unsigned char *src_nonce,
                       const unsigned char *src_key);

int crypto_box_open_afternm(unsigned char *dst_msg,
                            const unsigned char *src_cipher,
                            unsigned long long cipher_len,
                            const unsigned char *src_nonce,
                            const unsigned char *src_key);

/*
    crypto_sign API
*/
size_t crypto_sign_bytes(void);
size_t crypto_sign_seedbytes(void);
size_t crypto_sign_publickeybytes(void);
size_t crypto_sign_secretkeybytes(void);

const char *crypto_sign_primitive(void);

int crypto_sign_keypair(unsigned char *dst_public_Key,
                        unsigned char *dst_private_key);

int crypto_sign_seed_keypair(unsigned char *dst_public_Key,
                             unsigned char *dst_private_key,
                             const unsigned char *src_seed);

int crypto_sign(unsigned char *dst_signed_msg,
                unsigned long long *signed_msg_len,
                const unsigned char *src_msg,
                unsigned long long msg_len,
                const unsigned char *local_private_key);

int crypto_sign_open(unsigned char *dst_msg,
                     unsigned long long *msg_len,
                     const unsigned char *src_signed_msg,
                     unsigned long long signed_msg_len,
                     const unsigned char *remote_public_key);

int crypto_sign_detached(unsigned char *dst_signature,
                         unsigned long long *signature_len,
                         const unsigned char *src_msg,
                         unsigned long long msg_len,
                         const unsigned char *local_private_key);

int crypto_sign_verify_detached(const unsigned char *src_signature,
                                const unsigned char *src_msg,
                                unsigned long long msg_len,
                                const unsigned char *remote_public_key);

int crypto_sign_ed25519_sk_to_seed(unsigned char *dst_seed,
                                   const unsigned char *src_private_key);

int crypto_sign_ed25519_sk_to_pk(unsigned char *dst_public_key,
                                 const unsigned char *src_private_key);

/*
    crypto_hash API
*/
size_t crypto_generichash_bytes(void);
size_t crypto_generichash_bytes_min(void);
size_t crypto_generichash_bytes_max(void);
size_t crypto_generichash_keybytes(void);
size_t crypto_generichash_keybytes_min(void);
size_t crypto_generichash_keybytes_max(void);

const char *crypto_generichash_primitive(void);

int crypto_generichash(unsigned char *dst_hash,
                       unsigned long long dst_len,
                       const unsigned char *src_input,
                       unsigned long long input_len,
                       const unsigned char *src_key,
                       unsigned long long key_len);
/* TODO NOTE EXPERIMENTAL CODE FOLLOWS */

size_t crypto_generichash_statebytes(void);

int crypto_generichash_init(crypto_generichash_state *state,
                            const unsigned char *src_key,
                            const unsigned long long key_len,
                            const unsigned long long out_len);

int crypto_generichash_update(crypto_generichash_state *state,
                              const unsigned char *src_input,
                              unsigned long long input_len);

int crypto_generichash_final(crypto_generichash_state *state,
                             unsigned char *dst_out,
                             const unsigned long long out_len);

/* TODO END OF DANGER ZONE */

/*
    crypto_shorthash API
*/
size_t crypto_shorthash_bytes(void);
size_t crypto_shorthash_keybytes(void);

const char *crypto_shorthash_primitive(void);

int crypto_shorthash(unsigned char *dst_out,
                     const unsigned char *src_input,
                     unsigned long long input_len,
                     const unsigned char *src_key);

/*
    crypto_auth API
*/
size_t crypto_auth_bytes(void);
size_t crypto_auth_keybytes(void);

const char *crypto_auth_primitive(void);

int crypto_auth(unsigned char *dst_mac,
                const unsigned char *src_input,
                unsigned long long input_len,
                const unsigned char *src_key);

int crypto_auth_verify(const unsigned char *src_mac,
                       const unsigned char *src_input,
                       unsigned long long input_len,
                       const unsigned char *src_key);

/*
    crypto_onetimeauth API
    TODO streaming interface
*/
size_t crypto_onetimeauth_bytes(void);
size_t crypto_onetimeauth_keybytes(void);

const char *crypto_onetimeauth_primitive(void);

int crypto_onetimeauth(unsigned char *dst_out,
                       const unsigned char *src_input,
                       unsigned long long input_len,
                       const unsigned char *src_key);

int crypto_onetimeauth_verify(const unsigned char *src_mac,
                              const unsigned char *src_input,
                              unsigned long long input_len,
                              const unsigned char *src_key);

size_t crypto_onetimeauth_statebytes(void);

int crypto_onetimeauth_init(crypto_onetimeauth_state *dst_state,
                            const unsigned char *src_key);

int crypto_onetimeauth_update(crypto_onetimeauth_state *dst_state,
                              const unsigned char *src_input,
                              unsigned long long input_len);

int crypto_onetimeauth_final(crypto_onetimeauth_state *final_state,
                             unsigned char *dst_out);



/* *****************************************************************************

    LOW LEVEL API'S

    Low level API;s expose the functions for the specific primitives, and
    support some functions that are only included for legacy reasons.

    Some functions are aliased by the higher-level API calls, and should produce
    the exact same result when called. For compatibility reasons, the primitive-
    specific function calls are implemented and wrapped seperately, so when a
    primitive changes in the official Sodium library, it automatically changes
    in libstodium as well.

    The Low-level implementations are exported for the sake of completeness, as
    well as the primitive-specific implementations of the Java standard
    interfaces for cryptographic operations.

i***************************************************************************** */

/*
    AEAD aes256gcm
*/
  int crypto_aead_aes256gcm_encrypt(unsigned char *c,
                                      unsigned long long *clen_p,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *ad,
                                      unsigned long long adlen,
                                      const unsigned char *nsec,
                                      const unsigned char *npub,
                                      const unsigned char *k);

    int crypto_aead_aes256gcm_decrypt(unsigned char *m,
                                      unsigned long long *mlen_p,
                                      unsigned char *nsec,
                                      const unsigned char *c,
                                      unsigned long long clen,
                                      const unsigned char *ad,
                                      unsigned long long adlen,
                                      const unsigned char *npub,
                                      const unsigned char *k);

    int crypto_aead_aes256gcm_encrypt_detached(unsigned char *c,
                                               unsigned char *mac,
                                               unsigned long long *maclen_p,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *nsec,
                                               const unsigned char *npub,
                                               const unsigned char *k);

    int crypto_aead_aes256gcm_decrypt_detached(unsigned char *m,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *mac,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k);

/*
    AEAD chacha20poly1305
*/
int crypto_aead_chacha20poly1305_encrypt(unsigned char *c,
                                         unsigned long long *clen_p,
                                         const unsigned char *m,
                                         unsigned long long mlen,
                                         const unsigned char *ad,
                                         unsigned long long adlen,
                                         const unsigned char *nsec,
                                         const unsigned char *npub,
                                         const unsigned char *k);


int crypto_aead_chacha20poly1305_decrypt(unsigned char *m,
                                         unsigned long long *mlen_p,
                                         unsigned char *nsec,
                                         const unsigned char *c,
                                         unsigned long long clen,
                                         const unsigned char *ad,
                                         unsigned long long adlen,
                                         const unsigned char *npub,
                                         const unsigned char *k);


int crypto_aead_chacha20poly1305_encrypt_detached(unsigned char *c,
                                                  unsigned char *mac,
                                                  unsigned long long *maclen_p,
                                                  const unsigned char *m,
                                                  unsigned long long mlen,
                                                  const unsigned char *ad,
                                                  unsigned long long adlen,
                                                  const unsigned char *nsec,
                                                  const unsigned char *npub,
                                                  const unsigned char *k);


int crypto_aead_chacha20poly1305_decrypt_detached(unsigned char *m,
                                                  unsigned char *nsec,
                                                  const unsigned char *c,
                                                  unsigned long long clen,
                                                  const unsigned char *mac,
                                                  const unsigned char *ad,
                                                  unsigned long long adlen,
                                                  const unsigned char *npub,
                                                  const unsigned char *k);

/*
    AEAD chacha20poly1305 IETF
*/

int crypto_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
                                              unsigned long long *clen_p,
                                              const unsigned char *m,
                                              unsigned long long mlen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *nsec,
                                              const unsigned char *npub,
                                              const unsigned char *k);

int crypto_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
                                              unsigned long long *mlen_p,
                                              unsigned char *nsec,
                                              const unsigned char *c,
                                              unsigned long long clen,
                                              const unsigned char *ad,
                                              unsigned long long adlen,
                                              const unsigned char *npub,
                                              const unsigned char *k);

int crypto_aead_chacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                       unsigned char *mac,
                                                       unsigned long long *maclen_p,
                                                       const unsigned char *m,
                                                       unsigned long long mlen,
                                                       const unsigned char *ad,
                                                       unsigned long long adlen,
                                                       const unsigned char *nsec,
                                                       const unsigned char *npub,
                                                       const unsigned char *k);

int crypto_aead_chacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                       unsigned char *nsec,
                                                       const unsigned char *c,
                                                       unsigned long long clen,
                                                       const unsigned char *mac,
                                                       const unsigned char *ad,
                                                       unsigned long long adlen,
                                                       const unsigned char *npub,
                                                       const unsigned char *k);

/*
    AEAD xchacha20poly1305_ietf
*/
int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char *c,
                                               unsigned long long *clen_p,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *nsec,
                                               const unsigned char *npub,
                                               const unsigned char *k);

int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char *m,
                                               unsigned long long *mlen_p,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k);

int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                        unsigned char *mac,
                                                        unsigned long long *maclen_p,
                                                        const unsigned char *m,
                                                        unsigned long long mlen,
                                                        const unsigned char *ad,
                                                        unsigned long long adlen,
                                                        const unsigned char *nsec,
                                                        const unsigned char *npub,
                                                        const unsigned char *k);


int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                        unsigned char *nsec,
                                                        const unsigned char *c,
                                                        unsigned long long clen,
                                                        const unsigned char *mac,
                                                        const unsigned char *ad,
                                                        unsigned long long adlen,
                                                        const unsigned char *npub,
                                                        const unsigned char *k);



/*
    Auth HMAC-SHA-256
*/

size_t crypto_auth_hmacsha256_bytes(void);
size_t crypto_auth_hmacsha256_keybytes(void);

int crypto_auth_hmacsha256(unsigned char *out,
                           const unsigned char *in,
                           unsigned long long inlen,
                           const unsigned char *k);

int crypto_auth_hmacsha256_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  unsigned long long inlen,
                                  const unsigned char *k);

size_t crypto_auth_hmacsha256_statebytes(void);

int crypto_auth_hmacsha256_init(crypto_auth_hmacsha256_state *state,
                                const unsigned char *key,
                                size_t keylen);

int crypto_auth_hmacsha256_update(crypto_auth_hmacsha256_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen);

int crypto_auth_hmacsha256_final(crypto_auth_hmacsha256_state *state,
                                 unsigned char *out);

/*
    Auth HMAC-SHA-512
*/

size_t crypto_auth_hmacsha512_bytes(void);
size_t crypto_auth_hmacsha512_keybytes(void);

int crypto_auth_hmacsha512(unsigned char *out,
                           const unsigned char *in,
                           unsigned long long inlen,
                           const unsigned char *k);

int crypto_auth_hmacsha512_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  unsigned long long inlen,
                                  const unsigned char *k);

size_t crypto_auth_hmacsha512_statebytes(void);

int crypto_auth_hmacsha512_init(crypto_auth_hmacsha512_state *state,
                                const unsigned char *key,
                                size_t keylen);

int crypto_auth_hmacsha512_update(crypto_auth_hmacsha512_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen);

int crypto_auth_hmacsha512_final(crypto_auth_hmacsha512_state *state,
                                 unsigned char *out);

/*
    Auth HMAC-SHA-512/256
*/

size_t crypto_auth_hmacsha512256_bytes(void);
size_t crypto_auth_hmacsha512256_keybytes(void);

int crypto_auth_hmacsha512256(unsigned char *out,
                              const unsigned char *in,
                              unsigned long long inlen,
                              const unsigned char *k);

int crypto_auth_hmacsha512256_verify(const unsigned char *h,
                                     const unsigned char *in,
                                     unsigned long long inlen,
                                     const unsigned char *k);

size_t crypto_auth_hmacsha512256_statebytes(void);

int crypto_auth_hmacsha512256_init(crypto_auth_hmacsha512256_state *state,
                                   const unsigned char *key,
                                   size_t keylen);

int crypto_auth_hmacsha512256_update(crypto_auth_hmacsha512256_state *state,
                                     const unsigned char *in,
                                     unsigned long long inlen);

int crypto_auth_hmacsha512256_final(crypto_auth_hmacsha512256_state *state,
                                    unsigned char *out);

/*
    Box Curve25519XSalsa20Poly1305
*/

size_t crypto_box_curve25519xsalsa20poly1305_seedbytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_publickeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_secretkeybytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_beforenmbytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_noncebytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_zerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_boxzerobytes(void);
size_t crypto_box_curve25519xsalsa20poly1305_macbytes(void);

int crypto_box_curve25519xsalsa20poly1305(unsigned char *c,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *n,
                                          const unsigned char *pk,
                                          const unsigned char *sk);


int crypto_box_curve25519xsalsa20poly1305_open(unsigned char *m,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk,
                                                       unsigned char *sk,
                                                       const unsigned char *seed);

int crypto_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                  unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                                   const unsigned char *pk,
                                                   const unsigned char *sk);

int crypto_box_curve25519xsalsa20poly1305_afternm(unsigned char *c,
                                                  const unsigned char *m,
                                                  unsigned long long mlen,
                                                  const unsigned char *n,
                                                  const unsigned char *k);

int crypto_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *m,
                                                       const unsigned char *c,
                                                       unsigned long long clen,
                                                       const unsigned char *n,
                                                       const unsigned char *k);

/*
    Core HSalsa20
*/

size_t crypto_core_hsalsa20_outputbytes(void);
size_t crypto_core_hsalsa20_inputbytes(void);
size_t crypto_core_hsalsa20_keybytes(void);
size_t crypto_core_hsalsa20_constbytes(void);

int crypto_core_hsalsa20(unsigned char *out,
                         const unsigned char *in,
                         const unsigned char *k,
                         const unsigned char *c);

/*
    Core Salsa20
*/

size_t crypto_core_salsa20_outputbytes(void);
size_t crypto_core_salsa20_inputbytes(void);
size_t crypto_core_salsa20_keybytes(void);
size_t crypto_core_salsa20_constbytes(void);

int crypto_core_salsa20(unsigned char *out,
                        const unsigned char *in,
                        const unsigned char *k,
                        const unsigned char *c);

/*
    Core Salsa2012 TODO
*/ /*
size_t crypto_core_salsa2012_outputbytes(void);
size_t crypto_core_salsa2012_inputbytes(void);
size_t crypto_core_salsa2012_keybytes(void);
size_t crypto_core_salsa2012_constbytes(void);

int crypto_core_salsa2012(unsigned char *out,
                          const unsigned char *in,
                          const unsigned char *k,
                          const unsigned char *c);
*/
/*
    Core Salsa208 TODO
*/ /*

size_t crypto_core_salsa208_outputbytes(void);
size_t crypto_core_salsa208_inputbytes(void);
size_t crypto_core_salsa208_keybytes(void);
size_t crypto_core_salsa208_constbytes(void);

int crypto_core_salsa208(unsigned char *out,
                         const unsigned char *in,
                         const unsigned char *k,
                         const unsigned char *c);
*/
/*
    Generic Hash BLAKE2b
*/

size_t crypto_generichash_blake2b_bytes_min(void);
size_t crypto_generichash_blake2b_bytes_max(void);
size_t crypto_generichash_blake2b_bytes(void);
size_t crypto_generichash_blake2b_keybytes_min(void);
size_t crypto_generichash_blake2b_keybytes_max(void);
size_t crypto_generichash_blake2b_keybytes(void);
size_t crypto_generichash_blake2b_saltbytes(void);
size_t crypto_generichash_blake2b_personalbytes(void);

int crypto_generichash_blake2b(unsigned char *out,
                               size_t outlen,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *key,
                               size_t keylen);

int crypto_generichash_blake2b_salt_personal(unsigned char *out,
                                             size_t outlen,
                                             const unsigned char *in,
                                             unsigned long long inlen,
                                             const unsigned char *key,
                                             size_t keylen,
                                             const unsigned char *salt,
                                             const unsigned char *personal);

int crypto_generichash_blake2b_init(crypto_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen,
                                    const size_t outlen);

int crypto_generichash_blake2b_init_salt_personal(crypto_generichash_blake2b_state *state,
                                                  const unsigned char *key,
                                                  const size_t keylen,
                                                  const size_t outlen,
                                                  const unsigned char *salt,
                                                  const unsigned char *personal);

int crypto_generichash_blake2b_update(crypto_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen);

int crypto_generichash_blake2b_final(crypto_generichash_blake2b_state *state,
                                     unsigned char *out,
                                     const size_t outlen);

/*
    Hash SHA-256
*/

size_t crypto_hash_sha256_bytes(void);

int crypto_hash_sha256(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen);

size_t crypto_hash_sha256_statebytes(void);

int crypto_hash_sha256_init(crypto_hash_sha256_state *state);

int crypto_hash_sha256_update(crypto_hash_sha256_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

int crypto_hash_sha256_final(crypto_hash_sha256_state *state,
                             unsigned char *out);

/*
    Hash SHA-512
*/

size_t crypto_hash_sha512_bytes(void);

int crypto_hash_sha512(unsigned char *out,
                       const unsigned char *in,
                       unsigned long long inlen);

size_t crypto_hash_sha512_statebytes(void);

int crypto_hash_sha512_init(crypto_hash_sha512_state *state);

int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out);

/*
    Onetime-Auth Poly1305
*/

size_t crypto_onetimeauth_poly1305_bytes(void);
size_t crypto_onetimeauth_poly1305_keybytes(void);

int crypto_onetimeauth_poly1305(unsigned char *out,
                                const unsigned char *in,
                                unsigned long long inlen,
                                const unsigned char *k);

int crypto_onetimeauth_poly1305_verify(const unsigned char *h,
                                       const unsigned char *in,
                                       unsigned long long inlen,
                                       const unsigned char *k);

/* this method does not exist because it is a constant value, included for ease
   of implementation */
/*
%inline %{
size_t crypto_onetimeauth_poly1305_statebytes(void) {
    return 256U;
}
%}
*/

int crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
                                     const unsigned char *key);

int crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *in,
                                       unsigned long long inlen);

int crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state *state,
                                      unsigned char *out);

/*
    PW-Hash argon2
*/
int crypto_pwhash_alg_argon2i13(void);
int crypto_pwhash_alg_default(void);
size_t crypto_pwhash_bytes_min(void);
size_t crypto_pwhash_bytes_max(void);
size_t crypto_pwhash_passwd_min(void);
size_t crypto_pwhash_passwd_max(void);
size_t crypto_pwhash_saltbytes(void);
size_t crypto_pwhash_strbytes(void);
const char * crypto_pwhash_strprefix(void);
size_t crypto_pwhash_opslimit_min(void);
size_t crypto_pwhash_opslimit_max(void);
size_t crypto_pwhash_memlimit_min(void);
size_t crypto_pwhash_memlimit_max(void);
size_t crypto_pwhash_opslimit_interactive(void);
size_t crypto_pwhash_memlimit_interactive(void);
size_t crypto_pwhash_opslimit_moderate(void);
size_t crypto_pwhash_memlimit_moderate(void);
size_t crypto_pwhash_opslimit_sensitive(void);
size_t crypto_pwhash_memlimit_sensitive(void);
int crypto_pwhash(unsigned char * const out,
                  unsigned long long outlen,
                  const char * const passwd,
                  unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit,
                  size_t memlimit,
                  int alg);

int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES],
                      const char * const passwd,
                      unsigned long long passwdlen,
                      unsigned long long opslimit,
                      size_t memlimit);

int crypto_pwhash_str_verify(const char str[crypto_pwhash_STRBYTES],
                             const char * const passwd,
                             unsigned long long passwdlen);

const char * crypto_pwhash_primitive(void);


/*
    PW-Hash scryptsalsa208sha256
*/

size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);

size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);
const char *crypto_pwhash_scryptsalsa208sha256_strprefix(void);

size_t crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);
size_t crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);


int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       unsigned long long outlen,
                                       const char * const passwd,
                                       unsigned long long passwdlen,
                                       const unsigned char * const salt,
                                       unsigned long long opslimit,
                                       size_t memlimit);


int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           unsigned long long passwdlen,
                                           unsigned long long opslimit,
                                           size_t memlimit);


int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                                  const char * const passwd,
                                                  unsigned long long passwdlen);


int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd, size_t passwdlen,
                                          const uint8_t * salt, size_t saltlen,
                                          uint64_t N, uint32_t r, uint32_t p,
                                          uint8_t * buf, size_t buflen);


int crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                                        unsigned long long opslimit,
                                                        size_t memlimit);


/*
    ScalarMult Curve25519
*/
size_t crypto_scalarmult_curve25519_bytes(void);
size_t crypto_scalarmult_curve25519_scalarbytes(void);

int crypto_scalarmult_curve25519(unsigned char *q,
                                 const unsigned char *n,
                                 const unsigned char *p);
int crypto_scalarmult_curve25519_base(unsigned char *q,
                                      const unsigned char *n);

/*
    SecretBox XSalsa20Poly1305
*/
size_t crypto_secretbox_xsalsa20poly1305_keybytes(void);
size_t crypto_secretbox_xsalsa20poly1305_noncebytes(void);
size_t crypto_secretbox_xsalsa20poly1305_zerobytes(void);
size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes(void);
size_t crypto_secretbox_xsalsa20poly1305_macbytes(void);

int crypto_secretbox_xsalsa20poly1305(unsigned char *c,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n,
                                      const unsigned char *k);

int crypto_secretbox_xsalsa20poly1305_open(unsigned char *m,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *n,
                                           const unsigned char *k);

/*
    Secretbox XChacha20Poly1305
*/
int crypto_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                            const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *n,
                                            const unsigned char *k);

int crypto_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                                 const unsigned char *c,
                                                 unsigned long long clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k);

int crypto_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                                unsigned char *mac,
                                                const unsigned char *m,
                                                unsigned long long mlen,
                                                const unsigned char *n,
                                                const unsigned char *k);

int crypto_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                     const unsigned char *c,
                                                     const unsigned char *mac,
                                                     unsigned long long clen,
                                                     const unsigned char *n,
                                                     const unsigned char *k);

/*
    Shorthash SipHash-2-4
*/
size_t crypto_shorthash_siphash24_bytes(void);
size_t crypto_shorthash_siphash24_keybytes(void);

int crypto_shorthash_siphash24(unsigned char *out,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *k);

/*
    Sign Ed25519
    Ed25519SHa512Batch is not implemented
*/
size_t crypto_sign_ed25519_bytes(void);
size_t crypto_sign_ed25519_seedbytes(void);
size_t crypto_sign_ed25519_publickeybytes(void);
size_t crypto_sign_ed25519_secretkeybytes(void);

int crypto_sign_ed25519(unsigned char *sm,
                        unsigned long long *smlen_p,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *sk);

int crypto_sign_ed25519_open(unsigned char *m,
                             unsigned long long *mlen_p,
                             const unsigned char *sm,
                             unsigned long long smlen,
                             const unsigned char *pk);


int crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen,
              const unsigned char *n, const unsigned char *k);

int crypto_sign_ed25519_detached(unsigned char *sig,
                                 unsigned long long *siglen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *sk);

int crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk);

int crypto_sign_ed25519_keypair(unsigned char *pk,
                                unsigned char *sk);

int crypto_sign_ed25519_seed_keypair(unsigned char *pk,
                                     unsigned char *sk,
                                     const unsigned char *seed);

int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk);

int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk);

int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);

int crypto_sign_ed25519_sk_to_pk(unsigned char *pk,
                                 const unsigned char *sk);

/*
    Stream aes128ctr TODO
*/ /*
size_t crypto_stream_aes128ctr_keybytes(void);
size_t crypto_stream_aes128ctr_noncebytes(void);
size_t crypto_stream_aes128ctr_beforenmbytes(void);

int crypto_stream_aes128ctr(unsigned char *out,
                            unsigned long long outlen,
                            const unsigned char *n,
                            const unsigned char *k);

int crypto_stream_aes128ctr_xor(unsigned char *out,
                                const unsigned char *in,
                                unsigned long long inlen,
                                const unsigned char *n,
                                const unsigned char *k);

int crypto_stream_aes128ctr_beforenm(unsigned char *c,
                                     const unsigned char *k);

int crypto_stream_aes128ctr_afternm(unsigned char *out,
                                    unsigned long long len,
                                    const unsigned char *nonce,
                                    const unsigned char *c);

int crypto_stream_aes128ctr_xor_afternm(unsigned char *out,
                                        const unsigned char *in,
                                        unsigned long long len,
                                        const unsigned char *nonce,
                                        const unsigned char *c);
*/
/*
    Stream Chacha20
*/
size_t crypto_stream_chacha20_keybytes(void);
size_t crypto_stream_chacha20_noncebytes(void);

int crypto_stream_chacha20(unsigned char *c,
                           unsigned long long clen,
                           const unsigned char *n,
                           const unsigned char *k);

int crypto_stream_chacha20_xor(unsigned char *c,
                               const unsigned char *m,
                               unsigned long long mlen,
                               const unsigned char *n,
                               const unsigned char *k);

int crypto_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n,
                                  uint64_t ic,
                                  const unsigned char *k);

size_t crypto_stream_chacha20_ietf_noncebytes(void);

int crypto_stream_chacha20_ietf(unsigned char *c,
                                unsigned long long clen,
                                const unsigned char *n,
                                const unsigned char *k);

int crypto_stream_chacha20_ietf_xor(unsigned char *c,
                                    const unsigned char *m,
                                    unsigned long long mlen,
                                    const unsigned char *n,
                                    const unsigned char *k);

int crypto_stream_chacha20_ietf_xor_ic(unsigned char *c,
                                       const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n,
                                       uint32_t ic,
                                       const unsigned char *k);

/*
    Stream Salsa20
*/
size_t crypto_stream_salsa20_keybytes(void);
size_t crypto_stream_salsa20_noncebytes(void);

int crypto_stream_salsa20(unsigned char *c,
                          unsigned long long clen,
                          const unsigned char *n,
                          const unsigned char *k);

int crypto_stream_salsa20_xor(unsigned char *c,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k);

int crypto_stream_salsa20_xor_ic(unsigned char *c,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *n,
                                 uint64_t ic,
                                 const unsigned char *k);

/*
    Stream Salsa2012 TODO
*/ /*
size_t crypto_stream_salsa2012_keybytes(void);
size_t crypto_stream_salsa2012_noncebytes(void);

int crypto_stream_salsa2012(unsigned char *c,
                            unsigned long long clen,
                            const unsigned char *n,
                            const unsigned char *k);

int crypto_stream_salsa2012_xor(unsigned char *c,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *n,
                                const unsigned char *k);
*/
/*
    Stream Salsa208 TODO
*/ /*
size_t crypto_stream_salsa208_keybytes(void);
size_t crypto_stream_salsa208_noncebytes(void);

int crypto_stream_salsa208(unsigned char *c,
                           unsigned long long clen,
                           const unsigned char *n,
                           const unsigned char *k);

int crypto_stream_salsa208_xor(unsigned char *c,
                               const unsigned char *m,
                               unsigned long long mlen,
                               const unsigned char *n,
                               const unsigned char *k);
*/
/*
    Stream XSalsa20
*/
size_t crypto_stream_xsalsa20_keybytes(void);
size_t crypto_stream_xsalsa20_noncebytes(void);

int crypto_stream_xsalsa20(unsigned char *c,
                           unsigned long long clen,
                           const unsigned char *n,
                           const unsigned char *k);

int crypto_stream_xsalsa20_xor(unsigned char *c,
                               const unsigned char *m,
                               unsigned long long mlen,
                               const unsigned char *n,
                               const unsigned char *k);

int crypto_stream_xsalsa20_xor_ic(unsigned char *c,
                                  const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n,
                                  uint64_t ic,
                                  const unsigned char *k);