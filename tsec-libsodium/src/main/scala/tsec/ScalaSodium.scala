package tsec

import cats.effect.Sync
import jnr.ffi.LibraryLoader
import jnr.ffi.Platform
import jnr.ffi.annotations.In
import jnr.ffi.annotations.Out
import jnr.ffi.byref.LongLongByReference
import jnr.ffi.types.u_int64_t
import jnr.ffi.types.size_t

/** Libsodium bindings using jni-ffi.
  * Inspired from kalium's stuff.
  *
  */
trait ScalaSodium {

  /**
    * This function isn't thread safe. Be sure to call it once, and before
    * performing other operations.
    *
    * Check libsodium's documentation for more info.
    */
  def sodium_init: Int

  def sodium_version_string: String

  //--------------------------------------------------------------------
  // Argon2 password hashing

  //Argon 2id constants
  val crypto_pwhash_argon2id_ALG_ARGON2ID13       = 2
  val crypto_pwhash_argon2id_BYTES_MIN            = 16L
  val crypto_pwhash_argon2id_BYTES_MAX            = 4294967295L
  val crypto_pwhash_argon2id_PASSWD_MIN           = 0L
  val crypto_pwhash_argon2id_PASSWD_MAX           = 4294967295L
  val crypto_pwhash_argon2id_SALTBYTES            = 16L
  val crypto_pwhash_argon2id_STRBYTES             = 128L
  val crypto_pwhash_argon2id_OPSLIMIT_MIN         = 1L
  val crypto_pwhash_argon2id_OPSLIMIT_MAX         = 4294967295L
  val crypto_pwhash_argon2id_MEMLIMIT_MIN         = 8192L
  val crypto_pwhash_argon2id_MEMLIMIT_MAX         = 4398046510080L
  val crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE = 2L
  val crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE = 67108864L
  val crypto_pwhash_argon2id_OPSLIMIT_MODERATE    = 3L
  val crypto_pwhash_argon2id_MEMLIMIT_MODERATE    = 268435456L
  val crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE   = 4L
  val crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE   = 1073741824L

  def crypto_pwhash_ALG_DEFAULT        = crypto_pwhash_argon2id_ALG_ARGON2ID13
  def crypto_pwhash_SALTBYTES          = crypto_pwhash_argon2id_SALTBYTES
  def crypto_pwhash_STRBYTES           = crypto_pwhash_argon2id_STRBYTES
  def crypto_pwhash_OPSLIMIT_SENSITIVE = crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
  def crypto_pwhash_MEMLIMIT_SENSITIVE = crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE

  def crypto_pwhash(
      @Out out: Array[Byte],
      @In @u_int64_t outLen: Int,
      @In passwd: Array[Byte],
      @In @u_int64_t passwdLen: Int,
      @In salt: Array[Byte],
      @In @u_int64_t opsLimit: Long,
      @In @size_t memLimit: Long,
      @In @u_int64_t alg: Int
  ): Int

  def crypto_pwhash_str(
      @Out out: Array[Byte],
      @In passwd: Array[Byte],
      @In @u_int64_t passwdLen: Long,
      @In @u_int64_t opsLimit: Long,
      @In @size_t memLimit: Long
  ): Int

  def crypto_pwhash_str_verify(@In str: Array[Byte], @In passwd: Array[Byte], @In @u_int64_t passwdLen: Int): Int

  // ---------------------------------------------------------------------
  // Generating Random Data

  def randombytes(@Out buffer: Array[Byte], @In @u_int64_t size: Int): Unit

  // Secret-key cryptography: Authenticated encryption

  /**
    * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES
    */
  @deprecated val XSALSA20_POLY1305_SECRETBOX_KEYBYTES = 32

  /**
    * @deprecated use CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES
    */
  @deprecated val XSALSA20_POLY1305_SECRETBOX_NONCEBYTES = 24

  val CRYPTO_SECRETBOX_XSALSA20POLY1305_KEYBYTES = 32

  val CRYPTO_SECRETBOX_XSALSA20POLY1305_NONCEBYTES = 24

  def crypto_secretbox_xsalsa20poly1305(
      @Out ct: Array[Byte],
      @In msg: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_secretbox_xsalsa20poly1305_open(
      @Out message: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int

  // Secret-key cryptography: Authentication

  /**
    * @deprecated use CRYPTO_AUTH_HMACSHA512256_BYTESS
    */
  @deprecated val HMACSHA512256_BYTES = 32

  /**
    * @deprecated use CRYPTO_AUTH_HMACSHA512256_KEYBYTESS
    */
  @deprecated val HMACSHA512256_KEYBYTES = 32

  val CRYPTO_AUTH_HMACSHA512256_BYTES = 32

  val CRYPTO_AUTH_HMACSHA512256_KEYBYTES = 32

  def crypto_auth_hmacsha512256(
      @Out mac: Array[Byte],
      @In message: Array[Byte],
      @In @u_int64_t sizeof: Int,
      @In key: Array[Byte]
  ): Int

  def crypto_auth_hmacsha512256_verify(
      @In mac: Array[Byte],
      @In message: Array[Byte],
      @In @u_int64_t sizeof: Int,
      @In key: Array[Byte]
  ): Int

  // Secret-key cryptography: AEAD

  val CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = 32

  val CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = 8

  val CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = 16

  def crypto_aead_chacha20poly1305_keygen(@Out keyBytes: Array[Byte]): Int

  def crypto_aead_chacha20poly1305_encrypt(
      @Out ct: Array[Byte],
      @Out ctLength: LongLongByReference,
      @In message: Array[Byte],
      @In @u_int64_t messageLength: Int,
      @In additionalData: Array[Byte],
      @In @u_int64_t adLength: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_chacha20poly1305_decrypt(
      @Out message: Array[Byte],
      @Out messageLength: LongLongByReference,
      @In nsec: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t ctLength: Int,
      @In additionalData: Array[Byte],
      @In @u_int64_t adLength: Int,
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  // Public-key cryptography: Authenticated encryption

  /**
    * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES
    */
  @deprecated val PUBLICKEY_BYTES = 32

  /**
    * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTESS
    */
  @deprecated val SECRETKEY_BYTES = 32

  /**
    * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES
    */
  @deprecated val NONCE_BYTES = 24

  /**
    * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTESS
    */
  @deprecated val ZERO_BYTES = 32

  /**
    * @deprecated use CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES
    */
  @deprecated val BOXZERO_BYTES = 16

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES = 32

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_SECRETKEYBYTES = 32

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES = 32

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES = 16

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES
    : Int = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_ZEROBYTES - CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BOXZEROBYTES

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_NONCEBYTES = 24

  val CRYPTO_BOX_CURVE25519XSALSA20POLY1305_BEFORENMBYTES = 32

  def crypto_box_curve25519xsalsa20poly1305_keypair(@Out publicKey: Array[Byte], @Out secretKey: Array[Byte]): Int

  def crypto_box_curve25519xsalsa20poly1305_beforenm(
      @Out sharedkey: Array[Byte],
      @In publicKey: Array[Byte],
      @In privateKey: Array[Byte]
  ): Int

  def crypto_box_curve25519xsalsa20poly1305(
      @Out ct: Array[Byte],
      @In msg: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In publicKey: Array[Byte],
      @In privateKey: Array[Byte]
  ): Int

  def crypto_box_curve25519xsalsa20poly1305_afternm(
      @Out ct: Array[Byte],
      @In msg: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In shared: Array[Byte]
  ): Int

  def crypto_box_curve25519xsalsa20poly1305_open(
      @Out message: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In publicKey: Array[Byte],
      @In privateKey: Array[Byte]
  ): Int

  def crypto_box_curve25519xsalsa20poly1305_open_afternm(
      @Out message: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t length: Int,
      @In nonce: Array[Byte],
      @In shared: Array[Byte]
  ): Int

  // Public-key cryptography: Public-key signatures

  /**
    * @deprecated use the documented CRYPTO_SIGN_ED25519_BYTES.
    */
  @deprecated val SIGNATURE_BYTES = 64

  val CRYPTO_SIGN_ED25519_PUBLICKEYBYTES = 32

  val CRYPTO_SIGN_ED25519_SECRETKEYBYTES = 64

  val CRYPTO_SIGN_ED25519_BYTES = 64

  def crypto_sign_ed25519_seed_keypair(
      @Out publicKey: Array[Byte],
      @Out secretKey: Array[Byte],
      @In seed: Array[Byte]
  ): Int

  def crypto_sign_ed25519(
      @Out buffer: Array[Byte],
      @Out bufferLen: LongLongByReference,
      @In message: Array[Byte],
      @In @u_int64_t length: Int,
      @In secretKey: Array[Byte]
  ): Int

  def crypto_sign_ed25519_open(
      @Out buffer: Array[Byte],
      @Out bufferLen: LongLongByReference,
      @In sigAndMsg: Array[Byte],
      @In @u_int64_t length: Int,
      @In key: Array[Byte]
  ): Int

  // Public-key cryptography: Sealed boxes

  val CRYPTO_BOX_SEALBYTES
    : Int = CRYPTO_BOX_CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES + CRYPTO_BOX_CURVE25519XSALSA20POLY1305_MACBYTES

  def crypto_box_seal(
      @Out ct: Array[Byte],
      @In message: Array[Byte],
      @In @u_int64_t length: Int,
      @In publicKey: Array[Byte]
  ): Int

  def crypto_box_seal_open(
      @Out message: Array[Byte],
      @In c: Array[Byte],
      @In @u_int64_t length: Int,
      @In publicKey: Array[Byte],
      @In privateKey: Array[Byte]
  ): Int

  // Hashing: Generic hashing

  /**
    * @deprecated use CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX. Note that
    *             the Libsodium standard value is '32' and not '64' as defined here.
    */
  @deprecated val BLAKE2B_OUTBYTES = 64

  val CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32

  val CRYPTO_GENERICHASH_BLAKE2B_BYTES_MIN = 16

  val CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64

  val CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES = 32

  val CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MIN = 16

  val CRYPTO_GENERICHASH_BLAKE2B_KEYBYTES_MAX = 64

  def crypto_generichash_blake2b(
      @Out buffer: Array[Byte],
      @In @u_int64_t outLen: Int,
      @In message: Array[Byte],
      @u_int64_t messageLen: Int,
      @In key: Array[Byte],
      @In @u_int64_t keyLen: Int
  ): Int

  def crypto_generichash_blake2b_salt_personal(
      @Out buffer: Array[Byte],
      @In @u_int64_t outLen: Int,
      @In message: Array[Byte],
      @u_int64_t messageLen: Int,
      @In key: Array[Byte],
      @In @u_int64_t keyLen: Int,
      @In salt: Array[Byte],
      @In personal: Array[Byte]
  ): Int

  // Hashing: Short-input hashing

  // TODO

  // Password hashing

  /**
    * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES
    */
  @deprecated val PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102

  /**
    * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES
    */
  @deprecated val PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64

  /**
    * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE
    */
  @deprecated val PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288

  /**
    * @deprecated use CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
    */
  @deprecated val PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216

  val CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRBYTES = 102

  val CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OUTBYTES = 64

  val CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288

  val CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216

  def crypto_pwhash_scryptsalsa208sha256(
      @Out buffer: Array[Byte],
      @In @u_int64_t outlen: Int,
      @In passwd: Array[Byte],
      @In @u_int64_t passwdlen: Int,
      @In salt: Array[Byte],
      @In @u_int64_t opslimit: Long,
      @In @u_int64_t memlimit: Long
  ): Int

  def crypto_pwhash_scryptsalsa208sha256_str(
      @Out buffer: Array[Byte],
      @In passwd: Array[Byte],
      @In @u_int64_t passwdlen: Int,
      @In @u_int64_t opslimit: Long,
      @In @u_int64_t memlimit: Long
  ): Int

  def crypto_pwhash_scryptsalsa208sha256_str_verify(
      @In buffer: Array[Byte],
      @In passwd: Array[Byte],
      @In @u_int64_t passwdlen: Int
  ): Int

  // Advanced: AES256-GCM

  val CRYPTO_AEAD_AES256GCM_KEYBYTES = 32

  val CRYPTO_AEAD_AES256GCM_NPUBBYTES = 12

  val CRYPTO_AEAD_AES256GCM_ABYTES = 16

  /**
    * @return 1 if the current CPU supports the AES256-GCM implementation,
    *         and 0 if it doesn't.
    */
  def crypto_aead_aes256gcm_is_available: Int

  def crypto_aead_aes256gcm_encrypt(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_decrypt(
      @Out msg: Array[Byte],
      @Out msgLen: LongLongByReference,
      @In nsec: Array[Byte],
      @In ct: Array[Byte],
      @In @u_int64_t ctLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In npub: Array[Byte],
      @In key: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_statebytes: Int

  def crypto_aead_aes256gcm_beforenm(@Out state: Array[Byte], @In key: Array[Byte]): Int

  def crypto_aead_aes256gcm_encrypt_afternm(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In @Out state: Array[Byte]
  ): Int

  def crypto_aead_aes256gcm_decrypt_afternm(
      @Out ct: Array[Byte],
      @Out ctLen: LongLongByReference,
      @In msg: Array[Byte],
      @In @u_int64_t msgLen: Int,
      @In ad: Array[Byte],
      @In @u_int64_t adLen: Int,
      @In nsec: Array[Byte],
      @In npub: Array[Byte],
      @In @Out state: Array[Byte]
  ): Int

  // Advanced: SHA-2

  /**
    * @deprecated use CRYPTO_HASH_SHA256_BYTES
    */
  val SHA256BYTES = 32

  /**
    * @deprecated use CRYPTO_HASH_SHA512_BYTES
    */
  val SHA512BYTES = 64

  val CRYPTO_HASH_SHA256_BYTES = 32

  def crypto_hash_sha256(@Out buffer: Array[Byte], @In message: Array[Byte], @In @u_int64_t sizeof: Int): Int

  val CRYPTO_HASH_SHA512_BYTES = 64

  def crypto_hash_sha512(@Out buffer: Array[Byte], @In message: Array[Byte], @In @u_int64_t sizeof: Int): Int

  // Advanced: HMAC-SHA-2

  // Advanced: One-time authentication

  // Advanced: Diffie-Hellman

  val CRYPTO_SCALARMULT_CURVE25519_SCALARBYTES = 32

  val CRYPTO_SCALARMULT_CURVE25519_BYTES = 32

  def crypto_scalarmult_curve25519(@Out result: Array[Byte], @In intValue: Array[Byte], @In point: Array[Byte]): Int

  // Advanced: Stream ciphers: ChaCha20

  // Advanced: Stream ciphers: Salsa20

  val CRYPTO_STREAM_KEYBYTES = 32

  val CRYPTO_STREAM_NONCEBYTES = 24

  def crypto_stream_xor(
      @Out result: Array[Byte],
      @In message: Array[Byte],
      @In @u_int64_t mlen: Int,
      @In nonce: Array[Byte],
      @In key: Array[Byte]
  ): Int
  // Advanced: Stream ciphers: XSalsa20
  // Advanced: Ed25519 to Curve25519

  //Argon2 stuff

}

object ScalaSodium {

  val MIN_SUPPORTED_VERSION: Array[Integer] = Array[Integer](1, 0, 3)

  private var versionSupported = false

  private def checkVersion(lib: NaCl.Sodium): Unit = {
    if (!versionSupported) {
      val version: Array[String] = lib.sodium_version_string.split("\\.")
      versionSupported = version.length >= 3 && MIN_SUPPORTED_VERSION(0) <= new Integer(version(0)) && MIN_SUPPORTED_VERSION(
        1
      ) <= new Integer(version(1)) && MIN_SUPPORTED_VERSION(2) <= new Integer(version(2))
    }
    if (!versionSupported) {
      val message: String = String.format("Unsupported libsodium version: %s. Please update", lib.sodium_version_string)
      throw new UnsupportedOperationException(message)
    }
  }

  private def libraryName = Platform.getNativePlatform.getOS match {
    case Platform.OS.WINDOWS =>
      "libsodium"
    case _ =>
      "sodium"
  }

  private[tsec] lazy val Sodium: ScalaSodium = {
    val sodium = LibraryLoader
      .create(classOf[ScalaSodium])
      .search("/usr/local/lib")
      .search("/opt/local/lib")
      .search("lib")
      .load(libraryName)
    sodium.sodium_init
    sodium
  }

  def getSodiumUnsafe = Sodium

  def getSodiumUnsafe[F[_]](implicit F: Sync[F]): F[ScalaSodium] = F.delay(Sodium)

}
