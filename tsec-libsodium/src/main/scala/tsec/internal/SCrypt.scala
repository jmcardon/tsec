package tsec.internal

import jnr.ffi.annotations.{In, Out}
import jnr.ffi.types.{size_t, u_int64_t}

private[tsec] trait SCrypt {

  def crypto_pwhash_scryptsalsa208sha256(
      @Out out: Array[Byte],
      @In @u_int64_t outLen: Int,
      @In passwd: Array[Byte],
      @In @u_int64_t passwdLen: Int,
      @In salt: Array[Byte],
      @In @u_int64_t opsLimit: Long,
      @In @size_t memLimit: Long
  ): Int

  def crypto_pwhash_scryptsalsa208sha256_str(
      @Out out: Array[Byte],
      @In passwd: Array[Byte],
      @In @u_int64_t passwdLen: Int,
      @In @u_int64_t opsLimit: Long,
      @In @size_t memLimit: Long
  ): Int

  def crypto_pwhash_scryptsalsa208sha256_str_verify(
      @In str: Array[Byte],
      @In passwd: Array[Byte],
      @In @u_int64_t passwdLen: Int
  ): Int

}

private[tsec] trait SCryptConstants {

  val crypto_pwhash_scryptsalsa208sha256_BYTES_MIN  = 16
  val crypto_pwhash_scryptsalsa208sha256_BYTES_MAX  = 4294967295L
  val crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN = 0L
  val crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX = 4294967295L
  val crypto_pwhash_scryptsalsa208sha256_SALTBYTES  = 32
  val crypto_pwhash_scryptsalsa208sha256_STRBYTES   = 102

  val crypto_pwhash_scryptsalsa208sha256_STRPREFIX    = "$7$"
  val crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN = 32768
  val crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX = 4294967295L
  val crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN = 16777216
  val crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX = 4398046510080L

  val crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE = 524288
  val crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE = 16777216
  val crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE   = 33554432
  val crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE   = 1073741824

}
