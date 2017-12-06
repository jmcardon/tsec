package tsec.libsodium.hashing

import tsec.libsodium.ScalaSodium
import tsec.libsodium.hashing.internal.SodiumHashPlatform

sealed trait SodiumSHA256

object SodiumSHA256 extends SodiumHashPlatform[SodiumSHA256] {
  val hashLen: Int = 32

  val algorithm: String = "SHA256"

  def stateSize(implicit S: ScalaSodium): Int = S.crypto_hash_sha256_statebytes

  def sodiumHash(in: Array[Byte], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha256(out, in, in.length)

  def sodiumHashInit(state: HashState[SodiumSHA256])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha256_init(state)

  def sodiumHashChunk(state: HashState[SodiumSHA256], in: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha256_update(state, in, in.length)

  def sodiumHashFinal(state: HashState[SodiumSHA256], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha256_final(state, out)
}
