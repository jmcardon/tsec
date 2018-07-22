package tsec.hashing.libsodium

import tsec.hashing.libsodium.internal.SodiumHashPlatform
import tsec.libsodium.ScalaSodium

sealed trait SodiumSHA512

object SodiumSHA512 extends SodiumHashPlatform[SodiumSHA512]("SHA512") {
  val hashLen: Int = 64

  def stateSize(implicit S: ScalaSodium): Int = S.crypto_hash_sha512_statebytes

  def sodiumHash(in: Array[Byte], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha512(out, in, in.length)

  def sodiumHashInit(state: HashState[SodiumSHA512])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha512_init(state)

  def sodiumHashChunk(state: HashState[SodiumSHA512], in: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha512_update(state, in, in.length)

  def sodiumHashFinal(state: HashState[SodiumSHA512], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_hash_sha512_final(state, out)
}
