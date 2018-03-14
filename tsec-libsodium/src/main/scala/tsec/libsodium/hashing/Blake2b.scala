package tsec.libsodium.hashing

import java.security.MessageDigest

import cats.effect.Sync
import tsec.hashing._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.ScalaSodium.NullPtrBytes
import tsec.libsodium.hashing.internal.SodiumHashPlatform

sealed trait Blake2b

object Blake2b extends SodiumHashPlatform[Blake2b] {
  val MinKeyLen     = ScalaSodium.crypto_generichash_blake2b_KEYBYTES_MIN
  val DefaultKeyLen = ScalaSodium.crypto_generichash_blake2b_KEYBYTES
  val MaxKeyLen     = ScalaSodium.crypto_generichash_blake2b_KEYBYTES_MAX

  val MinHashLen = ScalaSodium.crypto_generichash_blake2b_BYTES_MIN
  val MaxHashLen = ScalaSodium.crypto_generichash_blake2b_BYTES_MAX

  val algorithm: String = "Blake2b"

  /** Duplicate of values **/
  val hashLen: Int = ScalaSodium.crypto_generichash_blake2b_BYTES

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[BlakeKey] = F.delay {
    BlakeKey(ScalaSodium.randomBytesUnsafe(DefaultKeyLen))
  }

  def generateMinKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[BlakeKey] = F.delay {
    BlakeKey(ScalaSodium.randomBytesUnsafe(MinKeyLen))
  }

  def generateMaxKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[BlakeKey] = F.delay {
    BlakeKey(ScalaSodium.randomBytesUnsafe(MaxKeyLen))
  }

  def generateKeyVarLen[F[_]](len: Int)(implicit F: Sync[F], S: ScalaSodium): F[BlakeKey] = F.delay {
    val outLen = math.max(MinKeyLen, math.min(MaxKeyLen, len))
    BlakeKey(ScalaSodium.randomBytesUnsafe(outLen))
  }

  def hashVarLen[F[_]](
      in: Array[Byte],
      len: Int = hashLen
  )(implicit F: Sync[F], S: ScalaSodium): F[CryptoHash[Blake2b]] =
    F.delay {
      val outLen = math.max(MinHashLen, math.min(MaxHashLen, len))
      val out    = new Array[Byte](outLen)
      S.crypto_generichash(out, outLen, in, in.length, NullPtrBytes, 0)
      CryptoHash[Blake2b](out)
    }

  def verify[F[_]](in: Array[Byte], compare: CryptoHash[Blake2b], key: BlakeKey)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean] =
    F.delay {
      val out = new Array[Byte](compare.length)
      S.crypto_generichash(out, compare.length, in, in.length, key, key.length)
      MessageDigest.isEqual(out, compare)
    }

  def hashKeyed[F[_]](in: Array[Byte], key: BlakeKey)(implicit F: Sync[F], S: ScalaSodium): F[CryptoHash[Blake2b]] =
    F.delay {
      val out = new Array[Byte](hashLen)
      S.crypto_generichash(out, hashLen, in, in.length, key, key.length)
      CryptoHash[Blake2b](out)
    }

  def hashKeyedVarLen[F[_]](in: Array[Byte], key: BlakeKey, len: Int = hashLen)(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[CryptoHash[Blake2b]] = F.delay {
    val outLen = math.max(MinHashLen, math.min(MaxHashLen, len))
    val out    = new Array[Byte](outLen)
    S.crypto_generichash(out, outLen, in, in.length, key, key.length)
    CryptoHash[Blake2b](out)
  }

  def stateSize(implicit S: ScalaSodium): Int = S.crypto_generichash_statebytes

  def sodiumHash(in: Array[Byte], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_generichash(out, hashLen, in, in.length, NullPtrBytes, 0)

  def sodiumHashInit(state: HashState[Blake2b])(implicit S: ScalaSodium): Int =
    S.crypto_generichash_blake2b_init(state, NullPtrBytes, 0, hashLen)

  def sodiumHashChunk(state: HashState[Blake2b], in: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_generichash_update(state, in, in.length)

  def sodiumHashFinal(state: HashState[Blake2b], out: Array[Byte])(implicit S: ScalaSodium): Int =
    S.crypto_generichash_final(state, out, hashLen)

}
