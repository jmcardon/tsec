package tsec.libsodium

import cats.effect.Sync
import cats.evidence.Is
import tsec.common.{ByteUtils, TaggedByteArray}
import tsec.libsodium.ScalaSodium.{NullPtrBytes, NullPtrInt}
import tsec.libsodium.hashing.SodiumHS256$$

package object hashing {

  private[tsec] val Blake2b$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type Blake2b = Blake2b$$.I

  private[tsec] val BlakeKey$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type BlakeKey = BlakeKey$$.I

  object BlakeKey {
    def apply(bytes: Array[Byte]): BlakeKey   = is.flip.coerce(bytes)
    @inline def is: Is[BlakeKey, Array[Byte]] = BlakeKey$$.is
  }

  object Blake2b {
    val MinKeyLen     = ScalaSodium.crypto_generichash_blake2b_KEYBYTES_MIN
    val DefaultKeyLen = ScalaSodium.crypto_generichash_blake2b_KEYBYTES
    val MaxKeyLen     = ScalaSodium.crypto_generichash_blake2b_KEYBYTES_MAX

    val MinHashLen     = ScalaSodium.crypto_generichash_blake2b_BYTES_MIN
    val DefaultHashLen = ScalaSodium.crypto_generichash_blake2b_BYTES
    val MaxHashLen     = ScalaSodium.crypto_generichash_blake2b_BYTES_MAX

    def apply(bytes: Array[Byte]): Blake2b   = is.flip.coerce(bytes)
    @inline def is: Is[Blake2b, Array[Byte]] = Blake2b$$.is

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

    def hash[F[_]](in: Array[Byte])(implicit F: Sync[F], S: ScalaSodium): F[Blake2b] = F.delay {
      val out = new Array[Byte](DefaultHashLen)
      S.crypto_generichash(out, DefaultHashLen, in, in.length, NullPtrBytes, 0)
      Blake2b(out)
    }

    def hashVarLen[F[_]](in: Array[Byte], len: Int = DefaultHashLen)(implicit F: Sync[F], S: ScalaSodium): F[Blake2b] =
      F.delay {
        val outLen = math.max(MinHashLen, math.min(MaxHashLen, len))
        val out    = new Array[Byte](outLen)
        S.crypto_generichash(out, outLen, in, in.length, NullPtrBytes, 0)
        Blake2b(out)
      }

    def verify[F[_]](in: Array[Byte], compare: Blake2b, key: BlakeKey)(
        implicit F: Sync[F],
        S: ScalaSodium
    ): F[Boolean] =
      F.delay {
        val out = new Array[Byte](compare.length)
        S.crypto_generichash(out, compare.length, in, in.length, key, key.length)
        ByteUtils.constantTimeEquals(out, compare)
      }

    def hashKeyed[F[_]](in: Array[Byte], key: BlakeKey)(implicit F: Sync[F], S: ScalaSodium): F[Blake2b] = F.delay {
      val out = new Array[Byte](DefaultHashLen)
      S.crypto_generichash(out, DefaultHashLen, in, in.length, key, key.length)
      Blake2b(out)
    }

    def hashKeyedVarLen[F[_]](in: Array[Byte], key: BlakeKey, len: Int = DefaultHashLen)(
        implicit F: Sync[F],
        S: ScalaSodium
    ): F[Blake2b] = F.delay {
      val outLen = math.max(MinHashLen, math.min(MaxHashLen, len))
      val out    = new Array[Byte](outLen)
      S.crypto_generichash(out, outLen, in, in.length, key, key.length)
      Blake2b(out)
    }
  }

  private[tsec] val HMACKey$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type HMACKey = HMACKey$$.I

  //Todo: Abstract out into HS256 and HS512
  object HMACKey {
    def apply(bytes: Array[Byte]): HMACKey   = is.flip.coerce(bytes)
    @inline def is: Is[HMACKey, Array[Byte]] = HMACKey$$.is
  }

  private[tsec] val SodiumHS256$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[I]
  }

  type SodiumHS256 = SodiumHS256$$.I

  object SodiumHS256 {
    def apply(bytes: Array[Byte]): SodiumHS256 = is.flip.coerce(bytes)
    def is: Is[SodiumHS256, Array[Byte]]       = SodiumHS256$$.is

    val DefaultKeyLen = ScalaSodium.crypto_auth_hmacsha256_KEYBYTES

    val DefaultHashLen = ScalaSodium.crypto_auth_hmacsha256_BYTES

    def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[HMACKey] = F.delay {
      HMACKey(ScalaSodium.randomBytesUnsafe(DefaultKeyLen))
    }

    def sign[F[_]](in: Array[Byte], key: HMACKey)(implicit F: Sync[F], S: ScalaSodium): F[SodiumHS256] = F.delay {
      val out = new Array[Byte](DefaultHashLen)
      S.crypto_auth_hmacsha256(out, in, in.length, key)
      SodiumHS256(out)
    }

    def verify[F[_]](in: Array[Byte], hashed: SodiumHS256, key: HMACKey)(
        implicit F: Sync[F],
        S: ScalaSodium
    ): F[Boolean] = F.delay {
      S.crypto_auth_hmacsha256_verify(hashed, in, in.length, key) == 0
    }

  }

}
