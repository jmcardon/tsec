package tsec.libsodium.kdf

import cats.effect.Sync
import tsec.common._
import tsec.libsodium.{ContextBytesError, KeyLengthError, ScalaSodium}
import tsec.libsodium.cipher.SodiumKey
import tsec.libsodium.pk.PrivateKey

sealed trait KeyDerivation

object KeyDerivation {

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[PrivateKey[KeyDerivation]] = F.delay {
    val masterKey = PrivateKey[KeyDerivation](new Array[Byte](ScalaSodium.crypto_kdf_KEYBYTES))
    S.crypto_kdf_keygen(masterKey)
    masterKey
  }

  def deriveKey[F[_]](
      masterKey: PrivateKey[KeyDerivation],
      keyLength: Int,
      id: Int,
      context: String
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumKey[KeyDerivation]] = F.delay {
    if (ScalaSodium.crypto_kdf_BYTES_MIN > keyLength || keyLength > ScalaSodium.crypto_kdf_BYTES_MAX)
      throw KeyLengthError(keyLength)

    val ctx = context.utf8Bytes
    if (ctx.length != ScalaSodium.crypto_kdf_CONTEXTBYTES)
      throw ContextBytesError(ctx.length)

    val subKey = SodiumKey[KeyDerivation](new Array[Byte](keyLength))
    S.crypto_kdf_derive_from_key(subKey, keyLength, id, ctx, masterKey)

    subKey
  }
}
