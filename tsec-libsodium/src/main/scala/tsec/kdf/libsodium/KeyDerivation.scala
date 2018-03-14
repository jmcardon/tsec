package tsec.kdf.libsodium

import cats.effect.Sync
import tsec.common._
import tsec.libsodium.ScalaSodium

sealed trait KeyDerivation

object KeyDerivation {

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[MasterKey] = F.delay {
    val masterKey = MasterKey(new Array[Byte](ScalaSodium.crypto_kdf_KEYBYTES))
    S.crypto_kdf_keygen(masterKey)
    masterKey
  }

  def deriveKey[F[_]](
      masterKey: MasterKey,
      keyLength: Int,
      id: Int,
      context: String
  )(implicit F: Sync[F], S: ScalaSodium): F[DerivedKey] = F.delay {
    if (ScalaSodium.crypto_kdf_BYTES_MIN > keyLength || keyLength > ScalaSodium.crypto_kdf_BYTES_MAX)
      throw KeyLengthError(keyLength)

    val ctx = context.utf8Bytes
    if (ctx.length != ScalaSodium.crypto_kdf_CONTEXTBYTES)
      throw ContextBytesError(ctx.length)

    val subKey = DerivedKey(new Array[Byte](keyLength))
    S.crypto_kdf_derive_from_key(subKey, keyLength, id, ctx, masterKey)

    subKey
  }
}
