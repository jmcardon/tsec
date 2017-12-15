package tsec.libsodium.kdf

import cats.data.StateT
import cats.effect.Sync
import tsec.libsodium.ScalaSodium
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
      context: Array[Byte]
  )(implicit F: Sync[F], S: ScalaSodium): StateT[F, Int, SodiumKey[KeyDerivation]] =
    StateT[F, Int, SodiumKey[KeyDerivation]] { id =>

      if (ScalaSodium.crypto_kdf_BYTES_MIN > keyLength || keyLength > ScalaSodium.crypto_kdf_BYTES_MAX)
        throw KeyLengthError(keyLength)

      if(context.length != ScalaSodium.crypto_kdf_CONTEXTBYTES)
        throw ContextBytesError(context.length)

      val subKey = SodiumKey[KeyDerivation](new Array[Byte](keyLength))
      S.crypto_kdf_derive_from_key(subKey, keyLength, id, context, masterKey)

      F.delay((id + 1, subKey))
    }
}
