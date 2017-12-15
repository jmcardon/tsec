package tsec.libsodium.authentication

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.cipher.SodiumKey

sealed trait OnetimeAuth

sealed trait MessageTag

object OnetimeAuth {

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumKey[OnetimeAuth]] = F.delay {
    val key = SodiumKey[OnetimeAuth](new Array[Byte](ScalaSodium.crypto_onetimeauth_poly1305_KEYBYTES))

    S.crypto_onetimeauth_keygen(key)

    key
  }

  def generateTag[F[_]](
      key: SodiumKey[OnetimeAuth],
      message: Array[Byte]
  )(implicit F: Sync[F], S: ScalaSodium): F[SodiumKey[MessageTag]] = F.delay {
    val tag = SodiumKey[MessageTag](new Array[Byte](ScalaSodium.crypto_onetimeauth_poly1305_BYTES))

    S.crypto_onetimeauth(tag, message, message.length, key)

    tag
  }

  def verify[F[_]](key: SodiumKey[OnetimeAuth], message: Array[Byte], tag: SodiumKey[MessageTag])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean] = F.delay(S.crypto_onetimeauth_verify(tag, message, message.length, key) == 0)

}
