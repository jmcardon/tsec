package tsec.libsodium.authentication.internal

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.authentication.{SodiumMAC, SodiumMACKey}

private[tsec] trait SodiumMacPlatform[A] extends SodiumMac[A] with SodiumMacAlgebra[A] {
  implicit val sm: SodiumMac[A]                = this
  implicit val macAlgebra: SodiumMacAlgebra[A] = this

  def sign[F[_]](in: Array[Byte], key: SodiumMACKey[A])(implicit F: Sync[F], S: ScalaSodium): F[SodiumMAC[A]] =
    F.delay {
      val out = new Array[Byte](macLen)
      sodiumSign(in, out, key)
      SodiumMAC[A](out)
    }

  def verify[F[_]](in: Array[Byte], hashed: SodiumMAC[A], key: SodiumMACKey[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean] = F.delay {
    sodiumVerify(in, hashed, key) == 0
  }

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumMACKey[A]] = F.delay {
    SodiumMACKey[A](ScalaSodium.randomBytesUnsafe(keyLen))
  }
}
