package tsec.libsodium.authentication.internal

import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.authentication.{SodiumMAC, SodiumMACKey}

trait SodiumMacAlgebra[A] {

  def sign[F[_]](in: Array[Byte], key: SodiumMACKey[A])(implicit F: Sync[F], S: ScalaSodium): F[SodiumMAC[A]]

  def verify[F[_]](in: Array[Byte], hashed: SodiumMAC[A], key: SodiumMACKey[A])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean]

  def generateKey[F[_]](implicit F: Sync[F], S: ScalaSodium): F[SodiumMACKey[A]]

}
