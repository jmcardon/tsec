package tsec.libsodium.passwordhashers.internal

import cats.effect.Sync
import cats.syntax.all._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.passwordhashers.{PWStrengthParam => PS}
import tsec.libsodium.passwordhashers._
import tsec.passwordhashers.core.{PasswordHash, PasswordHashAPI, PasswordHasher}

trait SodiumPasswordHasher[P] extends PasswordHashAPI[P] {
  val hashingAlgorithm: String
  val saltLen: Int
  val outLen: Int

  def hashpwWithStrength[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PS[P, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[P]]

  final def checkPassShortCircuit[F[_]](
      raw: String,
      hash: PasswordHash[P]
  )(implicit F: Sync[F], S: ScalaSodium, P: PasswordHasher[F, P]): F[Unit] =
    checkpw[F](raw, hash).flatMap(res => if (res) F.unit else F.raiseError(SodiumPasswordError("Invalid password")))

}
