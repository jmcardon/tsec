package tsec.passwordhashers.libsodium.internal

import cats.effect.Sync
import cats.syntax.all._
import tsec.libsodium.ScalaSodium
import tsec.passwordhashers._
import tsec.passwordhashers.libsodium._

trait SodiumPasswordHasher[P] extends PasswordHashAPI[P] {
  val hashingAlgorithm: String
  val saltLen: Int
  val outLen: Int

  def hashpwWithStrength[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PWStrengthParam[P, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[P]]

  final def checkPassShortCircuit[F[_]](
      raw: String,
      hash: PasswordHash[P]
  )(implicit F: Sync[F], S: ScalaSodium, P: PasswordHasher[F, P]): F[Unit] =
    checkpwBool[F](raw, hash).flatMap(res => if (res) F.unit else F.raiseError(SodiumPasswordError("Invalid password")))

}
