package tsec.libsodium.passwordhashers.internal

import cats.effect.Sync
import cats.syntax.all._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.passwordhashers.{PWStrengthParam => PS}
import tsec.libsodium.passwordhashers._

trait SodiumPasswordHasher[PwTyp] {
  val hashingAlgorithm: String
  val saltLen: Int
  val outLen: Int

  def hashPassword[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PS[PwTyp, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[PwTyp]]

  def checkPass[F[_]](raw: String, hash: PasswordHash[PwTyp])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean]

  final def checkPassShortCircuit[F[_]](
      raw: String,
      hash: PasswordHash[PwTyp]
  )(implicit F: Sync[F], S: ScalaSodium): F[Unit] =
    checkPass[F](raw, hash).flatMap(res => if (res) F.unit else F.raiseError(SodiumPasswordError("Invalid password")))
}