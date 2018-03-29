package tsec.passwordhashers.libsodium

import cats.effect.Sync
import tsec.common._
import tsec.libsodium.ScalaSodium
import tsec.passwordhashers.libsodium.internal.SodiumPasswordHasher
import tsec.passwordhashers.{PasswordHash, PasswordHasher}

sealed trait Argon2

object Argon2 extends SodiumPasswordHasher[Argon2] {
  implicit val hasher: SodiumPasswordHasher[Argon2] = this
  val hashingAlgorithm: String                      = "Argon2id"
  val saltLen: Int                                  = ScalaSodium.crypto_pwhash_argon2id_SALTBYTES
  val outLen: Int                                   = ScalaSodium.crypto_pwhash_argon2id_STRBYTES

  implicit def passwordHasher[F[_]](implicit F: Sync[F], S: ScalaSodium): PasswordHasher[F, Argon2] =
    new PasswordHasher[F, Argon2] {
      def hashpw(p: Array[Char]): F[PasswordHash[Argon2]] =
        F.delay(hashpwUnsafe(p))

      def hashpw(p: Array[Byte]): F[PasswordHash[Argon2]] =
        F.delay(hashpwUnsafe(p))

      def checkpwBool(p: Array[Char], hash: PasswordHash[Argon2]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      def checkpwBool(p: Array[Byte], hash: PasswordHash[Argon2]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      private[tsec] def hashPassUnsafe(p: Array[Byte]): String =
        impl.unsafeHashpw(p, PasswordStrength.InteractiveStrength)

      private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[Argon2]): Boolean =
        impl.unsafeCheckpw(p, hash)
    }

  def hashpwWithStrength[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PWStrengthParam[Argon2, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[Argon2]] =
    F.delay(impl.unsafeHashpw(p.asciiBytes, strength))

  def checkPass[F[_]](raw: String, hash: PasswordHash[Argon2])(implicit F: Sync[F], S: ScalaSodium): F[Boolean] =
    F.delay(impl.unsafeCheckpw(raw.asciiBytes, hash))

  object impl {
    def unsafeHashpw[S](
        passBytes: Array[Byte],
        strength: S
    )(implicit pws: PWStrengthParam[Argon2, S], S: ScalaSodium): PasswordHash[Argon2] = {
      val out = new Array[Byte](outLen)
      if (passBytes.isEmpty)
        throw SodiumPasswordError("Incorrect format")
      else if (S.crypto_pwhash_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
        throw SodiumPasswordError("Could not hash password. Possibly out of memory")
      else
        PasswordHash[Argon2](out.toAsciiString)
    }

    def unsafeCheckpw(raw: Array[Byte], hash: PasswordHash[Argon2])(implicit S: ScalaSodium): Boolean =
      S.crypto_pwhash_str_verify(hash.asciiBytes, raw, raw.length) == 0
  }
}
