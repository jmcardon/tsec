package tsec.libsodium.passwordhashers

import cats.effect.Sync
import tsec.common._
import tsec.passwordhashers.core._
import tsec.libsodium.ScalaSodium
import tsec.libsodium.passwordhashers.internal.SodiumPasswordHasher

sealed trait SodiumSCrypt

object SodiumSCrypt extends SodiumPasswordHasher[SodiumSCrypt] {
  implicit val hasher: SodiumPasswordHasher[SodiumSCrypt] = this

  val hashingAlgorithm: String = "SCrypt"
  val saltLen: Int             = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
  val outLen: Int              = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES

  def hashpwWithStrength[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PWStrengthParam[SodiumSCrypt, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[SodiumSCrypt]] =
    F.delay(impl.unsafeHashpw(p.asciiBytes, strength))

  implicit def genHasher[F[_]](implicit F: Sync[F], S: ScalaSodium): PasswordHasher[F, SodiumSCrypt] =
    new PasswordHasher[F, SodiumSCrypt] {
      def hashpw(p: Array[Char]): F[PasswordHash[SodiumSCrypt]] =
        F.delay(hashpwUnsafe(p))

      def hashpw(p: Array[Byte]): F[PasswordHash[SodiumSCrypt]] =
        F.delay(hashpwUnsafe(p))

      def checkpw(p: Array[Char], hash: PasswordHash[SodiumSCrypt]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      def checkpw(p: Array[Byte], hash: PasswordHash[SodiumSCrypt]): F[Boolean] =
        F.delay(checkpwUnsafe(p, hash))

      private[tsec] def hashPassUnsafe(p: Array[Byte]): String =
        impl.unsafeHashpw(p, PasswordStrength.InteractiveStrength)

      private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[SodiumSCrypt]): Boolean =
        impl.unsafeCheckpw(p, hash)
    }

  object impl {
    def unsafeHashpw[S](
        passBytes: Array[Byte],
        strength: S
    )(implicit pws: PWStrengthParam[SodiumSCrypt, S], S: ScalaSodium): PasswordHash[SodiumSCrypt] = {
      val out = new Array[Byte](outLen)
      if (passBytes.isEmpty)
        throw SodiumPasswordError("Incorrect format")
      else if (S.crypto_pwhash_scryptsalsa208sha256_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
        throw SodiumPasswordError("Could not hash password. Possibly out of memory")
      else
        PasswordHash[SodiumSCrypt](out.toAsciiString)
    }

    def unsafeCheckpw(rawBytes: Array[Byte], hash: PasswordHash[SodiumSCrypt])(
        implicit S: ScalaSodium
    ): Boolean =
      S.crypto_pwhash_scryptsalsa208sha256_str_verify(hash.asciiBytes, rawBytes, rawBytes.length) == 0
  }
}
