package tsec.libsodium.passwordhashers

import tsec.common._
import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.passwordhashers.internal.SodiumPasswordHasher

sealed trait SodiumSCrypt

object SodiumSCrypt extends SodiumPasswordHasher[SodiumSCrypt] {
  implicit val hasher: SodiumPasswordHasher[SodiumSCrypt] = this

  val hashingAlgorithm: String = "SCrypt"
  val saltLen: Int             = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
  val outLen: Int              = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES

  def hashPassword[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PWStrengthParam[SodiumSCrypt, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[SodiumSCrypt]] =
    F.delay {
      val passBytes = p.asciiBytes
      val out       = new Array[Byte](outLen)
      if (p.isEmpty || !asciiEncoder.canEncode(p))
        throw SodiumPasswordError("Incorrect format")
      else if (S.crypto_pwhash_scryptsalsa208sha256_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
        throw SodiumPasswordError("Could not hash password. Possibly out of memory")
      else
        PasswordHash[SodiumSCrypt](out.toAsciiString)
    }

  def checkPass[F[_]](raw: String, hash: PasswordHash[SodiumSCrypt])(
      implicit F: Sync[F],
      S: ScalaSodium
  ): F[Boolean] = F.delay {
    val rawBytes = raw.asciiBytes
    asciiEncoder
      .canEncode(raw) && S.crypto_pwhash_scryptsalsa208sha256_str_verify(hash.asciiBytes, rawBytes, raw.length) == 0
  }
}
