package tsec.libsodium.passwordhashers

import tsec.common._
import cats.effect.Sync
import tsec.libsodium.ScalaSodium
import tsec.libsodium.passwordhashers.internal.SodiumPasswordHasher

sealed trait Argon2

object Argon2 extends SodiumPasswordHasher[Argon2] {
  implicit val hasher: SodiumPasswordHasher[Argon2] = this
  val hashingAlgorithm: String = "Argon2id"
  val saltLen: Int             = ScalaSodium.crypto_pwhash_argon2id_SALTBYTES
  val outLen: Int              = ScalaSodium.crypto_pwhash_argon2id_STRBYTES

  def hashPassword[F[_], S](
      p: String,
      strength: S
  )(implicit pws: PWStrengthParam[Argon2, S], F: Sync[F], S: ScalaSodium): F[PasswordHash[Argon2]] = F.delay {
    val passBytes = p.asciiBytes
    val out       = new Array[Byte](outLen)
    if (p.isEmpty || !asciiEncoder.canEncode(p))
      throw SodiumPasswordError("Incorrect format")
    else if (S.crypto_pwhash_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
      throw SodiumPasswordError("Could not hash password. Possibly out of memory")
    else
      PasswordHash[Argon2](out.toAsciiString)
  }

  def checkPass[F[_]](raw: String, hash: PasswordHash[Argon2])(implicit F: Sync[F], S: ScalaSodium): F[Boolean] =
    F.delay {
      val rawBytes = raw.asciiBytes
      asciiEncoder.canEncode(raw) && S.crypto_pwhash_str_verify(hash.asciiBytes, rawBytes, raw.length) == 0
    }
}
