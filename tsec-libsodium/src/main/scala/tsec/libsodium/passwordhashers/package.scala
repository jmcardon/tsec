package tsec.libsodium

import java.nio.charset.Charset

import cats.effect.Sync
import cats.evidence.Is
import tsec.common._
import tsec.libsodium.passwordhashers.internal.SodiumPasswordHasher

package object passwordhashers {

  final case class SodiumPasswordError(reason: String) extends Exception {
    override def getMessage: String = reason

    override def fillInStackTrace(): Throwable = this
  }

  private val asciiEncoder = Charset.forName("US-ASCII").newEncoder()

  trait PWStrengthParam[PTyp, Str] {
    val opLimit: Int
    val memLimit: Int
  }

  private[tsec] val Argon2$$ : TaggedString = new TaggedString {
    type I = String
    val is = Is.refl[I]
  }

  type Argon2 = Argon2$$.I

  object Argon2 extends SodiumPasswordHasher[Argon2] {
    def apply(s: String): Argon2       = is.flip.coerce(s)
    @inline def is: Is[Argon2, String] = Argon2$$.is

    val hashingAlgorithm: String = "Argon2id"
    val saltLen: Int             = ScalaSodium.crypto_pwhash_argon2id_SALTBYTES
    val outLen: Int              = ScalaSodium.crypto_pwhash_argon2id_STRBYTES

    def hashPassword[F[_], S](
        p: String,
        strength: S
    )(implicit pws: PWStrengthParam[Argon2, S], F: Sync[F], S: ScalaSodium): F[Argon2] = F.delay {
      val passBytes = p.asciiBytes
      val out       = new Array[Byte](outLen)
      if (p.isEmpty || !asciiEncoder.canEncode(p))
        throw SodiumPasswordError("Incorrect format")
      else if (S.crypto_pwhash_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
        throw SodiumPasswordError("Could not hash password. Possibly out of memory")
      else
        Argon2(out.toAsciiString)
    }

    def checkPass[F[_]](raw: String, hash: Argon2)(implicit F: Sync[F], S: ScalaSodium): F[Boolean] = F.delay {
      val rawBytes = raw.asciiBytes
      asciiEncoder.canEncode(raw) && S.crypto_pwhash_str_verify(hash.asciiBytes, rawBytes, raw.length) == 0
    }

    def checkPassShortCircuit[F[_]](raw: String, hash: Argon2)(implicit F: Sync[F], S: ScalaSodium): F[Unit] = F.delay {
      val rawBytes = raw.asciiBytes
      if (!asciiEncoder.canEncode(raw) || S.crypto_pwhash_str_verify(hash.asciiBytes, rawBytes, raw.length) != 0)
        throw SodiumPasswordError("Invalid password")
    }

  }

  private[tsec] val ScryptS$$ : TaggedString = new TaggedString {
    type I = String
    val is = Is.refl[I]
  }

  type SodiumSCrypt = ScryptS$$.I

  object SodiumSCrypt extends SodiumPasswordHasher[SodiumSCrypt] {
    def apply(s: String): SodiumSCrypt       = is.flip.coerce(s)
    @inline def is: Is[SodiumSCrypt, String] = ScryptS$$.is

    val hashingAlgorithm: String = "SCrypt"
    val saltLen: Int             = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
    val outLen: Int              = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES

    def hashPassword[F[_], S](
        p: String,
        strength: S
    )(implicit pws: PWStrengthParam[SodiumSCrypt, S], F: Sync[F], S: ScalaSodium): F[SodiumSCrypt] = F.delay {
      val passBytes = p.asciiBytes
      val out       = new Array[Byte](outLen)
      if (p.isEmpty || !asciiEncoder.canEncode(p))
        throw SodiumPasswordError("Incorrect format")
      else if (S.crypto_pwhash_scryptsalsa208sha256_str(out, passBytes, passBytes.length, pws.opLimit, pws.memLimit) != 0)
        throw SodiumPasswordError("Could not hash password. Possibly out of memory")
      else
        SodiumSCrypt(out.toAsciiString)
    }

    def checkPass[F[_]](raw: String, hash: SodiumSCrypt)(implicit F: Sync[F], S: ScalaSodium): F[Boolean] = F.delay {
      val rawBytes = raw.asciiBytes
      asciiEncoder
        .canEncode(raw) && S.crypto_pwhash_scryptsalsa208sha256_str_verify(hash.asciiBytes, rawBytes, raw.length) == 0
    }

    def checkPassShortCircuit[F[_]](raw: String, hash: SodiumSCrypt)(implicit F: Sync[F], S: ScalaSodium): F[Unit] =
      F.delay {
        val rawBytes = raw.asciiBytes
        if (!asciiEncoder.canEncode(raw) || S.crypto_pwhash_scryptsalsa208sha256_str_verify(
              hash.asciiBytes,
              rawBytes,
              raw.length
            ) != 0)
          throw SodiumPasswordError("Invalid password")
      }
  }

  object PasswordStrength {
    object MinStrength
    object InteractiveStrength
    object ModerateStrength
    object SensitiveStrength
  }

  type MinStrength         = PasswordStrength.MinStrength.type
  type InteractiveStrength = PasswordStrength.InteractiveStrength.type
  type ModerateStrength    = PasswordStrength.ModerateStrength.type
  type SensitiveStrength   = PasswordStrength.SensitiveStrength.type

  implicit val argonMinstr: PWStrengthParam[Argon2, MinStrength] = new PWStrengthParam[Argon2, MinStrength] {
    val opLimit: Int  = ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_MIN
    val memLimit: Int = ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_MIN
  }

  implicit val argonInteractiveStr: PWStrengthParam[Argon2, InteractiveStrength] =
    new PWStrengthParam[Argon2, InteractiveStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
      val memLimit: Int = ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
    }

  implicit val argonModerateStr: PWStrengthParam[Argon2, ModerateStrength] =
    new PWStrengthParam[Argon2, ModerateStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_MODERATE
      val memLimit: Int = ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_MODERATE
    }

  implicit val argonSensitiveStr: PWStrengthParam[Argon2, SensitiveStrength] =
    new PWStrengthParam[Argon2, SensitiveStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
      val memLimit: Int = ScalaSodium.crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
    }

  //
  implicit val SodiumSCryptMinstr: PWStrengthParam[SodiumSCrypt, MinStrength] =
    new PWStrengthParam[SodiumSCrypt, MinStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN
      val memLimit: Int = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN
    }

  implicit val SodiumSCryptInteractiveStr: PWStrengthParam[SodiumSCrypt, InteractiveStrength] =
    new PWStrengthParam[SodiumSCrypt, InteractiveStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
      val memLimit: Int = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
    }

  implicit val SodiumSCryptSensitiveStr: PWStrengthParam[SodiumSCrypt, SensitiveStrength] =
    new PWStrengthParam[SodiumSCrypt, SensitiveStrength] {
      val opLimit: Int  = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
      val memLimit: Int = ScalaSodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
    }

}
