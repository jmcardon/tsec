package tsec.libsodium

import java.nio.charset.Charset

import cats.effect.Sync
import cats.evidence.Is
import tsec.common._
import tsec.libsodium.passwordhashers.PasswordHash$$
import tsec.libsodium.passwordhashers.internal.SodiumPasswordHasher

package object passwordhashers {

  final case class SodiumPasswordError(reason: String) extends Exception {
    override def getMessage: String = reason

    override def fillInStackTrace(): Throwable = this
  }

  private[passwordhashers] val asciiEncoder = Charset.forName("US-ASCII").newEncoder()

  trait PWStrengthParam[PTyp, Str] {
    val opLimit: Int
    val memLimit: Int
  }

  private[tsec] val PasswordHash$$ : HKStringNewt = new HKStringNewt {
    type Repr[A] = String

    def is[G] = Is.refl[String]
  }

  type PasswordHash[A] = PasswordHash$$.Repr[A]

  object PasswordHash {
    def apply[A](string: String): PasswordHash[A]  = is[A].coerce(string)
    @inline def is[A]: Is[String, PasswordHash[A]] = PasswordHash$$.is[A]
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
