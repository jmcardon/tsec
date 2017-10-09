package tsec

import cats.Eq
import tsec.common._
import cats.evidence.Is
import tsec.cipher.common._
import tsec.cipher.symmetric.imports._
import tsec.mac.imports.{MacTag, MacVerificationError}
import cats.instances.string._

package object cookies {

  protected val AEADCookie$$ : TaggedString = new TaggedString {
    type I = String
    val is = Is.refl[String]
  }

  type AEADCookie[A] = AEADCookie$$.I

  sealed trait EVCookieEncrypt[F[_]] {
    def fromEncrypted[A: AuthEncryptor](a: AEADCipherText[A], aad: AAD): F[A]

    def toString[A: AuthEncryptor](a: F[A]): String

    def subst[G[_], A: AuthEncryptor](fa: G[F[A]]): G[String]
  }

  implicit object AEADCookie extends EVCookieEncrypt[AEADCookie] {
    @inline def fromEncrypted[A: AuthEncryptor](a: AEADCipherText[A], aad: AAD): AEADCookie[A] =
      AEADCookie$$.is.flip.coerce(a.toSingleArray.toB64String + "-" + aad.aad.toB64String)

    @inline def toString[A: AuthEncryptor](a: AEADCookie[A]): String = AEADCookie$$.is.coerce(a)

    @inline def subst[G[_], A: AuthEncryptor](fa: G[AEADCookie[A]]): G[String] = AEADCookie$$.is.substitute[G](fa)
  }

  protected val SignedCookie$$ : TaggedString = new TaggedString {
    type I = String
    val is = Is.refl[String]
  }

  type SignedCookie[A] = SignedCookie$$.I

  sealed trait EVCookieMac[F[_]] {
    def from[A: MacTag: ByteEV](a: A, joined: String): F[A]

    def fromRaw[A: MacTag](raw: String): F[A]

    def to[A: MacTag](a: F[A]): String

    def substitute[G[_], A: MacTag](a: G[F[A]]): G[String]
  }

  implicit object SignedCookie extends EVCookieMac[SignedCookie] {
    @inline def from[A: MacTag: ByteEV](signed: A, joined: String): SignedCookie[A] =
      SignedCookie$$.is.flip.coerce(joined + "-" + signed.toArray.toB64String)

    @inline def fromRaw[A: MacTag](raw: String): SignedCookie[A] = SignedCookie$$.is.flip.coerce(raw)

    @inline def to[A: MacTag](a: SignedCookie[A]): String = SignedCookie$$.is.coerce(a)

    def getContent[A: MacTag](signed: SignedCookie[A]): Either[MacVerificationError, String] = {
      val split = to(signed).split("-")
      if(split.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        fromDecodedString(split(0).base64Bytes.toUtf8String)
      }
    }

    def fromDecodedString(original: String): Either[MacVerificationError, String] = {
      val split = original.split("-")
      if(split.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        Right(split(0).base64Bytes.toUtf8String)
      }

    }

    @inline def substitute[G[_], A: MacTag](fa: G[SignedCookie[A]]): G[String] = SignedCookie$$.is.substitute[G](fa)
  }

  implicit def cookieEQ[A: MacTag]: Eq[SignedCookie[A]] = Eq.by[SignedCookie[A], String](identity[String])

}
