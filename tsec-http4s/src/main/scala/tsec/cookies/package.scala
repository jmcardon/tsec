package tsec

import tsec.common._
import cats.evidence.Is
import tsec.cipher.common._
import tsec.cipher.symmetric.imports._
import tsec.mac.imports.{MacTag, MacVerificationError}

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
    @inline def from[A: MacTag: ByteEV](a: A, joined: String): SignedCookie[A] =
      SignedCookie$$.is.flip.coerce(joined + "-" + a.toArray.toB64String)

    @inline def fromRaw[A: MacTag](raw: String): SignedCookie[A] = SignedCookie$$.is.flip.coerce(raw)

    @inline def to[A: MacTag](a: SignedCookie[A]): String = SignedCookie$$.is.coerce(a)

    def splitOriginal(original: String) = {
      val originalsplit = original.split("-")
      if(originalsplit.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        Right(originalsplit(0).base64Bytes.toUtf8String)
      }

    }

    @inline def substitute[G[_], A: MacTag](fa: G[SignedCookie[A]]): G[String] = SignedCookie$$.is.substitute[G](fa)
  }

}
