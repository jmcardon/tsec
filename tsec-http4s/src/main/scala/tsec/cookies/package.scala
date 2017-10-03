package tsec

import tsec.common._
import cats.evidence.Is
import tsec.cipher.common._
import tsec.cipher.symmetric.imports._
import tsec.mac.imports.MacTag

package object cookies {

  protected val AEADCookie$$ : IsString = new IsString {
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

  protected val SignedCookie$$ : IsString = new IsString {
    type I = String
    val is = Is.refl[String]
  }

  type SignedCookie[A] = SignedCookie$$.I

  sealed trait EVCookieMac[F[_]] {
    def from[A: MacTag: ByteEV](a: A, joined: String): F[A]

    def to[A: MacTag](a: F[A]): String

    def substitute[G[_], A: MacTag](a: G[F[A]]): G[String]
  }

  implicit object SignedCookie extends EVCookieMac[SignedCookie] {
    @inline def from[A: MacTag: ByteEV](a: A, joined: String): SignedCookie[A] =
      SignedCookie$$.is.flip.coerce(joined + "-" + a.toArray.toB64String)

    @inline def to[A: MacTag](a: SignedCookie[A]): String = SignedCookie$$.is.coerce(a)

    @inline def substitute[G[_], A: MacTag](fa: G[SignedCookie[A]]): G[String] = SignedCookie$$.is.substitute[G](fa)
  }

}
