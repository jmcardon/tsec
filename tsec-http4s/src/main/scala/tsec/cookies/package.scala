package tsec

import cats.Eq
import tsec.common._
import cats.evidence.Is
import cats.instances.string._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.mac.imports.{MacTag, MacVerificationError}

import io.circe.{Decoder, Encoder, HCursor, Json}

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

    @inline def fromRaw[A: AuthEncryptor](raw: String): AEADCookie[A] = AEADCookie$$.is.flip.coerce(raw)

    def getEncryptedContent[A](
        signed: AEADCookie[A]
    )(implicit encryptor: AuthEncryptor[A]): Either[CipherTextError, AEADCipherText[A]] = {
      val split = toString[A](signed).split("-")
      if (split.length != 2)
        Left(CipherTextError("String encoded improperly"))
      else {
        encryptor.fromSingleArray(split(0).base64Bytes)
      }
    }

    implicit def circeDecoder[A: AuthEncryptor]: Decoder[AEADCookie[A]] = new Decoder[AEADCookie[A]] {
      def apply(c: HCursor) = c.as[String].map(AEADCookie.fromRaw[A])
    }

    implicit def circeEncoder[A: AuthEncryptor]: Encoder[AEADCookie[A]] = new Encoder[AEADCookie[A]] {
      def apply(a: AEADCookie[A]): Json = Json.fromString(a)
    }

  }

  protected val SignedCookie$$ : TaggedString = new TaggedString {
    type I = String
    val is = Is.refl[String]
  }

  type SignedCookie[A] = SignedCookie$$.I

  sealed trait EVCookieMac[F[_]] {
    def from[A: MacTag: ByteEV](a: A, joined: String): F[A]

    def fromRaw[A: MacTag](raw: String): F[A]

    def toString[A: MacTag](a: F[A]): String

    def substitute[G[_], A: MacTag](a: G[F[A]]): G[String]
  }

  implicit object SignedCookie extends EVCookieMac[SignedCookie] {
    @inline def from[A: MacTag: ByteEV](signed: A, joined: String): SignedCookie[A] =
      SignedCookie$$.is.flip.coerce(joined + "-" + signed.toArray.toB64String)

    @inline def fromRaw[A: MacTag](raw: String): SignedCookie[A] = SignedCookie$$.is.flip.coerce(raw)

    @inline def toString[A: MacTag](a: SignedCookie[A]): String = SignedCookie$$.is.coerce(a)

    def getContent[A: MacTag](signed: SignedCookie[A]): Either[MacVerificationError, String] = {
      val split = toString(signed).split("-")
      if (split.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        fromDecodedString(split(0).base64Bytes.toUtf8String)
      }
    }

    def fromDecodedString(original: String): Either[MacVerificationError, String] = {
      val split = original.split("-")
      if (split.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        Right(split(0).base64Bytes.toUtf8String)
      }

    }

    @inline def substitute[G[_], A: MacTag](fa: G[SignedCookie[A]]): G[String] = SignedCookie$$.is.substitute[G](fa)
  }
  implicit final def cookieEQ[A: MacTag]: Eq[SignedCookie[A]]       = Eq.by[SignedCookie[A], String](identity[String])
  implicit final def ecookieEQ[A: AuthEncryptor]: Eq[AEADCookie[A]] = Eq.by[AEADCookie[A], String](identity[String])
}
