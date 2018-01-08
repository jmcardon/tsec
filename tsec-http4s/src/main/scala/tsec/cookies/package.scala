package tsec

import cats.Eq
import tsec.common._
import cats.evidence.Is
import cats.instances.string._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.mac.imports.MacVerificationError
import io.circe.{Decoder, Encoder, HCursor, Json}
import tsec.mac.core.{MAC, MacTag}

package object cookies {

  protected val AEADCookie$$ : HKStringNewt = new HKStringNewt {
    type Repr[A] = String
    def is[A] = Is.refl[String]
  }

  type AEADCookie[A] = AEADCookie$$.Repr[A]

  sealed trait EVCookieEncrypt[F[_]] {
    def fromEncrypted[A: AES](a: GCMCipherText[A], aad: AAD): F[A]

    def toString[A: AES](a: F[A]): String

    def subst[G[_], A: AES](fa: G[F[A]]): G[String]
  }

  implicit object AEADCookie extends EVCookieEncrypt[AEADCookie] {
    @inline def fromEncrypted[A: AES](a: GCMCipherText[A], aad: AAD): AEADCookie[A] =
      AEADCookie$$.is[A].coerce(a.toSingleArray.toB64String + "-" + aad.toB64String)

    @inline def toString[A: AES](a: AEADCookie[A]): String = AEADCookie$$.is.coerce(a)

    @inline def subst[G[_], A: AES](fa: G[AEADCookie[A]]): G[String] = AEADCookie$$.is[A].flip.substitute[G](fa)

    @inline def apply[A: AES](raw: String): AEADCookie[A] = AEADCookie$$.is[A].coerce(raw)

    def getEncryptedContent[F[_], A: AES](
        signed: AEADCookie[A]
    )(implicit encryptor: GCMEncryptor[F, A]): Either[CipherTextError, GCMCipherText[A]] = {
      val split = toString[A](signed).split("-")
      if (split.length != 2)
        Left(CipherTextError("String encoded improperly"))
      else {
        CipherText.fromArray(split(0).base64Bytes)(encryptor.ivProcess)
      }
    }

    implicit def circeDecoder[A: AES]: Decoder[AEADCookie[A]] = new Decoder[AEADCookie[A]] {
      def apply(c: HCursor) = c.as[String].map(AEADCookie.apply[A])
    }

    implicit def circeEncoder[A: AES]: Encoder[AEADCookie[A]] = new Encoder[AEADCookie[A]] {
      def apply(a: AEADCookie[A]): Json = Json.fromString(a)
    }

  }

  protected val SignedCookie$$ : HKStringNewt = new HKStringNewt {
    type Repr[A] = String

    def is[A] = Is.refl[Repr[A]]
  }

  type SignedCookie[A] = SignedCookie$$.Repr[A]

  sealed trait EVCookieMac[F[_]] {
    def from[A: MacTag](a: MAC[A], joined: String): F[A]

    def apply[A: MacTag](raw: String): F[A]

    def toString[A: MacTag](a: F[A]): String
  }

  implicit object SignedCookie extends EVCookieMac[SignedCookie] {
    @inline def from[A: MacTag](signed: MAC[A], joined: String): SignedCookie[A] =
      SignedCookie$$.is.coerce(joined + "-" + signed.toB64String)

    @inline def apply[A: MacTag](raw: String): SignedCookie[A] = SignedCookie$$.is.coerce(raw)

    @inline def toString[A: MacTag](a: SignedCookie[A]): String = SignedCookie$$.is.coerce(a)

    def getContent[A: MacTag](signed: SignedCookie[A]): Either[MacVerificationError, String] = {
      val split = toString(signed).split("-")
      if (split.length != 2)
        Left(MacVerificationError("String encoded improperly"))
      else {
        fromDecodedString(split(0).base64Bytes.toUtf8String)
      }
    }

    def fromDecodedString(original: String): Either[MacVerificationError, String] =
      original.split("-") match {
        case Array(orig, nonce) =>
          Right(orig.base64Bytes.toUtf8String)
        case _ =>
          Left(MacVerificationError("String encoded improperly"))
      }

    @inline def is[A]: Is[String, SignedCookie[A]] = SignedCookie$$.is[A]
  }
  implicit final def cookieEQ[A: MacTag]: Eq[SignedCookie[A]] = Eq.by[SignedCookie[A], String](identity[String])
  implicit final def ecookieEQ[A: AES]: Eq[AEADCookie[A]]     = Eq.by[AEADCookie[A], String](identity[String])
}
