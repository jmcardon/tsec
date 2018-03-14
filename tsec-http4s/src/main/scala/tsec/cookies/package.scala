package tsec

import cats.Eq
import cats.instances.string._
import io.circe.{Decoder, Encoder, HCursor, Json}
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.imports._
import tsec.common._
import tsec.mac.MAC
import tsec.mac.imports.{JCAMacTag, MacVerificationError}

package object cookies {

  type AEADCookie[A] = AEADCookie.Cookie[A]

  implicit object AEADCookie  {
    type Cookie[A] <: String

    @inline def fromEncrypted[A: AES](a: CipherText[A], aad: AAD): AEADCookie[A] =
      apply[A](a.toConcatenated.toB64String + "-" + aad.toB64String)

    @inline def subst[G[_], A: AES](fa: G[AEADCookie[A]]): G[String] = fa.asInstanceOf[G[String]]

    @inline def apply[A: AES](raw: String): AEADCookie[A] = raw.asInstanceOf[AEADCookie[A]]

    def getEncryptedContent[F[_], A: AES](
        signed: AEADCookie[A]
    )(implicit encryptor: AADEncryptor[F, A, SecretKey]): Either[CipherTextError, CipherText[A]] = {
      val split = signed.split("-")
      if (split.length != 2)
        Left(CipherTextError("String encoded improperly"))
      else {
        CTOPS.ciphertextFromArray[A, GCM, NoPadding](split(0).base64Bytes)
      }
    }

    implicit def circeDecoder[A: AES]: Decoder[AEADCookie[A]] = new Decoder[AEADCookie[A]] {
      def apply(c: HCursor) = c.as[String].map(AEADCookie.apply[A])
    }

    implicit def circeEncoder[A: AES]: Encoder[AEADCookie[A]] = new Encoder[AEADCookie[A]] {
      def apply(a: AEADCookie[A]): Json = Json.fromString(a)
    }

  }

  type SignedCookie[A] = SignedCookie.Cookie[A]

  implicit object SignedCookie {
    type Cookie[A] <: String

    @inline def from[A: JCAMacTag](signed: MAC[A], joined: String): SignedCookie[A] =
      apply[A](joined + "-" + signed.toB64String)

    @inline def apply[A: JCAMacTag](raw: String): SignedCookie[A] = raw.asInstanceOf[SignedCookie[A]]

    def getContent[A: JCAMacTag](signed: SignedCookie[A]): Either[MacVerificationError, String] = {
      val split = signed.split("-")
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
  }
  implicit final def cookieEQ[A: JCAMacTag]: Eq[SignedCookie[A]] = Eq.by[SignedCookie[A], String](identity[String])
  implicit final def ecookieEQ[A: AES]: Eq[AEADCookie[A]]        = Eq.by[AEADCookie[A], String](identity[String])
}
