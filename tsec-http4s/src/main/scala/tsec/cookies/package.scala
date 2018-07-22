package tsec

import cats.{Eq, MonadError}
import cats.instances.string._
import cats.syntax.either._
import io.circe.{Decoder, Encoder, HCursor, Json}
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca._
import tsec.common._
import tsec.mac.MAC
import tsec.mac.jca.MacVerificationError

package object cookies {

  type AEADCookie[A] = AEADCookie.Cookie[A]

  implicit object AEADCookie {
    type Cookie[A] <: String

    @inline def fromEncrypted[A](a: CipherText[A], aad: AAD): AEADCookie[A] =
      apply[A](a.toConcatenated.toB64String + "-" + aad.toB64String)

    @inline def subst[G[_], A](fa: G[String]): G[AEADCookie[A]] = fa.asInstanceOf[G[AEADCookie[A]]]

    @inline def unsubst[G[_], A](fa: G[AEADCookie[A]]): G[String] = fa.asInstanceOf[G[String]]

    @inline def apply[A](raw: String): AEADCookie[A] = raw.asInstanceOf[AEADCookie[A]]

    def getEncryptedContent[F[_], A: AES](
        signed: AEADCookie[A]
    )(implicit encryptor: AADEncryptor[F, A, SecretKey]): Either[CipherTextError, CipherText[A]] = {
      val split = signed.split("-")
      if (split.length != 2)
        Left(CipherTextError("String encoded improperly"))
      else {
        split(0).b64Bytes match {
          case Some(e) => CTOPS.ciphertextFromArray[A, GCM, NoPadding](e)
          case None    => Left(CipherTextError("String encoded improperly"))
        }
      }
    }

    implicit def circeDecoder[A]: Decoder[AEADCookie[A]] = new Decoder[AEADCookie[A]] {
      def apply(c: HCursor) = c.as[String].map(AEADCookie.apply[A])
    }

    implicit def circeEncoder[A]: Encoder[AEADCookie[A]] = new Encoder[AEADCookie[A]] {
      def apply(a: AEADCookie[A]): Json = Json.fromString(a)
    }

  }

  type SignedCookie[A] = SignedCookie.Cookie[A]

  implicit object SignedCookie {
    type Cookie[A] <: String

    @inline def from[A](signed: MAC[A], joined: String): SignedCookie[A] =
      apply[A](joined + "-" + signed.toB64String)

    @inline def apply[A](raw: String): SignedCookie[A] = raw.asInstanceOf[SignedCookie[A]]

    @inline def subst[G[_], A](fa: G[String]): G[SignedCookie[A]] = fa.asInstanceOf[G[SignedCookie[A]]]

    @inline def unsubst[G[_], A](fa: G[SignedCookie[A]]): G[String] = fa.asInstanceOf[G[String]]

    def fromDecodedString[F[_]](original: String)(implicit F: MonadError[F, Throwable]): F[String] =
      original.split("-") match {
        case Array(orig, nonce) =>
          orig.b64Bytes match {
            case Some(o) => F.pure(o.toUtf8String)
            case None    => F.raiseError(MacVerificationError("String encoded improperly"))
          }
        case _ =>
          F.raiseError(MacVerificationError("String encoded improperly"))
      }
  }
  implicit final def cookieEQ[A]: Eq[SignedCookie[A]] = SignedCookie.subst(Eq[String])
  implicit final def ecookieEQ[A]: Eq[AEADCookie[A]]  = Eq.by[AEADCookie[A], String](identity[String])
}
