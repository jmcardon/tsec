package tsec.cookies

import cats.MonadError
import tsec.common._
import tsec.mac.{MessageAuth, _}
import tsec.mac.jca._
import cats.syntax.all._

object CookieSigner {

  def sign[F[_], A](message: String, nonce: String, key: MacSigningKey[A])(
      implicit signer: MessageAuth[F, A, MacSigningKey],
      F: MonadError[F, Throwable]
  ): F[SignedCookie[A]] =
    if (message.isEmpty)
      F.raiseError(MacSigningError("Cannot sign an empty string"))
    else {
      val toSign = (message.utf8Bytes.toB64String + "-" + nonce.utf8Bytes.toB64String).utf8Bytes
      signer.sign(toSign, key).map(SignedCookie.from[A](_, toSign.toB64String))
    }

  def verify[F[_], A](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: MessageAuth[F, A, MacSigningKey],
      F: MonadError[F, Throwable]
  ): F[Boolean] =
    signed.split("-") match {
      case Array(original, signed) =>
        signer.verifyBool(original.base64Bytes, MAC[A](signed.base64Bytes), key)
      case _ =>
        F.raiseError(MacVerificationError("Invalid cookie"))
    }

  def verifyAndRetrieve[F[_], A](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: MessageAuth[F, A, MacSigningKey],
      F: MonadError[F, Throwable]
  ): F[String] = {
    val split = signed.split("-")
    if (split.length != 2)
      F.raiseError(MacVerificationError("Invalid cookie"))
    else {
      val original = split(0).base64Bytes
      val signed   = split(1).base64Bytes
      signer.verifyBool(original, MAC[A](signed), key).flatMap {
        case true  => SignedCookie.fromDecodedString(original.toUtf8String)
        case false => F.raiseError(MacVerificationError("Invalid cookie"))
      }
    }
  }

}
