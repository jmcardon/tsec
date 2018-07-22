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
        (for {
          o <- original.b64Bytes
          s <- signed.b64Bytes
        } yield (o, s)).map {
          case (o2, s2) =>
            signer.verifyBool(o2, MAC[A](s2), key)
        } match {
          case Some(r) => r
          case None    => F.pure(false)
        }

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
      (for {
        o <- split(0).b64Bytes
        s <- split(1).b64Bytes
      } yield (o, s)).map {
        case (original, decoded) =>
          signer.verifyBool(original, MAC[A](decoded), key).flatMap[String] {
            case true  => SignedCookie.fromDecodedString(original.toUtf8String)
            case false => F.raiseError(MacVerificationError("Invalid cookie"))
          }
      } match { //Micro opti. could be .fold
        case Some(a) => a
        case None    => F.raiseError(MacVerificationError("Invalid cookie"))
      }
    }
  }

}
