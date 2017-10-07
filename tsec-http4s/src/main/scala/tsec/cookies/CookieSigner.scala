package tsec.cookies

import tsec.common._
import tsec.mac.imports._
import cats.syntax.either._

object CookieSigner {

  def sign[A: MacTag: ByteEV](message: String, nonce: String, key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): Either[Throwable, SignedCookie[A]] =
    if (message.isEmpty)
      Left(MacSigningError("Cannot sign an empty string"))
    else {
      val toSign = (message.utf8Bytes.toB64String + "-" + nonce).utf8Bytes
      signer.sign(toSign, key).map(SignedCookie.from[A](_, toSign.toB64String))
    }

  def verify[A: MacTag: ByteEV](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): MacErrorM[Boolean] = {
    val split = signed.split("-")
    if (split.length != 2)
      Left(MacVerificationError("Invalid cookie"))
    else {
      val original = split(0).base64Bytes
      val signed   = split(1).base64Bytes.toRepr[A]
      signer.verify(original, signed, key)
    }
  }

  def verifyAndRetrieve[A: MacTag: ByteEV](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): Either[Throwable, String] = {
    val split = signed.split("-")
    if (split.length != 2)
      Left(MacVerificationError("Invalid cookie"))
    else {
      val original = split(0).base64Bytes
      val signed   = split(1).base64Bytes.toRepr[A]
      signer.verify(original, signed, key).flatMap {
        case true  => SignedCookie.splitOriginal(original.toUtf8String)
        case false => Left(MacVerificationError("Invalid cookie"))
      }
    }
  }

}
