package tsec.cookies

import tsec.common._
import tsec.mac.core.{MAC, JCAMacTag}
import tsec.mac.imports._

object CookieSigner {

  def sign[A: JCAMacTag](message: String, nonce: String, key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): Either[Throwable, SignedCookie[A]] =
    if (message.isEmpty)
      Left(MacSigningError("Cannot sign an empty string"))
    else {
      val toSign = (message.utf8Bytes.toB64String + "-" + nonce.utf8Bytes.toB64String).utf8Bytes
      signer.sign(toSign, key).map(SignedCookie.from[A](_, toSign.toB64String))
    }

  def verify[A: JCAMacTag](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): MacErrorM[Boolean] =
    signed.split("-") match {
      case Array(original, signed) =>
        signer.verify(original.base64Bytes, MAC[A](signed.base64Bytes), key)
      case _ =>
        Left(MacVerificationError("Invalid cookie"))
    }

  def verifyAndRetrieve[A: JCAMacTag](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): Either[Throwable, String] = {
    val split = signed.split("-")
    if (split.length != 2)
      Left(MacVerificationError("Invalid cookie"))
    else {
      val original = split(0).base64Bytes
      val signed   = split(1).base64Bytes
      signer.verify(original, MAC[A](signed), key).flatMap {
        case true  => SignedCookie.fromDecodedString(original.toUtf8String)
        case false => Left(MacVerificationError("Invalid cookie"))
      }
    }
  }

}
