package tsec.cookies

import tsec.common._
import tsec.mac.imports._

object CookieSigner {

  def sign[A: MacTag: ByteEV](message: String, nonce: String, key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): Either[Throwable, SignedCookie[A]] = {
    if(message.isEmpty)
      Left(MacSigningError("Cannot sign an empty string"))
    else {
      val toSign = message + "-" + nonce
      signer.sign(toSign.utf8Bytes, key).map(SignedCookie.from[A](_, toSign))
    }
  }

  def verify[A: MacTag: ByteEV](signed: SignedCookie[A], key: MacSigningKey[A])(
      implicit signer: JCAMacImpure[A]
  ): MacErrorM[Boolean] = {
    val split = signed.split("-")
    if (split.length != 3)
      Left(MacVerificationError("Invalid cookie"))
    else {
      val signed   = split(2).base64Bytes.toRepr[A]
      val original = split(0) + "-" + split(1)
      signer.verify(original.utf8Bytes, signed, key)
    }

  }

}
