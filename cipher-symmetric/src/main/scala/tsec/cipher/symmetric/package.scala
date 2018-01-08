package tsec.cipher

import tsec.common._
import tsec.cipher.common._
import tsec.cipher.symmetric.imports.{IvProcess, SecretKey}

package object symmetric extends CipherErrors {

  //Todo: Un-case class
  final case class PlainText(content: Array[Byte]) extends AnyVal

  final case class CipherText[A, M, P](content: Array[Byte], iv: Array[Byte]) {
    def toSingleArray: Array[Byte] = content ++ iv
  }

  object CipherText {
    def fromArray[A2, M2, P2, K[_]](
        bytes: Array[Byte]
    )(implicit spec: IvProcess[A2, M2, P2, K]): Either[CipherTextError, CipherText[A2, M2, P2]] =
      if (bytes.length < spec.ivLengthBytes + 1)
        Left(CipherTextError("Array must be nonEmpty"))
      else {
        val ivIx         = bytes.length - spec.ivLengthBytes
        val ivArray      = new Array[Byte](spec.ivLengthBytes)
        val contentArray = new Array[Byte](ivIx)
        System.arraycopy(bytes, 0, contentArray, 0, ivIx)
        System.arraycopy(bytes, ivIx, ivArray, 0, spec.ivLengthBytes)

        Right(CipherText[A2, M2, P2](contentArray, ivArray))
      }
  }

  //Todo: Un-case class
  final case class AAD(aad: Array[Byte]) extends AnyVal

  object AAD {
    def buildFromStringUTF8(string: String) = AAD(string.utf8Bytes)
  }

}
