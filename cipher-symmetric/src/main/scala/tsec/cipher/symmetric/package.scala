package tsec.cipher

import tsec.common._
import tsec.cipher.common._

package object symmetric extends CipherErrors {

  //Todo: Un-case class
  final case class PlainText(content: Array[Byte]) extends AnyVal

  final case class CipherText[A, M, P](content: Array[Byte], iv: Array[Byte]) {
    def toSingleArray: Array[Byte] = content ++ iv
  }

  //Todo: Un-case class
  final case class AAD(aad: Array[Byte]) extends AnyVal

  object AAD {
    def buildFromStringUTF8(string: String) = AAD(string.utf8Bytes)
  }

}
