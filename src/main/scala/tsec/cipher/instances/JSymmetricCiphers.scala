package tsec.cipher.instances

import tsec.cipher.core._
import cats.instances.either._
import tsec.symmetric.instances.JEncryptionKey

class JSymmetricCiphers[A: CipherAlgo, M: CMode: ModeKeySpec, P: Padding](val algebra: JSymmetricCipherInterpreter[A, M, P])
    extends CipherPrograms[Either[CipherError, ?], A, M, P, JEncryptionKey](algebra)

object JSymmetricCiphers {
  def getCipher[A: CipherAlgo, M: CMode: ModeKeySpec, P: Padding] =
    new JSymmetricCiphers[A, M, P](new JSymmetricCipherInterpreter[A, M, P])
}
