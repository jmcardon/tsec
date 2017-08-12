package tsec.asymmetric.cipher

import java.security.{PrivateKey, PublicKey}

import com.softwaremill.tagging.@@
import tsec.cipher.core.{CipherText, PlainText}

trait CipherAlgebra[F[_], A, M, P] {
  type C

  def genInstance: () => C

  def encrypt(clearText: PlainText[A,M, P], key: PrivateKey @@ A, encyptor: C): F[CipherText[A,M,P]]

  def decrypt(cipherText: CipherText[A,M, P], key: PublicKey @@ A, encyptor: C): F[PlainText[A,M,P]]

}
