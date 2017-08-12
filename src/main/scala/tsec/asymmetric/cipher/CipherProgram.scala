package tsec.asymmetric.cipher

import java.security.{PrivateKey, PublicKey}

import cats.Monad
import com.softwaremill.tagging.@@
import tsec.cipher.core.{CipherText, PlainText}

abstract class CipherProgram[F[_]: Monad, A, M, P](algebra: CipherAlgebra[F, A, M, P]) {

  def encrypt(clearText: PlainText[A,M,P], key: PrivateKey @@ A): F[CipherText[A, M, P]] = {
    algebra.encrypt(clearText, key, algebra.genInstance())
  }

  def decrypt(cipherText: CipherText[A, M, P], key: PublicKey @@ A): F[PlainText[A, M, P]] = {
    algebra.decrypt(cipherText, key, algebra.genInstance())
  }
}
