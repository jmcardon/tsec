package tsec.keygen.symmetric

import cats.Id

trait SymmetricKeyGen[F[_], Y, K[_]] {

  def generateKey: F[K[Y]]

  def build(rawKey: Array[Byte]): F[K[Y]]

}

trait IdKeyGen[Y, K[_]] extends SymmetricKeyGen[Id, Y, K]
