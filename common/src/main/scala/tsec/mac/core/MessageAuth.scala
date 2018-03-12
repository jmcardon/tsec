package tsec.mac.core

trait MessageAuth[F[_], A, K[_]] {

  def sign(in: Array[Byte], key: K[A]): F[MAC[A]]

  def verify(in: Array[Byte], hashed: MAC[A], key: K[A]): F[Boolean]

}
