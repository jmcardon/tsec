package tsec.mac.core

trait MessageAuth[F[_], A, MK[_]] {

  def sign(in: Array[Byte], key: MK[A]): F[MAC[A]]

  def verify(in: Array[Byte], hashed: MAC[A], key: MK[A]): F[Boolean]

}
