package tsec.cipher.symmetric

trait IvGen[F[_], A] {

  def genIv: F[Iv[A]]

  def genIvUnsafe: Iv[A]

}
