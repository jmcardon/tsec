package tsec.cipher.symmetric.core

trait IvGen[F[_], A] { outer =>

  /** useful for not defining unsafe methods twice **/
  private[tsec] def unsafeNat[G[_]](unsafe: Iv[A] => G[Iv[A]]): IvGen[G, A] = new IvGen[G, A] {
    def genIv: G[Iv[A]] = unsafe(outer.genIvUnsafe)

    def genIvUnsafe: Iv[A] = outer.genIvUnsafe
  }

  def genIv: F[Iv[A]]

  def genIvUnsafe: Iv[A]

}
