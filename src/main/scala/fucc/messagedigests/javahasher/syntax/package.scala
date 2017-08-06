package fucc.messagedigests.javahasher

import fucc.messagedigests.core.CryptoPickler

package object syntax {

  class DigestOps[T](val c: T) extends AnyVal {
    def digestHash[K](implicit jHasher: JHasher[K], pickler: CryptoPickler[T]): K = jHasher.hash(c)
  }

  implicit def digestOps[T : CryptoPickler](c: T): DigestOps[T] = new DigestOps[T](c)

}
