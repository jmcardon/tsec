package tsec

import tsec.messagedigests.core.CryptoPickler
import tsec.messagedigests.imports.JHasher

package object messagedigests {
  class DigestOps[T](val c: T) extends AnyVal {
    def digestHash[K](implicit jHasher: JHasher[K], pickler: CryptoPickler[T]): K = jHasher.hash(c)
  }

  implicit def digestOps[T: CryptoPickler](c: T): DigestOps[T] = new DigestOps[T](c)

}
