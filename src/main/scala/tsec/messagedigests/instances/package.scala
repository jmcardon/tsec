package tsec.messagedigests

import java.nio.charset.Charset
import java.util.Base64

import shapeless._
import tsec.messagedigests.core._
import tsec.core.ByteUtils.ByteAux

package object instances {

  implicit val defaultStringEncoder: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8](tag[UTF8](Charset.forName("UTF-8")))

  implicit class HasherOps[T](val hasher: JHasher[T]) extends AnyVal {
    def hashStringToBase64(s: String)(implicit gen: ByteAux[T]): String =
      Base64.getEncoder.encodeToString(gen.to(hasher.hash[String](s)(defaultStringEncoder)).head)
  }

  implicit class HashedOps[T](hashed: T)(implicit gen: ByteAux[T]) {
    def toBase64String(implicit p: JHasher[T]): String =
      Base64.getEncoder.encodeToString(gen.to(hashed).head)
  }

}
