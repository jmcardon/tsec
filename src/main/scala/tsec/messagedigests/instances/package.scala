package tsec.messagedigests

import java.nio.charset.Charset
import java.security.MessageDigest

import tsec.messagedigests.core._
import com.softwaremill.tagging._
import tsec.core.CryptoTag
import org.apache.commons.codec.binary.{Base64 => ApacheB}
import shapeless._
import tsec.core.ByteUtils.ByteAux

package object instances {

  type JPureHasher[T] = PureHasher[MessageDigest, T]

  implicit val defaultStringEncoder: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8](Charset.forName("UTF-8").taggedWith[UTF8])

  implicit class HasherOps[T](val hasher: JHasher[T]) extends AnyVal {
    def hashStringToBase64(s: String)(implicit gen: ByteAux[T]): String =
      ApacheB.encodeBase64String(gen.to(hasher.hash[String](s)(defaultStringEncoder)).head)
  }

  implicit class HashedOps[T](val hashed: T) extends AnyVal {
    def toBase64String(implicit p: PureHasher[MessageDigest, T],gen: ByteAux[T]): String =
      ApacheB.encodeBase64String(gen.to(hashed).head)
  }

  def pureJavaHasher[T](implicit gen: ByteAux[T]) =
    new PureHasher[MessageDigest, T] {

      def tagged(implicit hashTag: CryptoTag[T]): TaggedHasher[MessageDigest, T] =
        Hasher(MessageDigest.getInstance(hashTag.algorithm)).taggedWith[T]

      def hashToBytes(toHash: Array[Byte])(implicit hashTag: CryptoTag[T]): Array[Byte] =
        tagged.hasher.digest(toHash)

      def hash(toHash: Array[Byte])(implicit hashTag: CryptoTag[T]): T = gen.from(hashToBytes(toHash)::HNil)
    }

}
