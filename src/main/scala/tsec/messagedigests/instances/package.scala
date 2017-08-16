package tsec.messagedigests

import java.nio.charset.Charset
import java.security.MessageDigest

import tsec.messagedigests.core._
import com.softwaremill.tagging._
import tsec.core.CryptoTag
import org.apache.commons.codec.binary.{Base64 => ApacheB}

package object instances {

  type JPureHasher[T] = PureHasher[MessageDigest, T]

  implicit val defaultStringEncoder: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8](Charset.forName("UTF-8").taggedWith[UTF8])

  implicit class HasherOps[T](val hasher: JHasher[T]) extends AnyVal {
    def hashStringToBase64(s: String): String =
      ApacheB.encodeBase64String(hasher.p.bytes(hasher.hash[String](s)(defaultStringEncoder)))
  }

  implicit class HashedOps[T](val hashed: T) extends AnyVal {
    def toBase64String(implicit p: PureHasher[MessageDigest, T]): String =
      ApacheB.encodeBase64String(p.bytes(hashed))
  }

  def pureJavaHasher[T](extract: T => Array[Byte], build: Array[Byte] => T) =
    new PureHasher[MessageDigest, T] {

      def tagged(implicit hashTag: CryptoTag[T]): TaggedHasher[MessageDigest, T] =
        Hasher(MessageDigest.getInstance(hashTag.algorithm)).taggedWith[T]

      def bytes(data: T): Array[Byte] = extract(data)

      def fromHashedBytes(array: Array[Byte]): T = build(array)

      def hashToBytes(toHash: Array[Byte])(implicit hashTag: CryptoTag[T]): Array[Byte] =
        tagged.hasher.digest(toHash)
    }

}
