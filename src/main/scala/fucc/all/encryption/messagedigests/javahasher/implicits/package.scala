package fucc.all.encryption.messagedigests.javahasher

import java.nio.charset.Charset
import java.security.MessageDigest

import fucc.all.encryption.messagedigests.core._
import com.softwaremill.tagging._
import org.apache.commons.codec.binary.{Base64 => ApacheB}

package object implicits {
  implicit val defaultStringEncoder: CryptoPickler[String] = CryptoPickler.stringPickle[UTF8](Charset.forName("UTF-8").taggedWith[UTF8])

  implicit class HasherOps[T](
    val hasher: JHasher[T])
    extends AnyVal {
    def hashStringToBase64(s: String): String =
      ApacheB.encodeBase64String(hasher.p.bytes(hasher.hash[String](s)(defaultStringEncoder)))
  }

  implicit class HashedOps[T](val hashed: T) extends AnyVal{
    def toBase64String(implicit p: PureHasher[MessageDigest, T]): String = ApacheB.encodeBase64String(p.bytes(hashed))
  }

  def pureJavaHasher[T](extract: T => Array[Byte], build: Array[Byte] => T) = new PureHasher[MessageDigest, T] {
    def tagged(implicit hashTag: HashTag[T]): TaggedHasher[MessageDigest, T] = Hasher(MessageDigest.getInstance(hashTag.algorithm)).taggedWith[T]

    def bytes(data: T): Array[Byte] = extract(data)

    def fromHashedBytes(array: Array[Byte]): T = build(array)

    def hashToBytes(toHash: Array[Byte])(implicit hashTag: HashTag[T]): Array[Byte] = tagged.hasher.digest(toHash)
  }

  implicit lazy val MD5Hasher: PureHasher[MessageDigest, MD5] = pureJavaHasher[MD5](_.array, MD5.apply)
  implicit lazy val SHA1Hasher: PureHasher[MessageDigest, SHA1] = pureJavaHasher[SHA1](_.array, SHA1.apply)
  implicit lazy val SHA256Hasher: PureHasher[MessageDigest, SHA256] = pureJavaHasher[SHA256](_.array, SHA256.apply)
  implicit lazy val SHA512Hasher: PureHasher[MessageDigest, SHA512] = pureJavaHasher[SHA512](_.array, SHA512.apply)

}
