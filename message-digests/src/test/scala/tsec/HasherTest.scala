package tsec

import java.security.MessageDigest

import tsec.common._
import tsec.messagedigests._
import tsec.messagedigests.imports._
import org.scalatest.MustMatchers
import tsec.messagedigests.core.DigestTag

class HasherTest extends TestSpec with MustMatchers {
  val str              = "hello World"
  val strList          = List("a", "a", "bcd")
  implicit val pickler = defaultStringPickler

  def hashTests[A](implicit tag: DigestTag[A], hasher: JHasher[A]): Unit =
    "A (base64 encoded) digitalHash and MessageDigest" should s"be equal for ${tag.algorithm}" in {
      str
        .pickleAndHash[A]
        .toB64String mustBe MessageDigest.getInstance(tag.algorithm).digest(str.utf8Bytes).toB64String
    }

  hashTests[MD5]
  hashTests[SHA1]
  hashTests[SHA256]
  hashTests[SHA512]
}
