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

  def hashTests[A](implicit tag: DigestTag[A], hasher: JHasher[A], aux: ByteEV[A]): Unit = {

    "A (base64 encoded) digitalHash and MessageDigest" should s"be equal for ${tag.algorithm}" in {
      aux
        .toArray(str.pickleAndHash[A])
        .toB64String mustBe MessageDigest.getInstance(tag.algorithm).digest(str.utf8Bytes).toB64String
    }

    "Batch hashing and sequential hashing" should s"be the same for ${tag.algorithm}" in {
      val batchList = hasher.hashBatch(strList).map(h => aux.toArray(h).toB64String)
      val seqList   = strList.map(b => aux.toArray(b.pickleAndHash[A]).toB64String)
      batchList must contain theSameElementsInOrderAs seqList
    }

    "Batch hashing" should s"return same size for ${tag.algorithm}" in {
      val list0 = List.empty[String]
      val list1 = List("a")
      val list2 = List("a", "b")

      list0.length mustBe hasher.hashBatch(list0).length
      list1.length mustBe hasher.hashBatch(list1).length
      list2.length mustBe hasher.hashBatch(list2).length
    }
  }

  hashTests[MD5]
  hashTests[SHA1]
  hashTests[SHA256]
  hashTests[SHA512]
}
