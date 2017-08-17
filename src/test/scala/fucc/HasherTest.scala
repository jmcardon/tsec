package fucc

import java.security.MessageDigest

import tsec.messagedigests.instances._
import tsec.messagedigests.syntax._
import org.apache.commons.codec.binary.Base64

class HasherTest extends TestSpec {
  val str = "hello World"
  val strList = List("a", "a", "bcd")

  "A (base64 encoded) digitalHash and MessageDigest" should "be equal for SHA1" in {
    assert(
      str.digestHash[SHA1].toBase64String ==
        Base64.encodeBase64String(
          MessageDigest
            .getInstance(SHA1.hashTag.algorithm)
            .digest(str.getBytes("UTF-8")))
    )
  }

  it should "be equal for MD5" in {
    assert(
      str.digestHash[MD5].toBase64String ==
        Base64.encodeBase64String(
          MessageDigest
            .getInstance(MD5.hashTag.algorithm)
            .digest(str.getBytes("UTF-8")))
    )
  }

  it should "be equal for SHA256" in {
    assert(
      str.digestHash[SHA256].toBase64String ==
        Base64.encodeBase64String(
          MessageDigest
            .getInstance(SHA256.hashTag.algorithm)
            .digest(str.getBytes("UTF-8")))
    )
  }

  it should "be equal for SHA512" in {
    assert(
      str.digestHash[SHA512].toBase64String ==
        Base64.encodeBase64String(
          MessageDigest
            .getInstance(SHA512.hashTag.algorithm)
            .digest(str.getBytes("UTF-8")))
    )
  }

  "Batch hashing and sequential hashing" should "be the same for SHA1" in {
    val batchList = SHA1.jHasher.hashBatch(strList)
    val seqList = strList.map(_.digestHash[SHA1])

    assert(
      (batchList zip seqList).forall(p => p._1.array.sameElements(p._2.array)))
  }

  it should "be the same for MD5" in {
    val batchList = MD5.jHasher.hashBatch(strList)
    val seqList = strList.map(_.digestHash[MD5])

    assert(
      (batchList zip seqList).forall(p => p._1.array.sameElements(p._2.array)))
  }

  it should "be the same for SHA256" in {
    val batchList = SHA256.jHasher.hashBatch(strList)
    val seqList = strList.map(_.digestHash[SHA256])

    assert(
      (batchList zip seqList).forall(p => p._1.array.sameElements(p._2.array)))
  }

  it should "be the same for SHA512" in {
    val batchList = SHA512.jHasher.hashBatch(strList)
    val seqList = strList.map(_.digestHash[SHA512])

    assert(
      (batchList zip seqList).forall(p => p._1.array.sameElements(p._2.array)))
  }

  "Batch hashing" should "return same size" in {
    val list0 = List.empty[String]
    val list1 = List("a")
    val list2 = List("a", "b")

    assert(
      list0.length == SHA1.jHasher.hashBatch(list0).length &&
        list1.length == SHA1.jHasher.hashBatch(list1).length &&
        list2.length == SHA1.jHasher.hashBatch(list2).length &&
        list2.length == SHA1.jHasher.hashBatch(list2).length
    )
  }

}
