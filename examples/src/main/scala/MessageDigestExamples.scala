object MessageDigestExamples {

  /*
    Imports
   */
  import tsec.common._
  import tsec.messagedigests._
  import tsec.messagedigests.imports._ //For this example, we will use our byteutil helpers

  /*
    To hash any class, like String, you must supply an implicit `CryptoPickler[A].
    As an example, you can use, for strings, the default string pickler, which serializes the string to
    utf-8 bytes

    A crypto pickler is simply a value class with a function T => Array[Bytes]. i.e:
    CryptoPickler[String](_.getBytes("UTF-8"))

    Alternatively, java standard charsets are covered with:
   */
  implicit val pickler: CryptoPickler[String] = CryptoPickler.stringPickle[UTF8]
  /*
    or: use the defaultPickler, which uses UTF-8
   */

  "hi".pickleAndHash[SHA256]

  /*
    For direct byte pickling, use:
   */
  "hiHello".utf8Bytes.hash[SHA1]
  "hiHello".utf8Bytes.hash[SHA256]
  "hiHello".utf8Bytes.hash[SHA512]
  "hiHello".utf8Bytes.hash[MD5]

}
