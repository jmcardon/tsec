object MessageDigestExamples {

  /** Imports */
  import tsec.common._
  import tsec.hashing.imports._ //For this example, we will use our byteutil helpers

  /**For direct byte pickling, use: */
  "hiHello".utf8Bytes.hash[SHA1]
  "hiHello".utf8Bytes.hash[SHA256]
  "hiHello".utf8Bytes.hash[SHA512]
  "hiHello".utf8Bytes.hash[MD5]

}
