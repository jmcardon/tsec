object MessageDigestExamples {

  /** Imports */
  import cats.Id
  import cats.effect.{IO, Sync}
  import fs2._
  import tsec.common._
  import tsec.hashing.jca._ //For this example, we will use our byteutil helpers

  /**For direct byte pickling, use: */
  "hiHello".utf8Bytes.hash[SHA1]
  "hiHello".utf8Bytes.hash[SHA256]
  "hiHello".utf8Bytes.hash[SHA512]
  "hiHello".utf8Bytes.hash[MD5]

  /** Alternatively, use the algorithms directly
    * Note: For the JCA, while you _can_ interpret
    * into `IO` if you ever need to work in it, hashing
    * is essentially pure. Thus, interpreting into `Id` is not unsafe
    * in this case
    */
  SHA1.hash[Id]("hiHello".utf8Bytes)
  SHA256.hash[Id]("hiHello".utf8Bytes)
  /** Some Monad with a sync bound: **/
  SHA512.hash[IO]("hiHello".utf8Bytes)


  def hashPipeExample[F[_]: Sync](str: Stream[F, Byte]): Stream[F, Byte] = {
    str.through(SHA512.hashPipe[F])
  }

}
