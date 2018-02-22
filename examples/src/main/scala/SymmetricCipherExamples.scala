object SymmetricCipherExamples {

  /** IMPORTANT NOTE: DO NOT SKIP
    * For 256-bit key sizes, you will have to install the
    * Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
    *
    * You can get it at: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
    *
    * You can refer to:
    * https://stackoverflow.com/questions/41580489/how-to-install-unlimited-strength-jurisdiction-policy-files
    *
    * Alternatively, if you are using a package manager like aptitude and have the java8 repositories on your machine,
    * you can install oracle-java8-unlimited-jce-policy
    *
    * For debian-like distros:
    * Follow the instructions here: http://tipsonubuntu.com/2016/07/31/install-oracle-java-8-9-ubuntu-16-04-linux-mint-18
    * then use:sudo apt-get install oracle-java8-unlimited-jce-policy
    */
  /** These are the imports you will need for basic usage */
  import tsec.common._
  import tsec.cipher.symmetric.core._
  import tsec.cipher.symmetric.imports._
  import cats.effect.IO

  //Feel free to choose any of the default Cipher constructions.
  //For non-authenticated ciphers, we recommend AES-CTR

  val toEncrypt = "hi hello welcome to tsec".utf8Bytes

  implicit val ctrStrategy: IvGen[AES128CTR] = AES128CTR.defaultIvStrategy

  val onlyEncrypt: IO[String] = AES128CTR
    .genEncryptor[IO]
    .flatMap(
      implicit instance =>
        for {
          key       <- AES128CTR.generateKey[IO] //Generate our key
          encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
          decrypted <- AES128CTR.decrypt[IO](encrypted, key)
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"

  /** You can also turn it into a singular array with the IV concatenated at the end */
  val onlyEncrypt2: IO[String] = AES128CTR
    .genEncryptor[IO]
    .flatMap(
      implicit instance =>
        for {
          key       <- AES128CTR.generateKey[IO]                        //Generate our key
          encrypted <- AES128CTR.encrypt[IO](PlainText(toEncrypt), key) //Encrypt our message
          array = encrypted.toConcatenated
          from      <- IO.fromEither(AES128CTR.ciphertextFromConcat(array))
          decrypted <- AES128CTR.decrypt[IO](from, key)
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"

  /** An authenticated encryption and decryption */
  implicit val gcmstrategy = AES128GCM.defaultIvStrategy

  val aad = AAD("myAdditionalAuthenticationData".utf8Bytes)
  val encryptAAD: IO[String] = AES128GCM
    .genEncryptor[IO]
    .flatMap(
      implicit instance =>
        for {
          key       <- AES128GCM.generateKey[IO]                                    //Generate our key
          encrypted <- AES128GCM.encryptWithAAD[IO](PlainText(toEncrypt), key, aad) //Encrypt
          decrypted <- AES128GCM.decryptWithAAD[IO](encrypted, key, aad)            //Decrypt
        } yield decrypted.toUtf8String
    ) // "hi hello welcome to tsec!"

  /** For more advanced usage, i.e you know which cipher you want specifically, you must import padding
    * as well as the low level package
    *
    * this is not recommended, but useful for.. science!
    *
    */
  import tsec.cipher.common.padding._
  import tsec.cipher.symmetric.imports.primitive._
  val desStrategy = JCAIvGen.random[DES]

  val advancedUsage: IO[String] = for {
    instance  <- JCAPrimitiveCipher[IO, DES, CBC, PKCS7Padding]()
    key       <- DES.generateKey[IO]
    iv        <- desStrategy.genIv[IO]
    encrypted <- instance.encrypt(PlainText(toEncrypt), key, iv) //Encrypt our message, with our auth data
    decrypted <- instance.decrypt(encrypted, key) //Decrypt our message: We need to pass it the same AAD
  } yield decrypted.toUtf8String

}
