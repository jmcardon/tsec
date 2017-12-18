package tsec.internal

private[tsec] trait KxConstants {

  val crypto_kx_PUBLICKEYBYTES  = 32
  val crypto_kx_SECRETKEYBYTES  = 32
  val crypto_kx_SEEDBYTES       = 32
  val crypto_kx_SESSIONKEYBYTES = 32
  val crypto_kx_PRIMITIVE       = "x25519blake2b"

}
