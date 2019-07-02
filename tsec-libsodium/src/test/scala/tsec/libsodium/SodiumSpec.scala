package tsec.libsodium

import tsec.TestSpec

trait SodiumSpec extends TestSpec {
  implicit val sodium: ScalaSodium = ScalaSodium.getSodiumUnsafe
}
