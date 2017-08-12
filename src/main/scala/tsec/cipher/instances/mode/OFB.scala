package tsec.cipher.instances.mode

sealed trait OFB
object OFB extends DefaultModeKeySpec[OFB]("OFB")
