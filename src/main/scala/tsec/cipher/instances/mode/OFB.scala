package tsec.cipher.instances.mode

sealed trait OFB
object OFB extends WithModeTag[OFB]("OFB") with DefaultModeKeySpec[OFB]
