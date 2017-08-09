package tsec.cipher.instances.mode

sealed trait OFBx
object OFBx extends WithModeTag[OFBx]("OFBx") with DefaultModeKeySpec[OFBx]
