package tsec.cipher.instances.mode

sealed trait CTR
object CTR extends WithModeTag[CTR]("CTR") with DefaultModeKeySpec[CTR]
