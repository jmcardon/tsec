package tsec.cipher.instances.mode

sealed trait CTR
object CTR extends DefaultModeKeySpec[CTR]("CTR")