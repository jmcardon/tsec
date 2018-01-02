logLevel := Level.Warn
addSbtPlugin("com.lucidchart" % "sbt-scalafmt" % "1.15")
addSbtPlugin("org.foundweekends" % "sbt-bintray" % "0.5.1")
addSbtPlugin("com.47deg"  % "sbt-microsites" % "0.7.4")
addSbtPlugin("org.tpolecat" % "tut-plugin" % "0.6.2")
addSbtPlugin("com.typesafe.sbt" % "sbt-ghpages" % "0.6.2")
addSbtPlugin("pl.project13.scala" % "sbt-jmh" % "0.3.2")
addSbtPlugin("com.timushev.sbt" % "sbt-updates" % "0.3.3")

libraryDependencies ++= List(
  //"org.scalameta" %% "scalameta" % "2.1.2",
  "com.geirsson" %% "scalafmt-core" % "1.3.0",
  "com.geirsson" %% "scalafmt-cli" % "1.3.0",
)

unmanagedJars in Compile ++= {
  val log = streams.value.log
  sys.env.get("JAVA_HOME").map(jh => new File(s"$jh/lib/tools.jar")) match {
    case Some(tools) => Seq(Attributed.blank(tools))
    case None        =>
      log.info(
        """Could not find tools.jar!
          |  This is surprising, as it is included with the JDK. Maybe look into that.
          |  If everything else works, comment out gensodium (don't check that in, though!)
        """.stripMargin
      )
      Nil
  }
}


sources in Compile ++= {
  /* Sad hack for intellij, which doesn't recognize the unmanagedSources key:
   * only compile the gensodium script if we're not inside IntelliJ.
   * We dynamically load it from the `gensodium` task, so as long as we compile
   * it from inside sbt, we'll be fine.
   */
  if (!sys.env.getOrElse("XPC_SERVICE_NAME", "").toLowerCase.contains("intellij"))
    file("project/boiler/gensodium.scala").getAbsoluteFile :: Nil
  else Nil
}