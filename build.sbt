name := """cognito_rnd_scala"""
organization := "com.knoldus"

version := "1.0-SNAPSHOT"

lazy val root = (project in file(".")).enablePlugins(PlayScala)

scalaVersion := "2.12.3"

libraryDependencies += guice
libraryDependencies += ws
libraryDependencies += "org.scalatestplus.play" %% "scalatestplus-play" % "3.1.2" % Test
libraryDependencies += "com.amazonaws" % "aws-java-sdk" % "1.11.257"
libraryDependencies += "com.typesafe.play" %% "play-json" % "2.6.0"
// Adds additional packages into Twirl
//TwirlKeys.templateImports += "com.knoldus.controllers._"

// Adds additional packages into conf/routes
// play.sbt.routes.RoutesKeys.routesImport += "com.knoldus.binders._"
