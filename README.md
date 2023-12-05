# IPMI Java Client
![GitHub release (with filter)](https://img.shields.io/github/v/release/sentrysoftware/oss-maven-template)
![Build](https://img.shields.io/github/actions/workflow/status/sentrysoftware/oss-maven-template/deploy.yml)
![GitHub top language](https://img.shields.io/github/languages/top/sentrysoftware/oss-maven-template)
![License](https://img.shields.io/github/license/sentrysoftware/oss-maven-template)

The IPMI Java Client is a library that communicates with the IPMI host, fetches FRUs and Sensors information then reports these information in a text output.

## Build instructions

This is a simple Maven project. Build with:

```bash
mvn verify
```

## Release instructions

The artifact is deployed to Sonatype's [Maven Central](https://central.sonatype.com/).

The actual repository URL is https://s01.oss.sonatype.org/, with server Id `ossrh` and requires credentials to deploy
artifacts manually.

But it is strongly recommended to only use [GitHub Actions "Release to Maven Central"](actions/workflows/release.yml) to perform a release:

* Manually trigger the "Release" workflow
* Specify the version being released and the next version number (SNAPSHOT)
* Release the corresponding staging repository on [Sonatype's Nexus server](https://s01.oss.sonatype.org/)
* Merge the PR that has been created to prepare the next version

## License

License is GNU General Lesser Public License (LGPL) version 3.0. Each source file includes the LGPL-3 header (build will fail otherwise).
To update source files with the proper header, simply execute the below command:

```bash
mvn license:update-file-header
```

## Run IPMI Client inside Java

Add IPMI in the list of dependencies in your [Maven **pom.xml**](https://maven.apache.org/pom.html):

```xml
<dependencies>
	<!-- [...] -->
	<dependency>
		<groupId>org.sentrysoftware</groupId>
		<artifactId>ipmi</artifactId>
		<version>1.0.00-SNAPSHOT</version> <!-- Use the latest version released -->
	</dependency>
</dependencies>
```

Invoke the IPMI Client:

```java

	public static void main(String[] args) throws InterruptedException, ExecutionException, TimeoutException {

		final String hostname = "my-host";
		final String username = "my-username";
		final char[] password = new char[] { 'p', 'a', 's', 's' };
		final boolean noAuth = false;
		final long timeout = 120;

		// Instantiates a new IPMI client configuration using the credentials above
		final IpmiClientConfiguration ipmiConfiguration = new IpmiClientConfiguration(
			hostname,
			username,
			password,
			null,
			noAuth,
			timeout
		);

		// Get the Chassis' status
		final String chassisStatusResult = IpmiClient.getChassisStatusAsStringResult(ipmiConfiguration);

		System.out.println("Chassis status: ");
		System.out.println(chassisStatusResult);

		// Get FRUs and Sensors
		final String sensorsResult = IpmiClient.getFrusAndSensorsAsStringResult(ipmiConfiguration);

		System.out.println("Sensors: ");
		System.out.println(sensorsResult);
	}
```

