# IPMI Java Client

The IPMI Java Client is a library that communicates with the IPMI host, fetches Field Replaceable Units (FRUs) and Sensors information then reports these information as a text output.

## How to run the IPMI Client inside Java

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
		final byte[] bmcKey = null;
		final long timeout = 120;

		// Instantiates a new IPMI client configuration using the credentials above
		final IpmiClientConfiguration ipmiClientConfiguration = new IpmiClientConfiguration(
			hostname,
			username,
			password,
			bmcKey,
			noAuth,
			timeout
		);

		// Get the Chassis' status
		final String chassisStatusResult = IpmiClient.getChassisStatusAsStringResult(ipmiClientConfiguration);

		System.out.println("Chassis status:");
		System.out.println(chassisStatusResult);

		// Get FRUs and Sensors
		final String sensorsResult = IpmiClient.getFrusAndSensorsAsStringResult(ipmiClientConfiguration);

		System.out.println("Sensors:");
		System.out.println(sensorsResult);
	}
```

