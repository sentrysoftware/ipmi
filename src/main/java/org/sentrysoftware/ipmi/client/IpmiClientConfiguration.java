package org.sentrysoftware.ipmi.client;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * IPMI Java Client
 * ჻჻჻჻჻჻
 * Copyright 2023 Sentry Software
 * ჻჻჻჻჻჻
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * ╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱
 */

/**
 * IPMI configuration including the required credentials that need to be used to establish the
 * communication with the IPMI interface
 *
 */
public class IpmiClientConfiguration {

	private String hostname;
	private String username;
	private char[] password;
	private byte[] bmcKey;
	private boolean skipAuth;
	private long timeout;

	/**
	 * Instantiates a new {@link IpmiClientConfiguration} in order to query the IPMI host.
	 * 
	 * @param hostname IP Address or host name of the remote IPMI host.
	 * @param username Name used to establish the connection with the host via the IPMI protocol.
	 * @param password Password used to establish the connection with the host via the IPMI protocol.
	 * @param bmcKey   The key that should be provided if the two-key authentication is enabled, null otherwise.
	 * @param skipAuth Whether the client should skip authentication
	 * @param timeout  Timeout used for each IPMI request.
	 */
	public IpmiClientConfiguration(String hostname, String username, char[] password,
			byte[] bmcKey, boolean skipAuth, long timeout) {
		this.hostname = hostname;
		this.username = username;
		this.password = password;
		this.bmcKey = bmcKey;
		this.skipAuth = skipAuth;
		this.timeout = timeout;
	}

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = hostname;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public char[] getPassword() {
		return password;
	}

	public void setPassword(char[] password) {
		this.password = password;
	}

	public byte[] getBmcKey() {
		return bmcKey;
	}

	public void setBmcKey(byte[] bmcKey) {
		this.bmcKey = bmcKey;
	}

	public boolean isSkipAuth() {
		return skipAuth;
	}

	public void setSkipAuth(boolean skipAuth) {
		this.skipAuth = skipAuth;
	}

	public long getTimeout() {
		return timeout;
	}

	public void setTimeout(long timeout) {
		this.timeout = timeout;
	}

}
