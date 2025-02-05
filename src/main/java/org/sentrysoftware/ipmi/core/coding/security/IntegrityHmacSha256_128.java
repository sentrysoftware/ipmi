package org.sentrysoftware.ipmi.core.coding.security;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * IPMI Java Client
 * ჻჻჻჻჻჻
 * Copyright 2023 Verax Systems, Sentry Software
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

import java.security.NoSuchAlgorithmException;

/**
 * HMAC-SHA256-128 integrity algorithm.
 */
public class IntegrityHmacSha256_128 extends IntegrityAlgorithm {

	private static final String ALGORITHM_NAME = "HmacSHA256";

	/**
	 * Initiates HMAC-SHA1-96 integrity algorithm.
	 *
	 * @throws NoSuchAlgorithmException when initiation of the algorithm fails
	 */
	public IntegrityHmacSha256_128() throws NoSuchAlgorithmException {
		super();
	}

	@Override
	public byte getCode() {
		return SecurityConstants.IA_HMAC_SHA256_128;
	}

	@Override
	public String getAlgorithmName() {
		return ALGORITHM_NAME;
	}

	@Override
	public int getAuthCodeLength() {
		return 16;
	}

}
