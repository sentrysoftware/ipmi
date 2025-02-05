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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


/**
 * RAKP-HMAC-MD5 authentication algorithm.
 */
public class AuthenticationRakpHmacMd5 extends AuthenticationAlgorithm {

    private static final String ALGORITHM_NAME = "HmacMD5";

    private Mac mac;

    /**
     * Initiates RAKP-HMAC-MD5 authentication algorithm.
     *
     * @throws NoSuchAlgorithmException - when initiation of the algorithm fails
     */
    public AuthenticationRakpHmacMd5() throws NoSuchAlgorithmException {
        mac = Mac.getInstance(ALGORITHM_NAME);
    }

    @Override
    public byte getCode() {
        return SecurityConstants.AA_RAKP_HMAC_MD5;
    }

    @Override
    public boolean checkKeyExchangeAuthenticationCode(byte[] data, byte[] key, String password)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] check = getKeyExchangeAuthenticationCode(data, password);
        return Arrays.equals(check, key);
    }

    @Override
    public byte[] getKeyExchangeAuthenticationCode(byte[] data, String password)
            throws NoSuchAlgorithmException, InvalidKeyException {

        byte[] key = password.getBytes();

        SecretKeySpec sKey = new SecretKeySpec(key, ALGORITHM_NAME);
        mac.init(sKey);

        return mac.doFinal(data);
    }

    @Override
    public boolean doIntegrityCheck(byte[] data, byte[] reference, byte[] sik)
            throws InvalidKeyException, NoSuchAlgorithmException {

        SecretKeySpec sKey = new SecretKeySpec(sik, ALGORITHM_NAME);
        mac.init(sKey);

        byte[] result = new byte[getIntegrityCheckBaseLength()];

        System.arraycopy(mac.doFinal(data), 0, result, 0, getIntegrityCheckBaseLength());

        return Arrays.equals(result, reference);
    }

    @Override
    public int getKeyLength() {
        return 16;
    }

    @Override
    public int getIntegrityCheckBaseLength() {
        return 12;
    }

    @Override
	public String getAlgorithmName() {
		return ALGORITHM_NAME;
	}

}
