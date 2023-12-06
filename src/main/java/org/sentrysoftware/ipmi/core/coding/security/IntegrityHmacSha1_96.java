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

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC-SHA1-96 integrity algorithm.
 */
public class IntegrityHmacSha1_96 extends IntegrityAlgorithm {

    public static final String ALGORITHM_NAME = "HmacSHA1";
    private Mac mac;

    private static final byte[] CONST1 = new byte[] { 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

    /**
     * Initiates HMAC-SHA1-96 integrity algorithm.
     *
     * @throws NoSuchAlgorithmException
     *             - when initiation of the algorithm fails
     */
    public IntegrityHmacSha1_96() throws NoSuchAlgorithmException {
        mac = Mac.getInstance(ALGORITHM_NAME);
    }

    @Override
    public void initialize(byte[] sik) throws InvalidKeyException {
        super.initialize(sik);

        SecretKeySpec k1 = new SecretKeySpec(sik, ALGORITHM_NAME);

        mac.init(k1);

        k1 = new SecretKeySpec(mac.doFinal(CONST1), ALGORITHM_NAME);

        mac.init(k1);
    }

    @Override
    public byte getCode() {
        return SecurityConstants.IA_HMAC_SHA1_96;
    }

    @Override
    public byte[] generateAuthCode(final byte[] base) {
        if (sik == null) {
            throw new NullPointerException("Algorithm not initialized.");
        }

        byte[] result = new byte[12];
        byte[] updatedBase;

        if(base[base.length - 2] == 0 /*there are no integrity pad bytes*/) {
            updatedBase = injectIntegrityPad(base,12);
        } else {
            updatedBase = base;
        }

        System.arraycopy(mac.doFinal(updatedBase), 0, result, 0, 12);

        return result;
    }

}
