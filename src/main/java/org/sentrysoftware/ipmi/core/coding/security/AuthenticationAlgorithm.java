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

import org.sentrysoftware.ipmi.core.coding.commands.session.Rakp1;

/**
 * Interface for authentication algorithms. All classes extending this one must
 * have a parameterless constructor.
 */
public abstract class AuthenticationAlgorithm {

    /**
     * @return algorithm-specific code
     */
    public abstract byte getCode();

    /**
     * @return length of the key for the RAKP2 message
     */
    public abstract int getKeyLength();

    /**
     * @return length of the integrity check base for RAKP4 message
     */
    public abstract int getIntegrityCheckBaseLength();

    /**
     * Checks value of the Key Exchange Authentication Code in RAKP messages
     *
     * @param data
     *            - The base for authentication algorithm. Depends on RAKP
     *            Message.
     * @param key
     *            - the Key Exchange Authentication Code to check.
     * @param password
     *            - password of the user establishing a session
     * @return True if authentication check was successful, false otherwise.
     * @throws NoSuchAlgorithmException
     *             when initiation of the algorithm fails
     * @throws InvalidKeyException
     *             when creating of the algorithm key failsS
     */
    public abstract boolean checkKeyExchangeAuthenticationCode(byte[] data,
            byte[] key, String password) throws NoSuchAlgorithmException,
            InvalidKeyException;

    /**
     * Calculates value of the Key Exchange Authentication Code in RAKP messages
     *
     * @param data
     *            - The base for authentication algorithm. Depends on RAKP
     *            Message.
     * @param password
     *            - password of the user establishing a session
     * @throws NoSuchAlgorithmException
     *             when initiation of the algorithm fails
     * @throws InvalidKeyException
     *             when creating of the algorithm key fails
     */
    public abstract byte[] getKeyExchangeAuthenticationCode(byte[] data,
            String password) throws NoSuchAlgorithmException,
            InvalidKeyException;

    /**
     * Validates Integrity Check Value in RAKP Message 4.
     *
     * @param data
     *            - The base for authentication algorithm.
     * @param reference
     *            - The Integrity Check Value to validate.
     * @param sik
     *            - The Session Integrity Key generated on base of RAKP Messages
     *            1 and 2.
     * @see Rakp1#calculateSik(org.sentrysoftware.ipmi.core.coding.commands.session.Rakp1ResponseData)
     * @return True if integrity check was successful, false otherwise.
     * @throws NoSuchAlgorithmException
     *             when initiation of the algorithm fails
     * @throws InvalidKeyException
     *             when creating of the algorithm key fails
     */
    public abstract boolean doIntegrityCheck(byte[] data, byte[] reference,
            byte[] sik) throws InvalidKeyException, NoSuchAlgorithmException;

    /**
     * @return the name of the algorithm as a {@code String}.
     */
    public abstract String getAlgorithmName();
}
