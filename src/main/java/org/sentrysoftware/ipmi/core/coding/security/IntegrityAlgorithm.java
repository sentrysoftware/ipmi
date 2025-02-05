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

import org.sentrysoftware.ipmi.core.coding.commands.session.Rakp1;
import org.sentrysoftware.ipmi.core.common.TypeConverter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Interface for Integrity Algorithms. All classes extending this one must
 * implement constructor(byte[]).
 */
public abstract class IntegrityAlgorithm {

	protected static final byte[] CONST1 = new byte[20];
	static {
		Arrays.fill(CONST1, (byte) 1);
	}

	protected byte[] sik;
	private final Mac mac;

	/**
	 * Constructs an integrity algorithm
	 *
	 * @throws NoSuchAlgorithmException - when initiation of the algorithm fails
	 */
	protected IntegrityAlgorithm() throws NoSuchAlgorithmException {
		mac = Mac.getInstance(getAlgorithmName());
	}

	/**
	 * Constructor that allows skipping HMAC initialization.
	 *
	 * @param noMacInit If {@code true}, HMAC will not be initialized.
	 */
	protected IntegrityAlgorithm(boolean noMacInit) {
		this.mac = null;
	}

	/**
	 * Initializes Integrity Algorithm
	 *
	 * @param sik - Session Integrity Key calculated during the opening of the
	 *            session or user password if 'one-key' logins are enabled.
	 */
	public void initialize(byte[] sik) throws InvalidKeyException {
		this.sik = sik;

		SecretKeySpec k1 = new SecretKeySpec(sik, getAlgorithmName());

		mac.init(k1);
		k1 = new SecretKeySpec(mac.doFinal(CONST1), getAlgorithmName());

		mac.init(k1);
	}

	/**
	 * Returns the algorithm's ID.
	 */
	public abstract byte getCode();

	/**
	 * Creates AuthCode field for message.
	 *
	 * @param base - data starting with the AuthType/Format field up to and
	 *             including the field that immediately precedes the AuthCode field
	 * @return AuthCode field. Might be null if empty AuthCOde field is generated.
	 *
	 * @see Rakp1#calculateSik(org.sentrysoftware.ipmi.core.coding.commands.session.Rakp1ResponseData)
	 */
	public byte[] generateAuthCode(final byte[] base) {

		if (sik == null) {
			throw new NullPointerException("Algorithm not initialized.");
		}

		byte[] result = new byte[getAuthCodeLength()];
		byte[] updatedBase;

		if (base[base.length - 2] == 0) { // pas de padding
			updatedBase = injectIntegrityPad(base, getAuthCodeLength());
		} else {
			updatedBase = base;
		}

		System.arraycopy(mac.doFinal(updatedBase), 0, result, 0, getAuthCodeLength());

		return result;
	}

	/**
	 * Modifies the algorithm base since with null Auth Code during encoding
	 * Integrity Pad isn't calculated.
	 *
	 * @param base           - integrity algorithm base without Integrity Pad.
	 * @param authCodeLength - expected length of the Auth Code field.
	 * @return - integrity algorithm base with Integrity Pad and updated Pad Length
	 *         field.
	 */
	protected byte[] injectIntegrityPad(byte[] base, int authCodeLength) {
		int pad = 0;
		if ((base.length + authCodeLength) % 4 != 0) {
			pad = 4 - (base.length + authCodeLength) % 4;
		}

		if (pad != 0) {
			byte[] newBase = new byte[base.length + pad];

			System.arraycopy(base, 0, newBase, 0, base.length - 2);

			for (int i = base.length - 2; i < base.length - 2 + pad; ++i) {
				newBase[i] = TypeConverter.intToByte(0xff);
			}

			newBase[newBase.length - 2] = TypeConverter.intToByte(pad);

			newBase[newBase.length - 1] = base[base.length - 1];

			return newBase;
		} else {
			return base;
		}
	}

	/**
	 * Returns the name of the algorithm.
	 *
	 * @return The algorithm name as a {@code String}.
	 */
	public abstract String getAlgorithmName();

	/**
	 * Returns the length of the authentication code
	 *
	 * @return The length of the authentication code in bytes.
	 */
	public abstract int getAuthCodeLength();

}
