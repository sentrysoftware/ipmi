package org.sentrysoftware.ipmi.core.coding.commands.sel;

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

import org.sentrysoftware.ipmi.core.coding.commands.CommandCodes;
import org.sentrysoftware.ipmi.core.coding.commands.IpmiCommandCoder;
import org.sentrysoftware.ipmi.core.coding.commands.IpmiVersion;
import org.sentrysoftware.ipmi.core.coding.commands.ResponseData;
import org.sentrysoftware.ipmi.core.coding.payload.CompletionCode;
import org.sentrysoftware.ipmi.core.coding.payload.IpmiPayload;
import org.sentrysoftware.ipmi.core.coding.payload.lan.IPMIException;
import org.sentrysoftware.ipmi.core.coding.payload.lan.IpmiLanRequest;
import org.sentrysoftware.ipmi.core.coding.payload.lan.IpmiLanResponse;
import org.sentrysoftware.ipmi.core.coding.payload.lan.NetworkFunction;
import org.sentrysoftware.ipmi.core.coding.protocol.AuthenticationType;
import org.sentrysoftware.ipmi.core.coding.protocol.IpmiMessage;
import org.sentrysoftware.ipmi.core.coding.security.CipherSuite;
import org.sentrysoftware.ipmi.core.common.TypeConverter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Wrapper for Get Sel Entry request
 */
public class GetSelEntry extends IpmiCommandCoder {

    private int reservationId;

    private int recordId;

    /**
     * Initiates GetSelEntry for both encoding and decoding.
     *
     * @param version
     *            - IPMI version of the command.
     * @param cipherSuite
     *            - {@link CipherSuite} containing authentication,
     *            confidentiality and integrity algorithms for this session.
     * @param authenticationType
     *            - Type of authentication used. Must be RMCPPlus for IPMI v2.0.
     * @param reservationId
     *            - SEL reservation ID received via {@link ReserveSel} command
     *            or 0 if requesting for whole record
     * @param recordId
     *            - ID of the record to get
     */
    public GetSelEntry(IpmiVersion version, CipherSuite cipherSuite,
            AuthenticationType authenticationType, int reservationId,
            int recordId) {
        super(version, cipherSuite, authenticationType);
        this.recordId = recordId;
        this.reservationId = reservationId;
    }

    @Override
    public byte getCommandCode() {
        return CommandCodes.GET_SEL_ENTRY;
    }

    @Override
    public NetworkFunction getNetworkFunction() {
        return NetworkFunction.StorageRequest;
    }

    @Override
    protected IpmiPayload preparePayload(int sequenceNumber)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] payload = new byte[6];

        byte[] buffer = TypeConverter.intToByteArray(reservationId);

        payload[0] = buffer[3];
        payload[1] = buffer[2]; // reservation ID

        buffer = TypeConverter.intToByteArray(recordId);

        payload[2] = buffer[3];
        payload[3] = buffer[2]; // record ID

        payload[4] = 0;
        payload[5] = TypeConverter.intToByte(0xff);

        return new IpmiLanRequest(getNetworkFunction(), getCommandCode(),
                payload, TypeConverter.intToByte(sequenceNumber));
    }

    @Override
    public ResponseData getResponseData(IpmiMessage message) throws IPMIException,
            NoSuchAlgorithmException, InvalidKeyException {
        if (!isCommandResponse(message)) {
            throw new IllegalArgumentException(
                    "This is not a response for Get SEL Entry command");
        }
        if (!(message.getPayload() instanceof IpmiLanResponse)) {
            throw new IllegalArgumentException("Invalid response payload");
        }
        if (((IpmiLanResponse) message.getPayload()).getCompletionCode() != CompletionCode.Ok) {
            throw new IPMIException(
                    ((IpmiLanResponse) message.getPayload())
                            .getCompletionCode());
        }

        byte[] raw = message.getPayload().getIpmiCommandData();

        if (raw == null || raw.length < 3) {
            throw new IllegalArgumentException(
                    "Invalid response payload length");
        }

        GetSelEntryResponseData responseData = new GetSelEntryResponseData();

        byte[] buffer = new byte[4];

        buffer[0] = raw[0];
        buffer[1] = raw[1];
        buffer[2] = 0;
        buffer[3] = 0;

        responseData.setNextRecordId(TypeConverter
                .littleEndianByteArrayToInt(buffer));

        byte[] recordData = new byte[raw.length - 2];

        System.arraycopy(raw, 2, recordData, 0, recordData.length);

        responseData.setSelRecord(SelRecord.populateSelRecord(recordData));

        return responseData;
    }

}
