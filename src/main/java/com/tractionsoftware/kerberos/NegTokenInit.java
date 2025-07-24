/*
 * Copyright (C) 2006-2010 Alfresco Software Limited.
 *
 * This file is part of Alfresco
 *
 * Alfresco is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Alfresco is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */

package com.tractionsoftware.kerberos;

import com.tractionsoftware.asn.*;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Contains the details of an SPNEGO NegTokenInit blob.
 *
 * @author gkspencer
 */
public class NegTokenInit {

    // Mechtypes list

    private Oid[] m_mechTypes;

    // Context flags

    private int m_contextFlags = -1;

    // Mechtoken

    private byte[] m_mechToken;

    // MectListMIC principal

    private String m_mecListMICPrincipal;

    /**
     * Class constructor for decoding
     */
    public NegTokenInit() {
    }

    /**
     * Class constructor for encoding
     *
     * @param mechTypes
     *     Oid[]
     * @param mechPrincipal
     *     String
     */
    public NegTokenInit(Oid[] mechTypes, String mechPrincipal) {
        m_mechTypes = mechTypes;
        m_mecListMICPrincipal = mechPrincipal;
    }

    /**
     * Class constructor for encoding
     *
     * @param mechTypes
     *     Vector
     * @param mechPrincipal
     *     String
     */
    public NegTokenInit(Collection<Oid> mechTypes, String mechPrincipal) {
        m_mechTypes = mechTypes.toArray(new Oid[0]);
        m_mecListMICPrincipal = mechPrincipal;
    }

    /**
     * Return the NegTokenInit object as a string
     *
     * @return String
     */
    @Override
    public String toString() {

        StringBuilder str = new StringBuilder(100);

        str.append("[NegTokenInit ");

        if (m_mechTypes != null) {
            str.append("mechTypes=");
            str.append(Arrays.stream(m_mechTypes).map(Object::toString).collect(Collectors.joining(",")));
        }

        if (m_contextFlags != -1) {
            str.append(" context=0x");
            str.append(Integer.toHexString(m_contextFlags));
        }

        if (m_mechToken != null) {
            str.append(" token=");
            str.append(m_mechToken.length);
            str.append(" bytes");
        }

        if (m_mecListMICPrincipal != null) {
            str.append(" principal=");
            str.append(m_mecListMICPrincipal);
        }
        str.append("]");

        return str.toString();

    }

    /**
     * Return the mechTypes OID list
     *
     * @return Oid[]
     */
    public final Oid[] getOids() {
        return m_mechTypes;
    }

    /**
     * Return the context flags
     *
     * @return int
     */
    public final int getContextFlags() {
        return m_contextFlags;
    }

    /**
     * Return the mechToken
     *
     * @return byte[]
     */
    public final byte[] getMechtoken() {
        return m_mechToken;
    }

    /**
     * Return the mechListMIC principal
     *
     * @return String
     */
    public final String getPrincipal() {
        return m_mecListMICPrincipal;
    }

    /**
     * Check if the OID list contains the specified OID
     *
     * @param oid
     *     Oid
     * @return boolean
     */
    public final boolean hasOid(Oid oid) {
        boolean foundOid = false;

        if (m_mechTypes != null) {
            foundOid = oid.containedIn(m_mechTypes);
        }

        return foundOid;
    }

    /**
     * Return the count of OIDs
     *
     * @return int
     */
    public final int numberOfOids() {
        return m_mechTypes != null ? m_mechTypes.length : 0;
    }

    /**
     * Return the specified OID
     *
     * @param idx
     *     int
     * @return OID
     */
    public final Oid getOidAt(int idx) {
        if (m_mechTypes != null && idx >= 0 && idx < m_mechTypes.length) {
            return m_mechTypes[idx];
        }
        return null;
    }

    /**
     * Decode an SPNEGO NegTokenInit blob, or accept a Kerberos v5 blob.
     *
     * @param buf
     *     byte[]
     * @param off
     *     int
     * @param len
     *     int
     * @throws IOException
     *     if the format of the data is invalid.
     */
    public void decode(byte[] buf, int off, int len) throws IOException {
        // Create a DER buffer to decode the blob
        DERBuffer derBuf = new DERBuffer(buf, off, len);
        // Get the first object from the blob
        DERObject derObj = derBuf.unpackApplicationSpecific();
        if (derObj instanceof DEROid derOid) {
            // Check that the OID indicates SPNEGO
            decodeWithOid(buf, derBuf, derOid);
        }
        else {
            throw new IOException("Invalid security blob");
        }
    }

    /**
     * Encode an SPNEGO NegTokenInit blob
     *
     * @return byte[]
     * @throws IOException
     *     if there is a problem packing/encoding the data.
     */
    public byte[] encode() throws IOException {
        // Create the list of objects to be encoded

        List<DERObject> objList = new ArrayList<>();

        objList.add(new DEROid(CommonOids.ID_SPNEGO));

        // Build the sequence of tagged objects

        DERSequence derSeq = new DERSequence();
        derSeq.setTagNo(0);

        // mechTypes sequence

        DERSequence mechTypesSeq = new DERSequence();
        mechTypesSeq.setTagNo(0);

        for (Oid mechType : m_mechTypes) {
            mechTypesSeq.addObject(new DEROid(mechType.toString()));
        }

        derSeq.addObject(mechTypesSeq);

        // mechListMIC
        //
        // Note: This field is not as specified

        if (m_mecListMICPrincipal != null) {
            DERSequence derMecSeq = new DERSequence();
            derMecSeq.setTagNo(3);

            DERGeneralString mecStr = new DERGeneralString(m_mecListMICPrincipal);
            mecStr.setTagNo(0);

            derMecSeq.addObject(mecStr);
            derSeq.addObject(derMecSeq);
        }

        // Add the sequence to the object list

        objList.add(derSeq);

        // Pack the objects

        DERBuffer derBuf = new DERBuffer();

        derBuf.packApplicationSpecific(objList);

        // Return the packed negTokenInit blob

        return derBuf.getBytes();
    }

    private void decodeWithOid(byte[] buf, DERBuffer derBuf, DEROid derOid) throws IOException {
        String oidName = derOid.getOid();
        switch (oidName) {
        case CommonOids.ID_KERBEROS5 -> setAlreadyDecoded(buf);
        case CommonOids.ID_SPNEGO -> decodeFromSPNEGO(derBuf);
        default -> throw new IOException("Blob is not Kerberos v5 or SPNEGO.");
        }
    }

    private void setAlreadyDecoded(byte[] buf) {
        // ALF-6284 fix, the blob is already kerberos5, no need to parse
        m_mechTypes = new Oid[] { CommonOids.KERBEROS5 };
        m_mechToken = buf;
    }

    private void decodeFromSPNEGO(DERBuffer derBuf) throws IOException {
        // Get the remaining objects from the DER buffer
        DERObject derObj = derBuf.unpackObject();
        if (derObj instanceof DERSequence derSeq) {
            decodeMechTypes(derSeq);
        }
        else {
            throw new IOException("Bad object type in SPNEGO blob.");
        }
    }

    private void decodeMechTypes(DERSequence derSeq) throws IOException {

        // Access the sequence, should be a sequence of tagged values

        // Get the mechTypes list

        DERObject derObj = derSeq.getTaggedObject(0);
        if (derObj == null) {
            throw new IOException("No mechTypes list in blob");
        }
        if (!(derObj instanceof DERSequence derOidSeq)) {
            throw new IOException("Invalid mechTypes object");
        }

        // Unpack the OID list (required)

        m_mechTypes = new Oid[derOidSeq.numberOfObjects()];
        int idx = 0;

        for (int i = 0; i < derOidSeq.numberOfObjects(); i++) {
            derObj = derOidSeq.getObjectAt(i);
            if (derObj instanceof DEROid derOid) {
                try {
                    m_mechTypes[idx++] = new Oid(derOid.getOid());
                }
                catch (GSSException ex) {
                    throw new IOException("Bad mechType OID");
                }
            }
        }

        // Unpack the context flags (optional)

        derObj = derSeq.getTaggedObject(1);
        if (derObj != null) {
            // Check the type
            if (derObj instanceof DERBitString derBitStr) {
                // Get the bit flags
                m_contextFlags = derBitStr.intValue();
            }
        }

        // Unpack the mechToken (required)
        derObj = derSeq.getTaggedObject(2);
        if (derObj == null) {
            throw new IOException("No mechToken in blob");
        }
        if (!(derObj instanceof DEROctetString derStr)) {
            throw new IOException("Invalid mechToken object");
        }

        m_mechToken = derStr.getValue();

        // Unpack the mechListMIC (optional)
//        derObj = derSeq.getTaggedObject(3);
//        if (derObj != null) {
//            // Check for the Microsoft format mechListMIC
//            if (derObj instanceof DERSequence) {
//            }
//        }

    }

}
