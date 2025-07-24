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

import com.sun.security.jgss.ExtendedGSSContext;
import com.sun.security.jgss.InquireType;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import javax.security.auth.kerberos.EncryptionKey;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Kerberos authentication details -- i.e., Kerberos response token and session details about the user.
 *
 * @author gkspencer
 */
public class KerberosDetails {

    private static final Logger LOGGER = Logger.getLogger(KerberosDetails.class.getName());

    public static KerberosDetails createInstance(GSSContext serverGSSContext, byte[] respBlob) throws GSSException {
        return new KerberosDetails(
            serverGSSContext.getSrcName(),
            serverGSSContext.getTargName(),
            serverGSSContext.getLifetime(),
            getSessionKeyAlgorithm(serverGSSContext),
            respBlob
        );
    }

    public static String getSessionKeyAlgorithm(GSSContext serverGSSContext) {
        if (serverGSSContext instanceof ExtendedGSSContext ext) {
            try {
                if (ext.inquireSecContext(InquireType.KRB5_GET_SESSION_KEY_EX) instanceof EncryptionKey key) {
                    return key.getAlgorithm();
                }
            }
            catch (GSSException | RuntimeException e) {
                LOGGER.log(Level.WARNING, "", e);
            }
        }
        return null;
    }

    private final String source;

    private final String target;

    private final int remainingLifetimeSeconds;

    private final String sessionKeyAlgorithm;

    private final byte[] responseToken;

    /**
     * Class constructor
     *
     * @param source
     *     GSSName
     * @param target
     *     GSSName
     * @param response
     *     byte[]
     */
    public KerberosDetails(GSSName source, GSSName target, int remainingLifetimeSeconds, String sessionKeyAlgorithm, byte[] response) {
        this.source = source.toString();
        this.target = target.toString();
        this.remainingLifetimeSeconds = remainingLifetimeSeconds;
        this.sessionKeyAlgorithm = sessionKeyAlgorithm;
        this.responseToken = response;
    }

    /**
     * Return the context initiator for the Kerberos authentication
     *
     * @return String
     */
    public final String getSourceName() {
        return source;
    }

    /**
     * Return the context acceptor for the Kerberos authentication
     *
     * @return String
     */
    public final String getTargetName() {
        return target;
    }

    public final int getRemainingLifetimeSeconds() {
        return remainingLifetimeSeconds;
    }

    public final String getSessionKeyAlgorithm() {
        return sessionKeyAlgorithm;
    }

    /**
     * Return the Kerberos response token
     *
     * @return byte[]
     */
    public final byte[] getResponseToken() {
        return responseToken;
    }

    /**
     * Parse the source name to return the user name part only
     *
     * @return String
     */
    public final String getUserName() {
        if (source == null) {
            return null;
        }
        int pos = source.indexOf('@');
        if (pos != -1) {
            return source.substring(0, pos);
        }
        return source;
    }

    public final String getDomain() {
        if (source == null) {
            return null;
        }
        int pos = source.indexOf('@');
        if (pos != -1) {
            return source.substring(pos + 1);
        }
        return null;
    }

    /**
     * Return the response token length
     *
     * @return int
     */
    public final int getResponseLength() {
        return responseToken != null ? responseToken.length : 0;
    }

    public String toString() {
        return "[Source=" +
               source +
               ",Target=" +
               target +
               ",Remaining Lifetime=" +
               remainingLifetimeSeconds +
               "s,Session Key Algorithm=" +
               Objects.toString(sessionKeyAlgorithm, "?") +
               ":Response=" +
               getResponseLength() +
               " bytes]";
    }

}
