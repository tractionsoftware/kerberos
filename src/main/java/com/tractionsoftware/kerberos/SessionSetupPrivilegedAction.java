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

import org.ietf.jgss.*;

import java.security.PrivilegedAction;
import java.util.concurrent.Callable;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Session Setup Privileged Action Class
 *
 * <p>
 * Handle the processing of a received SPNEGO packet in the context of the CIFS server.
 *
 * @author gkspencer
 */
public class SessionSetupPrivilegedAction implements PrivilegedAction<KerberosDetails>, Callable<KerberosDetails> {

    private static final Logger LOGGER = Logger.getLogger(SessionSetupPrivilegedAction.class.getName());

    private static final class GSSData implements AutoCloseable {

        private static GSSData create(String m_accountName) throws GSSException {

            GSSManager gssManager = GSSManager.getInstance();
            GSSName serverGSSName = gssManager.createName(m_accountName, GSSName.NT_USER_NAME);
            GSSCredential serverGSSCreds = gssManager.createCredential(
                serverGSSName,
                GSSCredential.INDEFINITE_LIFETIME,
                CommonOids.KERBEROS5,
                GSSCredential.ACCEPT_ONLY
            );

            try {
                GSSContext serverGSSContext = gssManager.createContext(serverGSSCreds);
                return new GSSData(serverGSSName, serverGSSCreds, serverGSSContext);
            }
            catch (GSSException | RuntimeException e) {
                try {
                    serverGSSCreds.dispose();
                }
                catch (GSSException | RuntimeException x) {
                    e.addSuppressed(x);
                }
                throw e;
            }

        }

        private GSSName serverGSSName;

        private GSSCredential serverGSSCreds;

        private GSSContext serverGSSContext;

        public GSSData(GSSName serverGSSName, GSSCredential serverGSSCreds, GSSContext serverGSSContext) {
            this.serverGSSName = serverGSSName;
            this.serverGSSCreds = serverGSSCreds;
            this.serverGSSContext = serverGSSContext;
        }

        @Override
        public void close() throws GSSException {
            if (serverGSSName != null) {
                closeImpl();
            }
        }

        public GSSContext getContext() {
            return serverGSSContext;
        }

        private void closeImpl() throws GSSException {
            serverGSSName = null;
            GSSException eMain = null;
            RuntimeException erMain = null;
            try {
                serverGSSCreds.dispose();
            }
            catch (GSSException e) {
                eMain = e;
            }
            catch (RuntimeException e) {
                erMain = e;
            }
            serverGSSCreds = null;
            try {
                serverGSSContext.dispose();
            }
            catch (GSSException e) {
                if (eMain == null) {
                    eMain = e;
                    if (erMain != null) {
                        eMain.addSuppressed(erMain);
                    }
                }
                else {
                    eMain.addSuppressed(e);
                }
            }
            catch (RuntimeException e) {
                if (eMain == null) {
                    erMain = e;
                }
                else {
                    eMain.addSuppressed(e);
                }
            }
            serverGSSContext = null;
            if (eMain != null) {
                throw eMain;
            }
            if (erMain != null) {
                throw erMain;
            }
        }

    }

    // Received security blob details

    private final byte[] m_secBlob;

    private final int m_secOffset;

    private final int m_secLen;

    // CIFS server account name

    private final String accountName;

    public SessionSetupPrivilegedAction(String accountName, byte[] secBlob) {
        this(accountName, secBlob, 0, secBlob.length);
    }

    public SessionSetupPrivilegedAction(String accountName, byte[] secBlob, int secOffset, int secLen) {
        this.accountName = accountName;
        this.m_secBlob = secBlob;
        this.m_secOffset = secOffset;
        this.m_secLen = secLen;
    }

    /**
     * Run the privileged action
     */
    @Override
    public KerberosDetails run() {
        try (GSSData data = GSSData.create(accountName)) {
            GSSContext serverGSSContext = data.getContext();
            // Accept the incoming security blob and generate the response blob
            byte[] respBlob = serverGSSContext.acceptSecContext(m_secBlob, m_secOffset, m_secLen);
            LOGGER.log(Level.FINE, "GSSContext for " + accountName + ": " + serverGSSContext);
            // Create the Kerberos response details
            return KerberosDetails.createInstance(serverGSSContext, respBlob);
        }
        catch (GSSException e) {
            LOGGER.log(Level.WARNING, "Failed to accept security context for " + accountName, e);
        }
        return null;
    }

    @Override
    public KerberosDetails call() {
        return run();
    }

}
