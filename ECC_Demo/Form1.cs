using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ECC_Demo
{
    public partial class Form1 : Form
    {
        // Networking
        private TcpListener? _server;
        private TcpClient? _client;
        private NetworkStream? _stream;
        private bool _isServer = false;

        // Cryptography - ECDH (Chat)
        private ECDiffieHellmanCng? _myEcdh;
        private byte[]? _sharedSecret;

        // Cryptography - ECDSA (Notary)
        // Create fresh keys for each signing operation for this demo.

        public Form1()
        {
            InitializeComponent();
        }

        // ========================================================================
        // TAB 1: Network Chat (ECDHE + ECIES)
        // ========================================================================

        // 1. Connection Logic
        private async void btnStartServer_Click(object sender, EventArgs e)
        {
            try
            {
                int port = int.Parse(txtMyPort.Text);
                _server = new TcpListener(IPAddress.Any, port);
                _server.Start();
                _isServer = true;
                Log($"[NET] Server started on port {port}.", Color.Cyan);
                Log("[NET] Waiting for incoming connection...", Color.White);

                // Accept one client
                _client = await _server.AcceptTcpClientAsync();
                Log("[NET] Peer connected successfully!", Color.Lime);

                _stream = _client.GetStream();

                // Start Handshake immediately
                await PerformHandshakeAsync();

                // Start Listening Loop
                _ = ReceiveLoopAsync();
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Server Error: {ex.Message}", Color.Red);
            }
        }

        private async void btnConnect_Click(object sender, EventArgs e)
        {
            try
            {
                int port = int.Parse(txtTargetPort.Text);
                _client = new TcpClient();
                Log($"[NET] Attempting connection to 127.0.0.1:{port}...", Color.Cyan);

                await _client.ConnectAsync("127.0.0.1", port);
                Log("[NET] Connection established!", Color.Lime);

                _stream = _client.GetStream();

                // Start Handshake immediately
                await PerformHandshakeAsync();

                // Start Listening Loop
                _ = ReceiveLoopAsync();

            }
            catch (Exception ex)
            {
                Log($"[ERROR] Connection Error: {ex.Message}", Color.Red);
            }
        }

        // 2. ECDH Logic & Handshake
        private async Task PerformHandshakeAsync()
        {
            try
            {
                Log("---------------------------------------------------------------", Color.Gray);
                Log("[ECDHE] Starting Ephemeral Key Exchange...", Color.Yellow);

                // Generate Ephemeral Keys
                _myEcdh = new ECDiffieHellmanCng(256);
                _myEcdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                _myEcdh.HashAlgorithm = CngAlgorithm.Sha256;
                Log("[ECDHE] Generated local Key Pair (Curve P-256).", Color.White);

                // Export Public Key
#pragma warning disable SYSLIB0043
                byte[] myPublicKey = _myEcdh.PublicKey.ToByteArray();
#pragma warning restore SYSLIB0043

                string hexKey = BitConverter.ToString(myPublicKey).Replace("-", "");
                Log($"[ECDHE] My Public Key ({myPublicKey.Length} bytes):", Color.Gray);
                Log($"        {hexKey.Substring(0, 32)}...", Color.Gray);

                // Send Public Key Packet (Type 1)
                await SendPacketAsync(1, myPublicKey);
                Log("[NET] Sent Public Key packet to peer.", Color.White);
                Log("---------------------------------------------------------------", Color.Gray);
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Handshake Init Error: {ex.Message}", Color.Red);
            }
        }

        // 3. Packet Handling & Receive Loop
        private async Task ReceiveLoopAsync()
        {
            if (_stream == null) return;

            byte[] headerBuffer = new byte[5]; // [Type:1][Length:4]

            try
            {
                while (_client != null && _client.Connected)
                {
                    // Read Header
                    int bytesRead = await _stream.ReadAsync(headerBuffer, 0, 5);
                    if (bytesRead == 0) break; // Disconnected

                    byte type = headerBuffer[0];
                    int length = BitConverter.ToInt32(headerBuffer, 1);

                    // Read Payload
                    byte[] payload = new byte[length];
                    int totalRead = 0;
                    while (totalRead < length)
                    {
                        int read = await _stream.ReadAsync(payload, totalRead, length - totalRead);
                        if (read == 0) break;
                        totalRead += read;
                    }

                    // Process Packet
                    ProcessPacket(type, payload);
                }
            }
            catch (Exception ex)
            {
                Log($"[NET] Receive Loop Error: {ex.Message}", Color.Red);
            }
            finally
            {
                Log("[NET] Disconnected from peer.", Color.Orange);
            }
        }

        private void ProcessPacket(byte type, byte[] payload)
        {
            // Marshal Key Derivation / Decryption to UI thread for logging safety
            if (rtbChatLog.InvokeRequired)
            {
                rtbChatLog.Invoke(new Action(() => ProcessPacket(type, payload)));
                return;
            }

            if (type == 1) // Handshake (Peer Public Key)
            {
                try
                {
                    Log("---------------------------------------------------------------", Color.Gray);
                    string hexPeer = BitConverter.ToString(payload).Replace("-", "");
                    Log($"[NET] Received Peer Public Key ({payload.Length} bytes):", Color.Yellow);
                    Log($"      {hexPeer.Substring(0, 32)}...", Color.Gray);

                    if (_myEcdh == null) return;

                    // Import Peer Key & Derive Secret
                    using (CngKey peerKey = CngKey.Import(payload, CngKeyBlobFormat.EccPublicBlob))
                    {
                        Log("[ECDH] Computing Shared Secret (ECDH)...", Color.White);
                        _sharedSecret = _myEcdh.DeriveKeyMaterial(peerKey);
                    }

                    string hexSecret = BitConverter.ToString(_sharedSecret).Replace("-", "");
                    Log("[ECDH] Shared Secret Derived Successfully!", Color.Lime);
                    Log($"       Secret (AES Key): {hexSecret}", Color.Lime);
                    Log("---------------------------------------------------------------", Color.Gray);
                }
                catch (Exception ex)
                {
                    Log($"[ERROR] Handshake Processing Error: {ex.Message}", Color.Red);
                }
            }
            else if (type == 2) // Encrypted Message
            {
                try
                {
                    Log("[NET] Received Encrypted Payload:", Color.Yellow);
                    Log($"      Bytes: {BitConverter.ToString(payload).Replace("-", "")}", Color.Gray);

                    if (_sharedSecret == null)
                    {
                        Log("[ERROR] No Shared Secret established. Cannot decrypt.", Color.Red);
                        return;
                    }

                    // Decrypt
                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = _sharedSecret;

                        // Extract IV (First 16 bytes for AES)
                        byte[] iv = new byte[aes.BlockSize / 8];
                        byte[] cipherText = new byte[payload.Length - iv.Length];

                        Array.Copy(payload, 0, iv, 0, iv.Length);
                        Array.Copy(payload, iv.Length, cipherText, 0, cipherText.Length);

                        aes.IV = iv;

                        Log($"[ECIES] Decrypting with Shared Secret...", Color.White);
                        Log($"        IV: {BitConverter.ToString(iv).Replace("-", "")}", Color.Gray);

                        using (var decryptor = aes.CreateDecryptor())
                        {
                            byte[] plainBytes = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                            string message = Encoding.UTF8.GetString(plainBytes);

                            Log($"[CHAT] Peer says: {message}", Color.Cyan);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log($"[ERROR] Decryption Error: {ex.Message}", Color.Red);
                }
            }
        }

        private async Task SendPacketAsync(byte type, byte[] payload)
        {
            if (_stream == null) return;

            // Packet Structure: [Type:1][Length:4][Payload:N]
            byte[] lengthBytes = BitConverter.GetBytes(payload.Length);
            byte[] packet = new byte[1 + 4 + payload.Length];

            packet[0] = type;
            Array.Copy(lengthBytes, 0, packet, 1, 4);
            Array.Copy(payload, 0, packet, 5, payload.Length);

            await _stream.WriteAsync(packet, 0, packet.Length);
        }

        // 4. Messaging Logic
        private async void btnEncryptSend_Click(object sender, EventArgs e)
        {
            if (_stream == null || _sharedSecret == null)
            {
                Log("[ERROR] Not connected or Handshake incomplete.", Color.Red);
                return;
            }

            string text = txtMessageInput.Text;
            if (string.IsNullOrWhiteSpace(text)) return;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = _sharedSecret;
                    aes.GenerateIV();

                    byte[] plainBytes = Encoding.UTF8.GetBytes(text);

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                        // Payload = [IV] + [Cipher]
                        byte[] payload = new byte[aes.IV.Length + cipherBytes.Length];
                        Array.Copy(aes.IV, 0, payload, 0, aes.IV.Length);
                        Array.Copy(cipherBytes, 0, payload, aes.IV.Length, cipherBytes.Length);

                        await SendPacketAsync(2, payload);

                        Log($"[ME] {text}", Color.White);
                        Log($"     [Encrypted] IV: {BitConverter.ToString(aes.IV).Replace("-", "")}", Color.Gray);
                        Log($"     [Encrypted] Cipher: {BitConverter.ToString(cipherBytes).Replace("-", "")}", Color.Gray);

                        txtMessageInput.Clear();
                    }
                }
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Encryption/Send Error: {ex.Message}", Color.Red);
            }
        }

        // --- Logging Helper ---
        private void Log(string message, Color color)
        {
            if (rtbChatLog.InvokeRequired)
            {
                rtbChatLog.Invoke(new Action(() => Log(message, color)));
            }
            else
            {
                rtbChatLog.SelectionStart = rtbChatLog.TextLength;
                rtbChatLog.SelectionLength = 0;
                rtbChatLog.SelectionColor = color;
                rtbChatLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\r\n");
                rtbChatLog.SelectionColor = rtbChatLog.ForeColor;
                rtbChatLog.ScrollToCaret();
            }
        }


        // ========================================================================
        // TAB 2: File Notary (ECDSA)
        // ========================================================================

        private void btnSignFile_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog ofd = new OpenFileDialog() { Title = "Select File to Sign" })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        Log("---------------------------------------------------------------", Color.Gray);
                        Log($"[ECDSA] Loading file: {Path.GetFileName(ofd.FileName)}", Color.Cyan);
                        byte[] data = File.ReadAllBytes(ofd.FileName);
                        Log($"        Size: {data.Length} bytes", Color.Gray);

                        // Generate new Signing Keys
                        Log("[ECDSA] Generating new P-256 Signing Keypair...", Color.White);
                        using (ECDsaCng dsa = new ECDsaCng(256))
                        {
                            dsa.HashAlgorithm = CngAlgorithm.Sha256;

                            // Sign
                            Log("[ECDSA] Hashing data (SHA-256) and creating signature...", Color.White);
                            byte[] signature = dsa.SignData(data);

                            string sigBase64 = Convert.ToBase64String(signature);
                            Log($"[ECDSA] Signature Generated ({signature.Length} bytes)!", Color.Lime);
                            Log($"        Sig: {sigBase64.Substring(0, 50)}...", Color.Lime);

                            // Export Public Key
#pragma warning disable SYSLIB0043
                            byte[] publicKey = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
#pragma warning restore SYSLIB0043

                            // Save .sig and .pub
                            string sigPath = ofd.FileName + ".sig";
                            string pubPath = ofd.FileName + ".pub";

                            File.WriteAllBytes(sigPath, signature);
                            File.WriteAllBytes(pubPath, publicKey);

                            lblNotaryStatus.Text = "Status: File Signed Successfully!";
                            lblNotaryStatus.ForeColor = Color.Green;

                            Log($"[ECDSA] Saved signature to: {Path.GetFileName(sigPath)}", Color.White);
                            Log($"[ECDSA] Saved public key to: {Path.GetFileName(pubPath)}", Color.White);
                            Log("---------------------------------------------------------------", Color.Gray);

                            MessageBox.Show($"Created:\n{Path.GetFileName(sigPath)}\n{Path.GetFileName(pubPath)}", "Signing Complete");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log($"[ERROR] Signing Error: {ex.Message}", Color.Red);
                        MessageBox.Show($"Signing Error: {ex.Message}");
                    }
                }
            }
        }

        private void btnVerifyFile_Click(object sender, EventArgs e)
        {
            string? origFile = null, sigFile = null, keyFile = null;

            using (OpenFileDialog ofd = new OpenFileDialog() { Title = "1. Select ORIGINAL File" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;
                origFile = ofd.FileName;
            }

            using (OpenFileDialog ofd = new OpenFileDialog() { Title = "2. Select SIGNATURE (.sig) File" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;
                sigFile = ofd.FileName;
            }

            using (OpenFileDialog ofd = new OpenFileDialog() { Title = "3. Select PUBLIC KEY (.pub) File" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;
                keyFile = ofd.FileName;
            }

            try
            {
                Log("---------------------------------------------------------------", Color.Gray);
                Log("[ECDSA] Starting Verification...", Color.Cyan);
                Log($"        Original: {Path.GetFileName(origFile)}", Color.Gray);
                Log($"        Signature: {Path.GetFileName(sigFile)}", Color.Gray);

                byte[] data = File.ReadAllBytes(origFile);
                byte[] signature = File.ReadAllBytes(sigFile);
                byte[] keyBytes = File.ReadAllBytes(keyFile);

                Log("[ECDSA] Importing Public Key...", Color.White);
                using (CngKey key = CngKey.Import(keyBytes, CngKeyBlobFormat.EccPublicBlob))
                using (ECDsaCng dsa = new ECDsaCng(key))
                {
                    dsa.HashAlgorithm = CngAlgorithm.Sha256;

                    Log("[ECDSA] Verifying data hash against signature...", Color.White);
                    bool valid = dsa.VerifyData(data, signature);

                    if (valid)
                    {
                        lblNotaryStatus.Text = "Status: VALID SIGNATURE";
                        lblNotaryStatus.ForeColor = Color.Green;
                        Log("[ECDSA] RESULT: VALID SIGNATURE. File is Authentic.", Color.Lime);
                        MessageBox.Show("Signature is VALID.", "Verification Result", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    else
                    {
                        lblNotaryStatus.Text = "Status: TAMPERED / INVALID";
                        lblNotaryStatus.ForeColor = Color.Red;
                        Log("[ECDSA] RESULT: INVALID. The file has been TAMPERED with!", Color.Red);
                        MessageBox.Show("Signature is INVALID.", "Verification Result", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    Log("---------------------------------------------------------------", Color.Gray);
                }
            }
            catch (Exception ex)
            {
                Log($"[ERROR] Verification Error: {ex.Message}", Color.Red);
                MessageBox.Show($"Verification Error: {ex.Message}");
            }
        }
    }
}