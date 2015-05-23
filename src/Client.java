
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.DatagramSocket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.HashMap;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 *
 * @author Dario
 */
public class Client implements Runnable {

    protected String srvIP;
    protected int srvPort;

    @Override
    public void run() {
    }

    public static class TCPClient extends Client {

        private SSLSocket srvSocket;
        private final PrivateKey privKey;
        private final PublicKey pubKey;
        private final SecretKey AESkey;
        private SecretKey srvAES;
        private PublicKey srvKey;
        private String myID;

        public TCPClient(String ip, int port) {
            srvIP = ip;
            srvPort = port;
            KeyPairGenerator keyGen = null;
            KeyGenerator AESkeyGen = null;
            try {
                keyGen = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                keyGen.initialize(2048, random);
                AESkeyGen = KeyGenerator.getInstance("AES");
                AESkeyGen.init(128);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }
            KeyPair pair = keyGen.genKeyPair();
            privKey = pair.getPrivate();
            pubKey = pair.getPublic();
            AESkey = AESkeyGen.generateKey();
            System.out.print("Enter a username for this session: ");
            myID = new Scanner(System.in).nextLine();
        }

        private void start() {
            boolean disconnect = true;
            while (disconnect) {
                try {
                    SSLSocketFactory sockF = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    srvSocket = (SSLSocket) sockF.createSocket(srvIP, srvPort);
                    srvSocket.setEnabledCipherSuites(new String[]{"SSL_DH_anon_WITH_RC4_128_MD5"});

                    disconnect = false;
                } catch (IOException ex) {
                    disconnect = true;
                    System.out.print("Can not reach the server, please enter another ip: ");
                    srvIP = new Scanner(System.in).next();
                    String input;
                    do {
                        System.out.print("Input a new port: ");
                        input = new Scanner(System.in).next();
                        if (input.matches("[0-9]+")) {
                            srvPort = Integer.parseUnsignedInt(input);
                        } else {
                            System.out.println("Input a valid port!");
                            input = "";
                        }
                    } while (input.isEmpty());
                }
            }
        }

        @Override
        public void run() {
            start();
            sendRSAKey();
            System.out.println("CLIENT: RSA decrypted sent!");
            getRSAKey();
            System.out.println("CLIENT: RSA encrypted received & decrypted!");
            getAESKey();
            System.out.println("CLIENT: AES double encrypted received & decrypted!");
            sendAESKey();
            System.out.println("CLIENT: AES double encrypted sent!");
            sendStr(myID);
            System.out.println("ALL SYSTEMS NORMAL!");
            System.out.println(getStr());
            new Thread(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        sendStr(new Scanner(System.in).nextLine());
                    }
                }
            }).start();
            while (true) {
                String s = getStr();
                if (!s.isEmpty() || s!=null) {
                    System.out.println(s);
                }

                try {
                    Thread.sleep(500);
                } catch (InterruptedException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        private void sendRSAKey() {
            try {
                ObjectOutputStream sOut = new ObjectOutputStream(srvSocket.getOutputStream());
                try {
                    sOut.writeObject(pubKey);
                } finally {
                    sOut.flush();
                }
            } catch (IOException ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        private void getRSAKey() {
            if (srvKey == null) {
                byte[] serByteObj1 = null, serByteObj2 = null, serByteObj3 = null;
                try {
                    ObjectInputStream sIn = new ObjectInputStream(srvSocket.getInputStream());
                    Cipher dcipher = Cipher.getInstance(privKey.getAlgorithm());
                    dcipher.init(Cipher.DECRYPT_MODE, privKey);
                    for (int i = 0; i < 3; i++) {
                        SealedObject sObj = (SealedObject) sIn.readObject();
                        if (i == 0) {
                            serByteObj1 = (byte[]) sObj.getObject(dcipher);
                        } else if (i == 1) {
                            serByteObj2 = (byte[]) sObj.getObject(dcipher);
                        } else if (i == 2) {
                            serByteObj3 = (byte[]) sObj.getObject(dcipher);
                        }
                    }
                    byte[] fObj = new byte[serByteObj1.length + serByteObj2.length + serByteObj3.length - 49];
                    System.arraycopy(serByteObj1, 0, fObj, 0, serByteObj1.length);
                    System.arraycopy(serByteObj2, 0, fObj, serByteObj1.length, serByteObj2.length);
                    System.arraycopy(serByteObj3, 0, fObj, serByteObj2.length + serByteObj1.length, serByteObj3.length - 49);
                    srvKey = (PublicKey) new ObjectInputStream(new ByteArrayInputStream(fObj)).readObject();
                } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        private void getAESKey() {
            try {
                ObjectInputStream sIn = new ObjectInputStream(srvSocket.getInputStream());
                Cipher dcipher1 = Cipher.getInstance(privKey.getAlgorithm());
                dcipher1.init(Cipher.DECRYPT_MODE, privKey);
                Cipher dcipher2 = Cipher.getInstance(srvKey.getAlgorithm());
                dcipher2.init(Cipher.DECRYPT_MODE, srvKey);
                byte[] serByteObj1 = null, serByteObj2 = null, serByteObj3 = null, serByteObj4 = null;
                for (int i = 0; i < 4; i++) {
                    SealedObject sObj1 = (SealedObject) sIn.readObject();
                    if (i == 0) {
                        serByteObj1 = (byte[]) sObj1.getObject(dcipher1);
                    } else if (i == 1) {
                        serByteObj2 = (byte[]) sObj1.getObject(dcipher1);
                    } else if (i == 2) {
                        serByteObj3 = (byte[]) sObj1.getObject(dcipher1);
                    } else if (i == 3) {
                        serByteObj4 = (byte[]) sObj1.getObject(dcipher1);
                    }
                }
                byte[] fObj = new byte[serByteObj1.length + serByteObj2.length + serByteObj3.length + serByteObj4.length];
                System.arraycopy(serByteObj1, 0, fObj, 0, serByteObj1.length);
                System.arraycopy(serByteObj2, 0, fObj, serByteObj1.length, serByteObj2.length);
                System.arraycopy(serByteObj3, 0, fObj, serByteObj1.length + serByteObj2.length, serByteObj3.length);
                System.arraycopy(serByteObj4, 0, fObj, serByteObj1.length + serByteObj2.length + serByteObj3.length, serByteObj4.length);
                srvAES = (SecretKey) new ObjectInputStream(new ByteArrayInputStream(dcipher2.doFinal(fObj))).readObject();
            } catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        private void sendAESKey() {
            try {
                ObjectOutputStream sOut = new ObjectOutputStream(srvSocket.getOutputStream());
                ByteArrayOutputStream bOs = new ByteArrayOutputStream();
                ObjectOutputStream out = new ObjectOutputStream(bOs);
                try {
                    Cipher cipher1 = Cipher.getInstance(privKey.getAlgorithm());
                    cipher1.init(Cipher.ENCRYPT_MODE, privKey);
                    Cipher cipher2 = Cipher.getInstance(srvKey.getAlgorithm());
                    cipher2.init(Cipher.ENCRYPT_MODE, srvKey);
                    out.writeObject(AESkey);
                    byte[] serByteObj1 = cipher1.doFinal(bOs.toByteArray());
                    for (int i = 0; i < 4; i++) {
                        byte[] serByteObj2 = Arrays.copyOfRange(serByteObj1, 64 * i, 64 * i + 64);
                        SealedObject sObj = new SealedObject(serByteObj2, cipher2);
                        sOut.writeObject(sObj);
                    }
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
                } finally {
                    sOut.flush();
                }
            } catch (IOException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        private void sendStr(String str) {
            try {
                Cipher cipher1 = Cipher.getInstance(srvAES.getAlgorithm());
                Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                cipher1.init(Cipher.ENCRYPT_MODE, srvAES);
                cipher2.init(Cipher.ENCRYPT_MODE, AESkey);
                ObjectOutputStream sOut = new ObjectOutputStream(srvSocket.getOutputStream());
                sOut.writeObject(cipher2.doFinal(cipher1.doFinal(str.getBytes())));
                sOut.flush();
            } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        private String getStr() {
            try {
                Cipher cipher1 = Cipher.getInstance(srvAES.getAlgorithm());
                Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                cipher1.init(Cipher.DECRYPT_MODE, srvAES);
                cipher2.init(Cipher.DECRYPT_MODE, AESkey);
                return new String(cipher2.doFinal(cipher1.doFinal((byte[]) new ObjectInputStream(srvSocket.getInputStream()).readObject())));
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException ex) {
                Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
            }
            return "";
        }
    }

    public static class UDPClient extends Client {

        private DatagramSocket srvSocket;

        public UDPClient(String ip, int port) {
            srvIP = ip;
            srvPort = port;
        }

        public void start() {
        }

        @Override
        public void run() {
            while (true) {
            }
        }
    }
}