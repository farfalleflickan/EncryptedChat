
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.AdjustmentEvent;
import java.awt.event.AdjustmentListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.WindowEvent;
import java.awt.event.WindowStateListener;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.DefaultCaret;

/**
 *
 * @author Dario
 */
public class ClientSwing implements Runnable {

    protected String srvIP;
    protected int srvPort;

    @Override
    public void run() {
    }

    public static class TCPClient extends ClientSwing {

        private SSLSocket srvSocket;
        private PrivateKey privKey;
        private PublicKey pubKey;
        private SecretKey AESkey;
        private SecretKey srvAES;
        private PublicKey srvKey;
        private String myID;
        private boolean running, reset, connected, valIn;
        private Thread InThread, OutThread;
        private JFrame startFr, conFr, mainFr;
        private JPanel startP;
        private JTextArea outF, inArea;
        private JButton sendMsg;

        public TCPClient() {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
            conFr = new JFrame();
            srvPort = 9002;
            inJFrame();
            reset = false;
            connected = false;
            KeyPairGenerator keyGen = null;
            KeyGenerator AESkeyGen = null;
            try {
                keyGen = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                keyGen.initialize(2048, random);
                AESkeyGen = KeyGenerator.getInstance("AES");
                AESkeyGen.init(128, random);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
            KeyPair pair = keyGen.genKeyPair();
            privKey = pair.getPrivate();
            pubKey = pair.getPublic();
            AESkey = AESkeyGen.generateKey();
        }

        private void reset() {
            if (!InThread.isInterrupted()) {
                InThread.interrupt();
                try {
                    InThread.join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            if (!OutThread.isInterrupted()) {
                OutThread.interrupt();
                try {
                    OutThread.join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            reset = false;
            connected = false;
            KeyPairGenerator keyGen = null;
            KeyGenerator AESkeyGen = null;
            try {
                keyGen = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                keyGen.initialize(2048, random);
                AESkeyGen = KeyGenerator.getInstance("AES");
                AESkeyGen.init(128, random);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
            KeyPair pair = keyGen.genKeyPair();
            privKey = pair.getPrivate();
            pubKey = pair.getPublic();
            AESkey = AESkeyGen.generateKey();
            srvAES = null;
            srvKey = null;
            mainFr.dispose();
            inJFrame();
            this.run();
        }

        private void start() {
            boolean disconnect = true;
            while (disconnect) {
                try {
                    SSLSocketFactory sockF = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    srvSocket = (SSLSocket) sockF.createSocket(srvIP, srvPort);
                    srvSocket.setEnabledCipherSuites(new String[]{"SSL_DH_anon_WITH_RC4_128_MD5"});
                    disconnect = false;
                } catch (IOException | IllegalArgumentException ex) {
                    disconnect = true;
                    startFr.dispose();
                    conFr.dispose();
                    JDialog d = new JDialog(startFr, "", true);
                    d.setLayout(new FlowLayout());
                    JButton but = new JButton("OK");
                    but.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e1) {
                            d.dispose();
                        }
                    });
                    JLabel str = new JLabel("Can not reach the server, please enter another ip!", SwingConstants.CENTER);
                    d.setLocationRelativeTo(null);
                    d.setResizable(false);
                    d.add(str);
                    d.add(but);
                    d.pack();
                    d.setVisible(true);
                    inJFrame();
                }
            }
        }

        @Override
        public void run() {
            startFr.dispose();
            conFr.setLocationRelativeTo(null);
            conFr.setResizable(false);
            conFr.add(new JLabel("Connecting...", SwingConstants.CENTER));
            conFr.setSize(125, 75);
            conFr.setVisible(true);
            start();
            conFr.dispose();
            mainFr = new JFrame();
            mainFr.setSize(800, 600);
            mainFr.setLayout(new BorderLayout());
            outF = new JTextArea();
            outF.setEditable(false);
            outF.setLineWrap(true);
            outF.setWrapStyleWord(true);
            DefaultCaret caret1 = (DefaultCaret) outF.getCaret();
            caret1.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
            JScrollPane scrollP1 = new JScrollPane(outF);
            scrollP1.setBounds(0, 0, mainFr.getWidth(), mainFr.getHeight());
            scrollP1.setPreferredSize(new Dimension(mainFr.getWidth(), 500));
            mainFr.add(scrollP1, BorderLayout.CENTER);
            JPanel p = new JPanel(new FlowLayout());
            inArea = new JTextArea();
            inArea.setLineWrap(true);
            inArea.setWrapStyleWord(true);
            inArea.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
            inArea.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String s = inArea.getText();

                    if (s.trim().length() > 0) {
                        sendStr(s);
                        outF.append("\nYou: " + s);
                        inArea.setText(null);
                    }
                }
            });
            inArea.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK), new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    inArea.append("\n");
                }
            });
            DefaultCaret caret2 = (DefaultCaret) inArea.getCaret();
            caret2.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
            JScrollPane scrollP2 = new JScrollPane(inArea, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            scrollP2.setBounds(p.getX(), p.getY(), p.getWidth(), p.getHeight());
            sendMsg = new JButton("send");
            sendMsg.setEnabled(false);
            p.add(scrollP2, FlowLayout.LEFT);
            p.add(sendMsg);
            mainFr.add(p, BorderLayout.SOUTH);
            mainFr.setResizable(true);
            mainFr.setLocationRelativeTo(null);
            mainFr.setVisible(true);
            scrollP2.setPreferredSize(new Dimension(mainFr.getWidth() - (sendMsg.getWidth() * 2), inArea.getFont().getSize() * 2));
            mainFr.addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    scrollP2.setPreferredSize(new Dimension(mainFr.getWidth() - (sendMsg.getWidth() * 2), inArea.getFont().getSize() * 2));
                }
            });
            mainFr.addWindowStateListener(new WindowStateListener() {
                @Override
                public void windowStateChanged(WindowEvent e) {
                    if (e.getNewState() == JFrame.MAXIMIZED_BOTH || e.getNewState() == JFrame.NORMAL) {
                        scrollP2.setPreferredSize(new Dimension(mainFr.getWidth() - (sendMsg.getWidth() * 2), inArea.getFont().getSize() * 2));
                    }
                }
            });

            mainFr.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            KeyStroke escapeKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
            Action escapeAction = new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    System.exit(0);
                }
            };
            mainFr.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escapeKeyStroke, "ESCAPE");
            mainFr.getRootPane().getActionMap().put("ESCAPE", escapeAction);

            sendRSAKey();
            addOut("CLIENT: RSA decrypted sent!");
            getRSAKey();
            addOut("CLIENT: RSA encrypted received & decrypted!");
            getAESKey();
            addOut("CLIENT: AES double encrypted received & decrypted!");
            sendAESKey();
            addOut("CLIENT: AES double encrypted sent!");
            running = true;
            sendStr(myID);
            addOut("ALL SYSTEMS NORMAL!");
            InThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (running) {
                        String s = getStr();
                        s = rmTime(s);
                        if (s.trim().length() > 0 && (!s.isEmpty() || s != null)) {
                            if (s.contains("(SRV-ID)") && connected == false) {
                                Matcher matcher = Pattern.compile("\\(SRV-ID\\)(.+?)\\(SRV-ID\\)").matcher(s);
                                matcher.find();
                                s = (String) matcher.group(1);
                                myID = s;
                                addOut("Your username has been changed to: " + myID + " by the server!");
                            } else if (s.contains("(SRV)CONNECTED(SRV)") && connected == false) {
                                addOut("You are now securily connected to the server!");
                                connected = true;
                                OutThread.start();
                            } else {
                                addOut(s);
                            }
                        }
                    }
                    OutThread.interrupt();
                }
            });
            OutThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    sendMsg.setEnabled(true);
                    sendMsg.setAction(new AbstractAction() {

                        @Override
                        public void actionPerformed(ActionEvent e) {
                            String s = inArea.getText();
                            if (s.trim().length() > 0) {
                                sendStr(s);
                                outF.append("\nYou: " + s);
                                inArea.setText(null);
                            }
                        }
                    });
                    sendMsg.setText("send");
                    while (running) {
                        try {
                            Thread.sleep(250);
                        } catch (InterruptedException ex) {
                        }
                    }
                    InThread.interrupt();
                }
            });
            InThread.start();
            while (running) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ex) {
                }
            }

            try {
                srvSocket.close();
            } catch (IOException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
            myID = "";
            srvIP = "";
            srvPort = 9002;
            KeyPairGenerator keyGen = null;
            KeyGenerator AESkeyGen = null;

            try {
                keyGen = KeyPairGenerator.getInstance("RSA");
                SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
                keyGen.initialize(2048, random);
                AESkeyGen = KeyGenerator.getInstance("AES");
                AESkeyGen.init(128, random);
                AESkey = AESkeyGen.generateKey();
                srvAES = AESkeyGen.generateKey();
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }

            keyGen.initialize(2048);
            privKey = keyGen.genKeyPair().getPrivate();
            pubKey = keyGen.genKeyPair().getPublic();
            addOut("All encryption keys have been deleted!");

            if (reset) {
                reset();
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
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
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
                    Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
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
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
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
                    Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
                } finally {
                    sOut.flush();
                }
            } catch (IOException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        private void sendStr(String str) {
            if (str.matches("!quit") || str.matches("!q")) {
                sendStr("(STX)" + "close" + "(ETX)");
                addOut("You have disconnected!");
                reset = false;
                running = false;
            } else if (str.matches("!disconnect") || str.matches("!dc")) {
                sendStr("(STX)" + "close" + "(ETX)");
                addOut("You have disconnected!");
                running = false;
                reset = true;
            } else if (str.matches("!l") || str.matches("!list")) {
                sendStr("(STX)" + "listusers" + "(ETX)");
            } else if ((!str.isEmpty() || str != null) && running) {
                str += "(STX)" + (System.currentTimeMillis() / 1000L) + "(ETX)";
                try {
                    Cipher cipher1 = Cipher.getInstance(srvAES.getAlgorithm());
                    Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                    cipher1.init(Cipher.ENCRYPT_MODE, srvAES);
                    cipher2.init(Cipher.ENCRYPT_MODE, AESkey);
                    ObjectOutputStream sOut = new ObjectOutputStream(srvSocket.getOutputStream());
                    sOut.writeObject(cipher2.doFinal(cipher1.doFinal(str.getBytes(StandardCharsets.UTF_8))));
                    sOut.flush();
                } catch (SSLException ex) {
                    if (running) {
                        addOut("You have been disconnected from the server!");
                        running = false;
                    }
                } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        }

        private String getStr() {
            try {
                Cipher cipher1 = Cipher.getInstance(srvAES.getAlgorithm());
                Cipher cipher2 = Cipher.getInstance(AESkey.getAlgorithm());
                cipher1.init(Cipher.DECRYPT_MODE, srvAES);
                cipher2.init(Cipher.DECRYPT_MODE, AESkey);
                String str = new String(cipher2.doFinal(cipher1.doFinal((byte[]) new ObjectInputStream(srvSocket.getInputStream()).readObject())), StandardCharsets.UTF_8);
                return new String(str.getBytes(Charset.defaultCharset()));
            } catch (SocketException ex) {
                if (running) {
                    addOut("You have been disconnected from the server!");
                    running = false;
                }
                reset = true;
            } catch (SSLException | EOFException ex) {
                if (running) {
                    addOut("You have been disconnected from the server!");
                    running = false;
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | IOException | ClassNotFoundException ex) {
                Logger.getLogger(ClientSwing.class.getName()).log(Level.SEVERE, null, ex);
            }
            return "";
        }

        private static String rmTime(String str) {
            String ogStr = str;
            try {
                Matcher matcher = Pattern.compile("\\(STX\\)(.+?)\\(ETX\\)").matcher(str);
                matcher.find();
                return (String) str.subSequence(0, matcher.start(0));
            } catch (IllegalStateException ex) {
            }
            return str;
        }

        private void addOut(String str) {
            if (outF.getText().isEmpty()) {
                outF.setText(str);
            } else {
                outF.append("\n" + str);
            }
        }

        private void inJFrame() {
            valIn = false;
            startFr = new JFrame();
            startFr.setResizable(false);
            startFr.setLocationRelativeTo(null);
            KeyStroke escapeKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0, false);
            Action escapeAction = new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    System.exit(0);
                }
            };
            startFr.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(escapeKeyStroke, "ESCAPE");
            startFr.getRootPane().getActionMap().put("ESCAPE", escapeAction);
            startP = new JPanel();
            JPanel pan1 = new JPanel();
            JPanel pan2 = new JPanel();
            JPanel pan3 = new JPanel();
            startFr.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            startFr.setSize(325, 200);
            startFr.setLayout(new GridLayout());
            JTextField srvIPF = new JTextField(srvIP, 25);
            JLabel str1 = new JLabel("   Server ip:");
            JTextField srvIPp = new JTextField(Integer.toString(srvPort), 25);
            JLabel str2 = new JLabel("Server port:");
            JTextField usrN = new JTextField(myID, 25);
            JLabel str3 = new JLabel("  Username:");
            JButton button1 = new JButton("Connect");
            JButton button2 = new JButton("Exit");

            pan1.add(str1);
            pan1.add(srvIPF);
            pan2.add(str2);
            pan2.add(srvIPp);
            pan3.add(str3);
            pan3.add(usrN);
            startP.add(pan1);
            startP.add(pan2);
            startP.add(pan3);
            startP.add(button1);
            startP.add(button2);
            startFr.add(startP);
            startFr.setVisible(true);
            button1.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    srvIP = srvIPF.getText();
                    String input = srvIPp.getText();
                    if (input.matches("[0-9]+")) {
                        srvPort = Integer.parseInt(input);
                        valIn = true;
                    } else {
                        valIn = false;
                        JDialog d = new JDialog(startFr, "", true);
                        d.setLayout(new FlowLayout());
                        JButton but = new JButton("OK");
                        but.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e1) {
                                d.dispose();
                            }
                        });
                        JLabel str = new JLabel("Invalid port!", SwingConstants.CENTER);
                        d.setLocationRelativeTo(startFr);
                        d.setResizable(false);
                        d.add(str);
                        d.add(but);
                        d.setSize(150, 75);
                        d.setVisible(true);
                    }
                    myID = usrN.getText();
                    if (myID.isEmpty()) {
                        valIn = false;
                        JDialog d = new JDialog(startFr, "", true);
                        d.setLayout(new FlowLayout());
                        JButton but = new JButton("OK");
                        but.addActionListener(new ActionListener() {
                            @Override
                            public void actionPerformed(ActionEvent e1) {
                                d.dispose();
                            }
                        });
                        JLabel str = new JLabel("Username can not be empty!", SwingConstants.CENTER);
                        d.setLocationRelativeTo(startFr);
                        d.setResizable(false);
                        d.add(str);
                        d.add(but);
                        d.setSize(150, 75);
                        d.setVisible(true);
                    } else {
                        valIn = true;
                    }

                }
            });
            button2.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    System.exit(0);
                }
            });
            while (!valIn) {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ex) {
                }
            }
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
