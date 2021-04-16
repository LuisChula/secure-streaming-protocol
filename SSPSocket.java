import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Random;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class SSPSocket {
	private final byte SEPARATOR = 0x40;

	private DatagramSocket s;
	private int counterID;
	private Random generator = new Random();
	private CryptoStuff cs;

	// 1 fase
	public SSPSocket(SocketAddress addr, String file) throws Exception {
		s = new DatagramSocket(addr);
        counterID = 0;
        cs = new CryptoStuff(file, true);
	}

	public SSPSocket(String file) throws Exception {
		s = new DatagramSocket();
        counterID = 0;
        cs = new CryptoStuff(file, true);
	}
	
	// 2 fase
	public SSPSocket(SocketAddress addr) throws Exception {
		s = new DatagramSocket(addr);
        counterID = 0;
        cs = new CryptoStuff();
	}
	
	public void setCryptoStuff(String file) throws Exception {
		cs = new CryptoStuff(file, false);
	}

	
	public CryptoStuff getCS() {
		return cs;
	}

	public DatagramSocket getSocket() {
		return s;
	}

	public byte[] getHeader(int payloadSize, byte shp) {
		byte[] bytes = ByteBuffer.allocate(4).putInt(payloadSize).array();
		byte[] header = new byte[] 
		{
			0x01, shp,  // version info
			0x01,       // content type
			0x00,	    // payload type
			bytes[0], bytes[1], bytes[2], bytes[3] //payload size
		};
		return header;
	}

	private byte[] getMP(byte[] m, int size) {
		byte[] id = ByteBuffer.allocate(4).putInt(counterID++).array();
		int i = generator.nextInt();
		System.out.println("NONCE: " + i);
		byte[] nonce = ByteBuffer.allocate(4).putInt(i).array();
		System.out.println("Len: " + (nonce.length + id.length + size));
		byte[] mp = ByteBuffer
			        .allocate(id.length + nonce.length + size)
			        .put(id).put(nonce).put(Arrays.copyOfRange(m, 0, size))
			        .array();

		return mp;
	}
	
	private byte[] getC(byte[] mp, byte[] mac1) throws Exception {
		byte[] input = ByteBuffer
		        .allocate(mp.length + mac1.length)
		        .put(mp).put(mac1)
		        .array();
		
		return cs.encrypt(input);
	}
	
	private byte[] getPayload(byte[] c, byte[] mac2) {
		byte[] output = ByteBuffer
		        .allocate(c.length + mac2.length)
		        .put(c).put(mac2)
		        .array();
		
		return output;
	}

	public void send(DatagramPacket p) throws Exception {
		send(p, (byte)0x00);
	}

	public void send(DatagramPacket p, byte shp) throws Exception {
		byte[] data = p.getData();
		int size = p.getLength();
		int offset = p.getOffset();
		System.out.println("I Size:"+size);
		byte[] header = getHeader(size, shp);
		byte[] mp = getMP(data, size);
		System.out.println("MP: " + mp.length);
		System.out.println("MP: " + mp[0] + " " + mp[1] + " " + mp[2]);
		byte[] mac1 = mp.clone();
		mac1 = cs.tamperedWithMac1(mac1);
		System.out.println("Mac1: " + mac1.length);
		// System.out.println("mac1: " + mac1[0] + " " + mac1[1] + " " + mac1[2]);
		byte[] c = getC(mp, mac1);
		System.out.println("C: " + c.length);
		byte[] mac2 = c.clone();
		mac2 = cs.tamperedWithMac2(mac2);
		System.out.println("Mac2: " + mac2.length);
		byte[] payload = getPayload(c, mac2);
		
		size = header.length + payload.length;
		System.out.println("Header: " + header.length);
		System.out.println("Payload: " + payload.length);
		
		byte[] message = ByteBuffer
		        .allocate(size)
		        .put(header).put(payload)
		        .array();
		
		p.setData(message, 0, size);
		
		System.out.println("F Size:"+size);
		System.out.println("=============");
		
		s.send(p);
	}

	public void receive(DatagramPacket p) throws Exception {
		s.receive(p);

		byte[] buff = p.getData();
		int size = p.getLength();
		int offset = p.getOffset();
		System.out.println("-------");
		System.out.println(size);

		byte[] data = p.getData();
		byte[] header = Arrays.copyOfRange(data, 0, 8);
		int mac2Length = cs.getMac2Length();
		byte[] c = Arrays.copyOfRange(data, 8, size - mac2Length);
		byte[] mac2 = Arrays.copyOfRange(data, size - mac2Length, size);

		byte[] messageHash = cs.tamperedWithMac2(c);
		if(!MessageDigest.isEqual(mac2, messageHash)) {
			System.out.println("Message got tampered!");
			System.exit(-1);
		}
		System.out.println("C: " + c.length);
		System.out.println("Mac2: " + mac2.length);
		c = cs.decrypt(c);

		int mac1Length = cs.getMac1Length();
		byte[] mp = Arrays.copyOfRange(c, 0, c.length - mac1Length);
		byte[] mac1 = Arrays.copyOfRange(c, c.length - mac1Length, c.length);
		messageHash = cs.tamperedWithMac1(mp);
		if(!MessageDigest.isEqual(mac1, messageHash)) {
			System.out.println("MP got tampered!");
			System.exit(-1);
		}
		System.out.println("MP: " + mp.length);

		byte[] message = Arrays.copyOfRange(mp, 8, mp.length);

		p.setData(message, 0, message.length);

	}
}