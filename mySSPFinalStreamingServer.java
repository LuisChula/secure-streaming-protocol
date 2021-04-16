/*
 * hjStreamServer.java 
 * Streaming server: streams video frames in UDP packets
 * for clients to play in real time the transmitted movies
 */
import java.io.*;
import java.net.*;

class mySSPFinalStreamingServer {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Erro, usar: mySSPFinalStreamingServer <ip-multicast-address> <port>");
            System.out.println("        or: mySSPFinalStreamingServer <ip-unicast-address> <port>");
            System.exit(-1);
        }
        
        int size;
        int count = 0;
        long time;
        byte[] buff = new byte[4096];

        SSHSocket s = new SSHSocket("dataBase.conf");
        String movie = s.getMovie();
        DataInputStream g = new DataInputStream(new FileInputStream(movie));
        
        InetSocketAddress addr = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
        DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
        long t0 = System.nanoTime(); // tempo de referencia para este processo
        long q0 = 0;

        while (g.available() > 0) {
            size = g.readShort();
            time = g.readLong();
            if (count == 0) q0 = time; // tempo de referencia no stream
            count += 1;
            g.readFully(buff, 0, size);
            p.setData(buff, 0, size);
            p.setSocketAddress(addr);
            long t = System.nanoTime();
            Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

            // send packet (with a frame payload)
            // Frames sent in clear (no encryption)
            s.send(p);
            System.out.print(".");
        }

        System.out.println("DONE! all frames sent: " + count);
    }
}