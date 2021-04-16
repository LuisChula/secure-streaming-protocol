import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;

public class Teste {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		InputStream inputStream = new FileInputStream("configs/SSP-1.conf");
		Properties properties = new Properties();
        properties.load(inputStream);
    	        
        String s = properties.getProperty("SESSION-KEY");
        byte[] x = hexToBytes(s);
        System.out.println(s.length());
        System.out.println(s);
        System.out.println("----------------");
        System.out.println(x.length);
        for(byte b : x) {
        	System.out.print(b+", ");
        }
	}
	
	private static byte[] hexToBytes(String s) {
		String[] bytes = s.split(",");
		byte[] res = new byte[bytes.length];
		for(int i = 0; i < bytes.length; i++) {
			String aux = bytes[i].split("x")[1].substring(0,1);
			System.out.println(aux);
			res[i] = new Integer(Integer.parseInt(aux, 16)).byteValue();
		}
		return res;
	}

}
