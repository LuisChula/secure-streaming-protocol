import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

public class Message implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private List<byte[]> m;
	
	public Message() {
		m = new LinkedList<byte[]>();
	}
	
	public void add(byte[] bytes) {
		m.add(bytes);
	}
	
	public List<byte[]> getMessage() {
		return m;
	}
	
	public void add(int index, byte[] b) {
		m.add(index, b);
	}

}
