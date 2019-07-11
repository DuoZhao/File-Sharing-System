/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.math.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

public class GroupServer extends Server {

	//for SRP 
	private static final BigInteger N = new BigInteger("e438f5f9e266d547f2ce63db4f2ccef46c4f2ebdac1a5eb703ae1ce9"+
					   "afae2100a2ea6922df52d6dbada5ff0c3dc510613275918b6a26b19f"+
					   "c1e5625e58c2a045492a2283da75ec38a9f0748c87b9db06d72c65bd"+
					   "ca21fdf3cc02ac48165d539996d7aa2f99b4a39d370cbaf0e4a07b77"+
					   "49899c3a5d73f54b792094857b3693d3",16);	
					   
	private static final BigInteger g = new BigInteger("c4a04391743a1a270af5bec952a84951229560b5a4b7ca1a24316836"+
					   "b9031943f4f2cb64aa854f7ca9546530ed11dce0f54691baec98b1c6"+
					   "a8de9b80ae96f684c0b84dfdcc505951a896ce3f4d07556e93f00dfd"+
					   "1c64a76c10721afb390ee2af5515fe40d1a0cb97c9eb9162da33981c"+
					   "d9260de4f6721b6421b243d39dc0c412",16);
					   
	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
	public String username;
	public String password;
	private KeyPair g_keys;
	
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created

		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);

			userList = (UserList)userStream.readObject();			

		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Please enter your username: ");
			username = console.next();
			System.out.print("Please enter your password: ");
			password = console.next(); 
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

			SecureRandom random = new SecureRandom();
			byte[] s =new byte[32];
			random.nextBytes(s);
			
			BigInteger x = SRP6Util.calculateX(new SHA256Digest(),N, s, username.getBytes(), password.getBytes());
			userList.setPass(username, s ,g.modPow(x, N));
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		
		//read goup file 
		try
		{
			FileInputStream fis2 = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(fis2);
			groupList = (GroupList)groupStream.readObject();
		}
		catch(FileNotFoundException e)
		{

			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No groups currently exist. Your account will add to the ADMIN group.");
			groupList = new GroupList();
			groupList.addGroup("ADMIN");
			groupList.setOwner(username, "ADMIN");
			groupList.addGroupKey("ADMIN");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		
		PrivateKey private_key = Crypto.gen_key_pair(1024).getPrivate();
		
		//This block listens for connections and creates threads on new connections
		try
		{

			final ServerSocket serverSock = new ServerSocket(port);

			Socket sock = null;
			GroupThread thread = null;

			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this, private_key);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener(GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}		
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.groupList);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);					
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}				
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream.writeObject(my_gs.groupList);				
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				

			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		} while(true);
	}
}
