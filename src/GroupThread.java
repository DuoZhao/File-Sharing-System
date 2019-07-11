/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

//for SRP
import java.math.*;
import javax.crypto.spec.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;


public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	private PrivateKey key_g_private;
	private Crypto crypto;
	private String user_name;
	private boolean startConversation;
	private int sequence = 0; 
	
	//for SRP 
	private SecretKey K;
	private byte[] iv;
	private byte[] c1;
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
	
	// for hmac
	private byte[] hKey;
	
	public GroupThread(Socket _socket, GroupServer _gs, PrivateKey key)
	{
		socket = _socket;
		my_gs = _gs;
		key_g_private = key;
		crypto = new Crypto();
		K = null;
		startConversation = false;
	}
	
	public void run()
	{
		boolean proceed = true;
		K = null;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message;
				if(!startConversation)
				{
					message = (Envelope)input.readObject();
					this.sequence++;
					if(message.getSequence() != this.sequence){
						System.out.println("Invalid sequence number");
						socket.close();
						proceed = false;
					}
				}else{
					byte[] tempbyte = (byte[])input.readObject();
					ArrayList<byte[]> result = (ArrayList)crypto.byteArrayToObject(tempbyte);
					byte[] hmacClient = result.get(1);
					byte[] hmacThread = crypto.hmac(result.get(0), hKey);
					if(!Base64.getEncoder().encodeToString(hmacClient).equals(Base64.getEncoder().encodeToString(hmacThread)))
					{
						System.out.println("The HMAC from the Client is not the same as the Server");
						socket.close();
					}
					message = (Envelope)crypto.aes_decrypt_obj(result.get(0), K);

					
					this.sequence++;
					if(message.getSequence() != this.sequence){
						System.out.println("Invalid sequence number");
						socket.close();
						proceed = false;
					}
				}

				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null || K == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
						if(K==null){
							System.out.println("Session Key Empty");
						}
					}
					else
					{
						String fs_key = (String)message.getObjContents().get(1);
						UserToken yourToken = createToken(fs_key); //Create a token
						byte[] signature = crypto.rsa_sign_token((Token)yourToken, key_g_private);
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						response.addObject(signature);
						output.reset();

						
						this.sequence++;
						response.setSequence(this.sequence);
						output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
					}
				}
				else if(message.getMessage().equals("SRP"))
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								BigInteger A = (BigInteger)message.getObjContents().get(1);
							
								//pass the server's credentials to client
								BigInteger B = genServerCredentials(A);
								
								c1 =new byte[16]; //choose the challenge to be 128 bits 
								SecureRandom random = new SecureRandom();
								random.nextBytes(c1);
								if(B != null){
									response = new Envelope("OK");
									response.addObject(B);
									//add challenge c1
									response.addObject(c1);
								}
							}
						}
					}	
					this.sequence++; 
					response.setSequence(this.sequence);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("SALT"))
				{
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response =new Envelope("FAIL");
						
						if(message.getObjContents().get(0)!=null)
						{
							String username =(String) message.getObjContents().get(0);
							user_name = username;
							byte[] s = my_gs.userList.getSalt(user_name);
							response.addObject(s);
						}
					}
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CHALLENGERES"))
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0)!=null)
						{
							if(message.getObjContents().get(1)!=null)
							{
								// Crypto crypto =new Crypto(); 
								byte[] c1_encrypt = (byte[])message.getObjContents().get(0);
								byte[] c2 =(byte[])message.getObjContents().get(1);
								
								byte[] c1_decrypt = crypto.aes_cbc_decrypt(K,c1_encrypt);
								
								if(!Arrays.equals(c1,c1_decrypt)){
									//c1 between client and server does not match
									output.writeObject(response);
								}
								
								response = new Envelope("OK");
								response.addObject(crypto.aes_cbc_encrypt(K,c2));
								startConversation = true;
									
									this.sequence++;
									response.setSequence(this.sequence);
								output.writeObject(response);
							}
						}
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2)!=null)
								{
									if(message.getObjContents().get(3)!=null)
									{
										String username = (String)message.getObjContents().get(0); //Extract the username
										// BigInteger password
										BigInteger v = (BigInteger)message.getObjContents().get(1);
										byte[] s = (byte[])message.getObjContents().get(2);
										UserToken yourToken = (UserToken)message.getObjContents().get(3); //Extract the token
								
										if(createUser(username, v, s, yourToken))
										{
											response = new Envelope("OK"); //Success
										}
									}
								}
							}
						}
					}

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));

				   
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);

								ArrayList<String> mlist=listMembers(groupname, yourToken);
								response = new Envelope("OK"); 
								response.addObject(mlist);
								
							}
						}
					}
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));

				}

				else if(message.getMessage().equals("LGROUPS")) //Client wants a list of groups a member joined
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								ArrayList<String> gList=listGroups(groupname, yourToken);
								response = new Envelope("OK"); //Success
								response.addObject(gList);
								
							}
						}
					}
					

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));

				    /* TODO:  Write this handler */
					
				}

				else if(message.getMessage().equals("LOWNEDGROUPS")) //Client wants a list of groups a member joined
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								ArrayList<String> gList=listOwnedGroups(groupname, yourToken);
								response = new Envelope("OK"); //Success
								response.addObject(gList);
								
							}
						}
					}
					

					

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				    /* TODO:  Write this handler */
					
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						System.out.println("Object Contents less than 3");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = (String)message.getObjContents().get(0);
									String groupname = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									
									if(addUserToGroup(username,groupname,yourToken))
									{
										response = new Envelope("OK");	//Success
									}
								}
							}
						}
					}

					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
						
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								if(message.getObjContents().get(2) != null)
								{
									String username = (String)message.getObjContents().get(0);
									String groupname = (String)message.getObjContents().get(1);
									UserToken yourToken = (UserToken)message.getObjContents().get(2);
									
									if(deleteUserFromGroup(username,groupname,yourToken))
									{
										response = new Envelope("OK");
									}
								}
							}
						}
					}
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				}
				else if(message.getMessage().equals("GETGROUPKEYS")) //Client wants a list of members in a group
				{
				    if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0);
								UserToken yourToken = (UserToken)message.getObjContents().get(1);

								ArrayList<SecretKey> groupKeys = getGroupKeys(groupname, yourToken);
								response = new Envelope("OK"); 
								response.addObject(groupKeys);
								
							}
						}
					}
					
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(crypto.encrypt_aes_hmac(response, K, hKey));
				}
				
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					this.sequence++;
					response.setSequence(this.sequence);
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private UserToken createToken(String fs_key) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(user_name))
		{

			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, user_name, my_gs.userList.getUserGroups(user_name), fs_key);
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	private ArrayList<String> listGroups(String username, UserToken token) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			ArrayList<String> glist=my_gs.groupList.getMemberGroups(username);
			return glist;
		}
		else
		{
			return null;
		}
	}

	private ArrayList<String> listOwnedGroups(String username, UserToken token) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			ArrayList<String> olist=my_gs.userList.getUserOwnership(username);
			return olist;
		}
		else
		{
			return null;
		}
	}



	private boolean createGroup(String groupname, UserToken token){
		String requester = token.getSubject();
		if(my_gs.groupList.checkGroup(groupname))
		{
			System.out.println("Groupname "+groupname+" has already been occupied. ");
			return false;
		}
		else if(groupname.contains("`") || groupname.contains((char)0x00 + "")){
			System.out.println("Group name contains invalid character.");
			return false;
		}
		else
		{
			my_gs.groupList.addGroup(groupname);
			my_gs.groupList.setOwner(requester, groupname);
			my_gs.userList.addOwnership(requester, groupname);
			my_gs.groupList.addGroupKey(groupname);
			return true;
		}

	}
	
	
	//Method to create a user
	private boolean createUser(String username,BigInteger v , byte[] s, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					System.out.println("User already exists!");
					return false; //User already exists
				}
				else if(username.contains((char)0x00 + "")){
					System.out.println("Username contains invalid character.");
					return false;
				}
				else
				{
					my_gs.userList.addUser(username);
					my_gs.userList.setPass(username,s,v);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}
					
					//Delete the user from the groups
					//If user is the owner, removeMember will automatically delete group!
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), null);
					}
					
					//If the user is in these groups, these groups add a new group key
					for(int index = 0; index < deleteFromGroups.size(); index++)
					{
						my_gs.groupList.addGroupKey(deleteFromGroups.get(index));
					}
					
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean deleteGroup(String groupname, UserToken token){
		String requester = user_name;
		//check group existance
		if(my_gs.groupList.checkGroup(groupname)){
			ArrayList<String> temp;
			if(my_gs.userList.checkUser(requester)){
				temp = my_gs.userList.getUserGroups(requester);
				//can delete group only if requester is ADMIN or owner of the group
				if(temp.contains("ADMIN") || my_gs.groupList.getGroupOwner(groupname).equals(requester)){
					ArrayList<String> members=my_gs.groupList.getGroupMembers(groupname);
					for(int i=0;i<members.size();i++){
						my_gs.userList.removeGroup(members.get(i), groupname);
					}
					my_gs.groupList.deleteGroup(groupname);
				}
				return true;
			}
		}
		
		return false;
		
	}
	
	private boolean addUserToGroup(String username, String groupname, UserToken yourToken )
	{
		// if he is the group owner, then he is abele to add user to group 
		
		String requester = yourToken.getSubject();
		
		//check if group exists, if the group not exists, return false
		if(!my_gs.groupList.checkGroup(groupname))
		{
			System.out.println("Group does not exit");
			return false; 
		}else if(!my_gs.userList.checkUser(username))
		{
			System.out.println("User does not exist");
			return false;
		}else if(my_gs.userList.getUserGroups(username).contains(groupname))
		{
			System.out.println("User is already in the group "+ groupname);
			return false;
		} else if(!my_gs.userList.getUserOwnership(requester).contains(groupname) && !my_gs.groupList.checkMembership("ADMIN", requester))	//user is not the owner of the group
		{
			System.out.println("User is not the owner of the group, so he cannot add users to this group");
			return false;
		}
		
		my_gs.userList.addGroup(username, groupname);
		my_gs.groupList.addMember(username, groupname);
		
		return true;
	}
	
	private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken)
	{
		// if he is the group owner, then he is abele to delete user from the group 
		
		String requester = yourToken.getSubject();
		
		//check if user exists, if the user not exists, return false
		if(!my_gs.userList.checkUser(username))
		{
			System.out.println("User does not exit");
			return false;
		}
		
		//check if group exists, if the user not exists, return false
		if(!my_gs.groupList.checkGroup(groupname))
		{
			System.out.println("Group does not exist");
			return false; 
		}
		else if(!my_gs.userList.getUserGroups(username).contains(groupname))
		{
			System.out.println("User is not in the group "+ groupname);
			return false;
		} else if(!my_gs.userList.getUserOwnership(requester).contains(groupname) && !my_gs.groupList.checkMembership("ADMIN", requester))	//user is not the owner of the group
		{
			System.out.println("User is not the owner of the group, so he cannot add users to this group");
			return false;
		}
	
		my_gs.userList.removeGroup(username, groupname);
		my_gs.groupList.removeMember(username, groupname);
		my_gs.groupList.addGroupKey(groupname);
		
		return true;
	}
	
	private ArrayList<String> listMembers(String groupname, UserToken token)
	{
		String requester = token.getSubject();
		ArrayList<String> temp=my_gs.userList.getUserGroups(requester);
		for(String a: temp){
			System.out.println(a);
		}
		//if the requester is in the group
		if(my_gs.userList.getUserGroups(requester).contains(groupname))
		{
			ArrayList<String> member_list = my_gs.groupList.getGroupMembers(groupname);
			return member_list;
		}
		
		System.out.println(requester+" not in group "+groupname);
		return null; 
	}
	
	private BigInteger genServerCredentials(BigInteger A){
		Security.addProvider(new BouncyCastleProvider());
	    SRP6Server server = new SRP6Server();
		SecureRandom random = new SecureRandom();
		server.init(N,g,my_gs.userList.getPass(user_name),new SHA256Digest(),random);
		BigInteger B = server.generateServerCredentials();
		BigInteger S = null;
		try{
			S = server.calculateSecret(A);
			// System.out.println("********************************");
			// System.out.println("GroupThread calcultae the secret: "+S.toString(16));
			// System.out.println("********************************");
		}catch(CryptoException e){
			System.out.println(e.getMessage());
		}
		
		K = new SecretKeySpec(S.toByteArray(), 0, 32, "AES");
		hKey = crypto.hmacKey(S);
		System.out.print("*****Key from Server*****");
		System.out.println(Base64.getEncoder().encodeToString(hKey));
		// System.out.println(K.hashCode());
		return B;
	}
	
	private ArrayList<SecretKey> getGroupKeys(String groupname, UserToken token)
	{
		String requester = token.getSubject();
		//check if the user is in the group
		if(!my_gs.userList.getUserGroups(requester).contains(groupname))
		{
			return null;
		}
		return my_gs.groupList.getGroupKeys(groupname);
	}
}
