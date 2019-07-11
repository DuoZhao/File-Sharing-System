/* This list represents the users on the server */
import java.util.*;
import java.math.*;

	public class UserList implements java.io.Serializable {
	
		/**
		 * 
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();
		
		public synchronized void addUser(String username)
		{
			User newUser = new User();
			list.put(username, newUser);
		}
		
		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}
		
		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}
		
		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}
		
		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}
		
		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}
		
		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}
		
		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}
		
		public synchronized void setPass(String user, byte[] salt, BigInteger passwordMod){
				if(!checkUser(user)) {
				return;
			}
			list.get(user).setPass(salt,passwordMod);
		}
		
		public synchronized BigInteger getPass(String user){
			if(!checkUser(user)) {
				return null;
			}
			return list.get(user).getPass();
		}
		
		public synchronized byte[] getSalt(String user){
			if(!checkUser(user)) {
				return null;
			}
			return list.get(user).getSalt();
		}
	
	class User implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private BigInteger passwordMod;
		private byte[] salt;
		
		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}
		
		public ArrayList<String> getGroups()
		{
			return groups;
		}
		
		public ArrayList<String> getOwnership()
		{
			return ownership;
		}
		
		public void addGroup(String group)
		{
			groups.add(group);
		}
		
		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
		public void addOwnership(String group)
		{
			//owner should also be in the group
			ownership.add(group);
			if(!groups.contains(group))
			{
				groups.add(group);
			}
		}
		
		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}
		
		public void setPass(byte[] salt, BigInteger passwordMod){
			this.salt=salt;
			this.passwordMod=passwordMod;
		}
		
		public byte[] getSalt(){
			return this.salt;
		}
		
		public BigInteger getPass(){
			return this.passwordMod; 
		}
		
	}
	
}	
