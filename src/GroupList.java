/* This list represents the group on the server */
import java.util.*;
import javax.crypto.*;

	public class GroupList implements java.io.Serializable {
		// my_gs.groupList.removeMember(username, deleteFromGroups.get(index));

		private static final long serialVersionUID = 7600343803563417100L;
	
		
		private Hashtable<String, Group> list = new Hashtable<String, Group>();

		public synchronized int getSize()
		{
			return list.size();
		}

		public synchronized void listGroups(){
			Set<String> keys = list.keySet();
			System.out.println("the Groups:");
			for(String groupname: keys){
				System.out.println(groupname);
			}		
		}

		public synchronized ArrayList<String> getMemberGroups(String username)
		{
			ArrayList<String> glist=new ArrayList<String>();
			Set<String> keys = list.keySet();
			for(String groupname: keys){
				if(list.get(groupname).checkMember(username)){
					glist.add(groupname);
				}
			}
			return glist;
		}
		
		// add member into a group 
		public synchronized void addMember(String username, String groupname)
		{
			list.get(groupname).addMember(username);
		}
		
		//remove a user from the group 
		public synchronized void removeMember(String username, String groupname)
		{
	       list.get(groupname).removeMember(username);
		}
		
		//add a new group
		public synchronized void addGroup(String groupname)
		{
			Group newGroup = new Group();
			list.put(groupname, newGroup);
			System.out.println("Add group " + groupname +" Successful!");
		}
		
		//delete a specific group 
		public synchronized void deleteGroup(String groupname)
		{
			list.remove(groupname);
		}
		
		//check if a group exist 
		public synchronized boolean checkGroup(String groupname)
		{
			if(list.containsKey(groupname))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		public synchronized boolean checkMembership(String groupname, String username){
			return list.get(groupname).checkMember(username);
		}
		
		//get members in a specific group 
		public synchronized ArrayList<String> getGroupMembers(String groupname)
		{
			return list.get(groupname).getMembers();
		}
		
		//get the owner of a group
		public synchronized ArrayList<String> getGroupOwner(String groupname)
		{
			return list.get(groupname).getOwner();
		}

	   
	   //??? How about the ownership of the previous user ??? 
	   public synchronized void setOwner(String username, String groupname)
	   {
		   list.get(groupname).setOwner(username);
	   }
	   
	   public synchronized void addGroupKey(String groupname)
	   {
		   list.get(groupname).addGroupKey();
	   }
	   
	   public synchronized ArrayList<SecretKey> getGroupKeys(String groupname)
	   {
		   return list.get(groupname).getGroupKeys();
	   }
		
	
	class Group implements java.io.Serializable {

		/**
		 * 
		 */
		private static final long serialVersionUID = -6699986336399821100L;
		private ArrayList<String> owner;
		private ArrayList<String> members;
		private int versionOfKey;
		private ArrayList<SecretKey> groupKeys; 
		
		public Group()
		{
			owner = new ArrayList<String>();
			members = new ArrayList<String>();
			versionOfKey = -1;
			groupKeys = new ArrayList<SecretKey>();
		}
		
		public ArrayList<String> getOwner()
		{
			return owner;
		}
			
		public ArrayList<String> getMembers()
		{
			return members;
		}
		
		public void addMember(String username)
		{
			members.add(username);
		}
		
		public void removeMember(String username)
		{
			members.remove(username);
		}
		
		public void setOwner(String username)
		{
			if(!members.contains(username)){
				members.add(username);
			}
			owner.add(username);
		}

		public boolean checkMember(String username){
			if(members.contains(username)){
				return true;
			}
			else{
				return false;
			}
		}
		
		public void addGroupKey(){
			versionOfKey++;
			Crypto crypto = new Crypto();
			groupKeys.add(versionOfKey, crypto.gen_AESKey());
		}
		
		public ArrayList<SecretKey> getGroupKeys(){
			return groupKeys; 
		}
	}
	
}	
