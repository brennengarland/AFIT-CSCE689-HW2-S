#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"
#include <string>
#include <sstream>

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::vector<uint8_t> passwd, salt;
   std::cout << "Checking user\n";

   bool result = findUser(name, passwd, salt);
   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the hash and salt
   if (!findUser(name, userhash, salt))
      return false;  // User did not exist

   std::cout << "User Found!\n";

   // Hash the input password to check against the read hash
   hashArgon2(passhash, salt, passwd, &salt);

   // Correct password entered
   if (userhash == passhash)
      return true;

   return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {

   // Insert your insane code here
   FileFD pwfile(_pwd_file.c_str());

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   bool eof = false;
   std::vector<std::string> usernames;
   std::vector<std::vector<uint8_t>> hashes;
   std::vector<std::vector<uint8_t>> salts;
   while (!eof) {
      std::string uname;
      
      if(pwfile.readStr(uname) <= 0)
      {
         eof = true;
      }
      else if(uname == std::string(name))
      {

         srand(time(0));
         std::vector<uint8_t> passhash;
         std::vector<uint8_t> salt;

         hashArgon2(passhash, salt, passwd, NULL);

         usernames.push_back(uname);
         hashes.push_back(passhash);
         salts.push_back(salt);

         std::vector<uint8_t> hash_empty;
         std::vector<uint8_t> salt_empty;
         pwfile.readBytes(hash_empty, 32);
         pwfile.readBytes(salt_empty, 16);
         std::string empty;
         pwfile.readStr(empty);
         

      } else 
      {
         std::vector<uint8_t> passhash;
         std::vector<uint8_t> salt;
         pwfile.readBytes(passhash, 32);
         pwfile.readBytes(salt, 16);
         std::string empty;
         pwfile.readStr(empty);

         usernames.push_back(uname);
         hashes.push_back(passhash);
         salts.push_back(salt);
      }    
      
   }

   pwfile.closeFD();


   if (!pwfile.openFile(FileFD::writefd))
      throw pwfile_error("Could not open passwd file for writing");

   for(int i = 0; i < hashes.size(); i++) {
      pwfile.writeFD(usernames.at(i).c_str());
      pwfile.writeByte('\n');
      pwfile.writeBytes(hashes.at(i));
      pwfile.writeBytes(salts.at(i));
      pwfile.writeByte('\n');
   }

   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Read Username
   ssize_t read = pwfile.readStr(name);

   // Error Checking
   if(read == -1) {
      throw pwfile_error("Could not read, file corrupted");
   } else if(read == 0) {
      // File is empty
      return false;
   }
   
   // Read Salt and hash
   pwfile.readBytes(hash, 32);
   pwfile.readBytes(salt, 16);

   // Read newline for next username
   std::string empty;
   pwfile.readStr(empty);
   
   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;
      
   // Write username
   if(pwfile.writeFD(name) == -1)
      throw pwfile_error("Error writing username");
   if(pwfile.writeByte('\n') == -1)
      throw pwfile_error("Error writing newline after username");

   results += name.size();

   // Write the hash and salt
   if(pwfile.writeBytes(hash) == -1)
      throw pwfile_error("Error writing hash");
   results += hash.size();
   if(pwfile.writeBytes(salt) == -1)
      throw pwfile_error("Error writing salt");
   results += salt.size();
   if(pwfile.writeByte('\n') == -1)
      throw pwfile_error("Error writing newline after salt");

   results += 2; // Account for newlines

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());
   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }
      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
   std::cout << "Hashing passwd...\n";

   // Create buffers to store the hash and salt
   uint8_t hash[32];
   uint8_t salt[16];

   // Check our input salt
   if(in_salt == NULL) {
      // Seed rand
      srand(time(0));
      // Create random salt
      for(int i = 0; i < 16; i++) {  
         // Chars '!' through '~'
         salt[i] = (rand() % 93 + 33);
      }
   } else if(in_salt->size() < 16) {
      throw std::runtime_error("Incorrect salt size");
   } else {
      // No problems, push the vector into the buffer
      for(int i=0; i < 16; i++) {
         salt[i] = in_salt->at(i);
      }
   }

   argon2i_hash_raw(2, (1<<16), 1, in_passwd, strlen(in_passwd), salt, 16, hash, 32);

   // Clear the return vectors so they are clean
   ret_hash.clear();
   ret_salt.clear();

   // Populate with the salt and hash
   for(int i=0; i < 32; i++)
   {
      ret_hash.push_back(hash[i]);
   }

   for(int i=0; i < 16; i++)
   {
      ret_salt.push_back(salt[i]);
   }

   
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!
   if(!checkUser(name))
   {
      // Create empty vectors that will store the returned hash and salt
      std::vector<uint8_t> passhash;
      std::vector<uint8_t> salt;

      // Open file
      FileFD pwfile(_pwd_file.c_str());
      if (!pwfile.openFile(FileFD::appendfd))
         throw pwfile_error("Could not open passwd file for reading");

      hashArgon2(passhash, salt, passwd, NULL);

      std::string name_str(name);
      writeUser(pwfile, name_str, passhash, salt);

   }
}

