#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <sstream>
#include "TCPConn.h"
#include "strfuncts.h"
#include <crypto++/secblock.h>
#include <crypto++/osrng.h>
#include <crypto++/filters.h>
#include <crypto++/rijndael.h>
#include <crypto++/gcm.h>
#include <crypto++/aes.h>
#include <crypto++/hex.h>

using namespace CryptoPP;

// Common defines for this TCPConn
const unsigned int iv_size = AES::BLOCKSIZE;
const unsigned int key_size = AES::DEFAULT_KEYLENGTH;
const unsigned int auth_size = 16;

/**********************************************************************************************
 * TCPConn (constructor) - creates the connector and initializes - creates the command strings
 *                         to wrap around network commands
 *
 *    Params: key - reference to the pre-loaded AES key
 *            verbosity - stdout verbosity - 3 = max
 *
 **********************************************************************************************/

TCPConn::TCPConn(LogMgr &server_log, CryptoPP::SecByteBlock &key, unsigned int verbosity):
                                    _data_ready(false),
                                    _aes_key(key),
                                    _verbosity(verbosity),
                                    _server_log(server_log)
{
   // prep some tools to search for command sequences in data
   uint8_t slash = (uint8_t) '/';
   c_rep.push_back((uint8_t) '<');
   c_rep.push_back((uint8_t) 'R');
   c_rep.push_back((uint8_t) 'E');
   c_rep.push_back((uint8_t) 'P');
   c_rep.push_back((uint8_t) '>');

   c_endrep = c_rep;
   c_endrep.insert(c_endrep.begin()+1, 1, slash);

   c_ack.push_back((uint8_t) '<');
   c_ack.push_back((uint8_t) 'A');
   c_ack.push_back((uint8_t) 'C');
   c_ack.push_back((uint8_t) 'K');
   c_ack.push_back((uint8_t) '>');

   c_auth.push_back((uint8_t) '<');
   c_auth.push_back((uint8_t) 'A');
   c_auth.push_back((uint8_t) 'U');
   c_auth.push_back((uint8_t) 'T');
   c_auth.push_back((uint8_t) '>');

   c_endauth = c_auth;
   c_endauth.insert(c_endauth.begin()+1, 1, slash);

   c_sid.push_back((uint8_t) '<');
   c_sid.push_back((uint8_t) 'S');
   c_sid.push_back((uint8_t) 'I');
   c_sid.push_back((uint8_t) 'D');
   c_sid.push_back((uint8_t) '>');

   c_endsid = c_sid;
   c_endsid.insert(c_endsid.begin()+1, 1, slash);
}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   // Accept the connection
   bool results = _connfd.acceptFD(server);


   // Set the state as waiting for the authorization packet
   _status = s_connected;
   _connected = true;
   return results;
}

/**********************************************************************************************
 * sendData - sends the data in the parameter to the socket
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendData(std::vector<uint8_t> &buf) {
   
   _connfd.writeBytes<uint8_t>(buf);
   
   return true;
}

/**********************************************************************************************
 * sendEncryptedData - sends the data in the parameter to the socket after block encrypting it
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

bool TCPConn::sendEncryptedData(std::vector<uint8_t> &buf) {

   // Encrypt
   encryptData(buf);

   // And send!
   return sendData(buf);
}

/**********************************************************************************************
 * encryptData - block encrypts data and places the results in the buffer in <ID><Data> format
 *
 *    Params:  buf - where to place the <IV><Data> stream
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

void TCPConn::encryptData(std::vector<uint8_t> &buf) {
   // For the initialization vector
   SecByteBlock init_vector(iv_size);
   AutoSeededRandomPool rnd;

   // Generate our random init vector
   rnd.GenerateBlock(init_vector, init_vector.size());

   // Encrypt the data
   CFB_Mode<AES>::Encryption encryptor;
   encryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   std::string cipher;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(encryptor, new StringSink(cipher)));

   // Now add the IV to the stream we will be sending out
   std::vector<uint8_t> enc_data(init_vector.begin(), init_vector.end());
   enc_data.insert(enc_data.end(), cipher.begin(), cipher.end());
   buf = enc_data;
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   try {

      switch(_status)
      {
         //CLIENT: I've just connected. Send my SID- this is my identity and indicates I want to set up a connection.
         case s_connecting:
            //std::cout << "CLIENT: Sending SID\n";
            sendSID();
            _status = c_waitForSID;
            break;

         //SERVER: A client has connected. Wait to recieve their SID, send them our SID, then send them a challenge.
         case s_connected:
           //std::cout << "SERVER: Waiting for SID\n";
            if(waitForSID())
            {
               //std::cout << "SERVER: Sending SID to " << getNodeID() <<"\n";
               sendSID();
               //usleep(1000);
               //std::cout << "SERVER: Sending Challenge to " << getNodeID() <<"\n";
               sendChallenge();
               _status = s_waitForResponse;
            }
            break;

         //CLIENT: Wait for SID from server
         case c_waitForSID:
            //std::cout << "CLIENT: Waiting for SID from Server\n";
            if(waitForSID())
            {
               //std::cout << "CLIENT: Recieved SID from server " << getNodeID() <<", waiting for challenge.\n";
               //SID recieved, wait for challenge.
               _status = c_waitforchallenge;
            }
            break;

         //CLIENT: Wait for challenge from server, then send response.
         case c_waitforchallenge:
            //std::cout << "CLIENT: Waiting for challenge from " << getNodeID() << "\n";
            if(waitForChallenge()) {_status = c_sendChallenge;}
            break;

         //SERVER: Challenge sent, wait for response.
         case s_waitForResponse:
            //std::cout << "SERVER: Waiting for challenge response from " << getNodeID() << "\n";
            if(waitForResponse()) {_status = s_waitForChallenge;}
            break;

         //CLIENT: Response sent, send challenge.
         case c_sendChallenge:
            //std::cout << "CLIENT: Sending challenge to " << getNodeID() << "\n";
           //usleep(1000);
            sendChallenge();
            _status = c_waitForResponse;
            break;

         //SERVER: Response recieved, wait for challenge (then send response)
         case s_waitForChallenge:
            //std::cout << "SERVER: Waiting for challenge from client " << getNodeID() << "\n";
            if(waitForChallenge()) {_status = s_datarx;}
            break;

         //CLIENT: Wait for challenge response
         case c_waitForResponse:
            //std::cout << "CLIENT: Waiting for challenge response from server " << getNodeID() << "\n";
            if(waitForResponse()) {_status = s_datatx;}
            break;

         //CLIENT: Response recieved, send data.
         case s_datatx:
            //std::cout << "CLIENT: Response recieved, transmitting data to " << getNodeID() << "\n";
            //usleep(1000);
            //std::cout << "\n----Transmitting data-----\n";
            transmitData();
            break;

         //SERVER: Wait for data from client (then send ack and disconnect)
         case s_datarx:
            //std::cout << "SERVER: Waiting for data from client " << getNodeID() << "\n";
            waitForData();
            break;

         //CLIENT: Wait for ack that data was recieved, then disconnect
         case s_waitack:
            //std::cout << "CLIENT: Waiting for ACK from server " << getNodeID() << "\n";
            awaitAck();
            break;

         // SERVER Data received and conn disconnected, but waiting for the data to be retrieved
         case s_hasdata:
            //std::cout << "SERVER: Data recieved and disconnected from " << getNodeID() << "\n";
            //std::cout << "\n----SERVER HAS DATA----\n";
            break;

         //Default/invalid status
         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.\n";
      disconnect();
      return;
   }

}

/**********************************************************************************************
 * sendSID()  - Client: after a connection, client sends its Server ID to the server
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::sendSID() {
   std::vector<uint8_t> buf(_svr_id.begin(), _svr_id.end());
   wrapCmd(buf, c_sid, c_endsid);
   sendData(buf);
}

/**********************************************************************************************
 * waitForSID()  - receives the SID and sends our SID
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::waitForSID() {

   // If data on the socket, should be our Auth string from our host server
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf))
         return false;


      if (!getCmdData(buf, c_sid, c_endsid)) {
         std::stringstream msg;
         msg << "SID string from connecting client invalid format. Cannot authenticate.";
         //msg << "(" << std::string(buf.begin(), buf.end()) << ")\n";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
         disconnect();
         return false;
      }


      std::string node(buf.begin(), buf.end());
      setNodeID(node.c_str());

      return true;
   }
   return false;
}


/**********************************************************************************************
 * transmitData()  - Transmits data from client to server.
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::transmitData() {

   
      sendEncryptedData(_outputbuf);
      //sendData(_outputbuf);

      if (_verbosity >= 3)
         std::cout << "Successfully authenticated connection with " << getNodeID() <<
                      " and sending replication data.\n";

      // Wait for their response
      _status = s_waitack;

      // std::stringstream msg;
      // msg << _svr_id << ": Transmitted data. Awaiting response.";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";
   
}


/**********************************************************************************************
 * waitForData - receiving server, authentication complete, wait for replication datai
               Also sends a plaintext random auth string of our own
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::waitForData() {

   // If data on the socket, should be replication data
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getEncryptedData(buf))
         return;

   
      //decryptData(buf);
      //std::string debugStr(buf.begin(), buf.end());

      if (!getCmdData(buf, c_rep, c_endrep)) {
         std::stringstream msg;
         msg << "Replication data possibly corrupted from" << getNodeID() << "\n";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";

         disconnect();
         return;
      }

      // Got the data, save it
      _inputbuf.clear();
      _inputbuf = buf;
      _data_ready = true;

      // Send the acknowledgement and disconnect
      sendEncryptedData(c_ack);
      //sendData(c_ack);

      if (_verbosity >= 2)
         std::cout << "Successfully received replication data from " << getNodeID() << "\n";


      disconnect();
      _status = s_hasdata;

      // std::stringstream msg;
      // msg << _svr_id << ": Data recieved, disconnecting.";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";
   }
   else
   {
      _data_ready = false;
   }
}


/**********************************************************************************************
 * awaitAwk - waits for the awk that data was received and disconnects
 *
 *    Throws: socket_error for network issues, runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::awaitAck() {

   // Should have the awk message
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getEncryptedData(buf))
         return;

      //decryptData(buf);
      std::string debugStr(buf.begin(), buf.end());
      
      if (findCmd(buf, c_ack) == buf.end())
      {
         std::stringstream msg;
         msg << "Ack expected from data send, received something else. Node:" << getNodeID() << "\n";
         //msg << "(" << std::string(buf.begin(), buf.end()) << ")\n";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
      }
  
      if (_verbosity >= 3)
         std::cout << "Ack received from " << getNodeID() << ". Disconnecting.\n";

      // std::stringstream msg;
      // msg << _svr_id << ": Recieved ACK";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";

 
      disconnect();
   }
}

/**********************************************************************************************
 * getData - Reads in data from the socket and checks to see if there's an end command to the
 *           message to confirm we got it all
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false if they lost connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getData(std::vector<uint8_t> &buf) {

   std::vector<uint8_t> readbuf;
   size_t count = 0;

   buf.clear();
  // std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Clearing passed in buffer.\n";

   while (_connfd.hasData()) {
      // read the data on the socket up to 1024
      //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Reading data on socket.\n";
      count += _connfd.readBytes<uint8_t>(readbuf, 1024);

      // check if we lost connection
      if (readbuf.size() == 0) {
        // std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Connection lost.\n";
         std::stringstream msg;
         std::string ip_addr;
         msg << "Connection from server " << _node_id << " lost (IP: " << 
                                                         getIPAddrStr(ip_addr) << ")"; 
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
         disconnect();
         return false;
      }

      //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Inserting read values into buffer\n";
      buf.insert(buf.end(), readbuf.begin(), readbuf.end());

      // std::stringstream msg;
      // msg << _svr_id << ": Recieved data.";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";

      // concat the data onto anything we've read before
//      _inputbuf.insert(_inputbuf.end(), readbuf.begin(), readbuf.end());
   }
   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "No more data on _connFD\n";
   return true;
}

/**********************************************************************************************
 * decryptData - Takes in an encrypted buffer in the form IV/Data and decrypts it, replacing
 *               buf with the decrypted info (destroys IV string>
 *
 *    Params: buf - the encrypted string and holds the decrypted data (minus IV)
 *
 **********************************************************************************************/
void TCPConn::decryptData(std::vector<uint8_t> &buf) {
   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Initialize SecByteBlock vector.\n";
   // For the initialization vector
   SecByteBlock init_vector(iv_size);

   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Copy the IV from the incoming stream of data\n";
   // Copy the IV from the incoming stream of data
    //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Assign buf data to init vector\n";
   init_vector.Assign(buf.data(), iv_size);
   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Erase the buffer from the beginning to however big iv-size is (16)\n";

   if(buf.size() < iv_size) buf.resize(iv_size + 1);
   buf.erase(buf.begin(), buf.begin() + iv_size);

    //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Decrypt the data\n";
   // Decrypt the data
   CFB_Mode<AES>::Decryption decryptor;
   decryptor.SetKeyWithIV(_aes_key, _aes_key.size(), init_vector);

   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Recover data\n";
   std::string recovered;
   ArraySource as(buf.data(), buf.size(), true,
            new StreamTransformationFilter(decryptor, new StringSink(recovered)));

   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Assign data to buffera\n";
   buf.assign(recovered.begin(), recovered.end());

}


/**********************************************************************************************
 * getEncryptedData - Reads in data from the socket and decrypts it, passing the decrypted
 *                    data back in buf
 *
 *    Params: None - data is stored in _inputbuf for retrieval with GetInputData
 *
 *    Returns: true if the data is ready to be read, false otherwise
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getEncryptedData(std::vector<uint8_t> &buf) {
   //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Attempting to read encrypted data.\n";
   // Get the data from the socket
   if (!getData(buf))
   {
      //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "getData returns false.\n";
      return false;
   }

   decryptData(buf);
  // std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << "Buffer has been decrypted.\n";

   return true; 
}

/**********************************************************************************************
 * findCmd - returns an iterator to the location of a string where a command starts
 * hasCmd - returns true if command was found, false otherwise
 *
 *    Params: buf = the data buffer to look for the command within
 *            cmd - the command string to search for in the data
 *
 *    Returns: iterator - points to cmd position if found, end() if not found
 *
 **********************************************************************************************/

std::vector<uint8_t>::iterator TCPConn::findCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return std::search(buf.begin(), buf.end(), cmd.begin(), cmd.end());
}

bool TCPConn::hasCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &cmd) {
   return !(findCmd(buf, cmd) == buf.end());
}

/**********************************************************************************************
 * getCmdData - looks for a startcmd and endcmd and returns the data between the two 
 *
 *    Params: buf = the string to search for the tags
 *            startcmd - the command at the beginning of the data sought
 *            endcmd - the command at the end of the data sought
 *
 *    Returns: true if both start and end commands were found, false otherwisei
 *
 **********************************************************************************************/

bool TCPConn::getCmdData(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd, 
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = buf;
   auto start = findCmd(temp, startcmd);
   auto end = findCmd(temp, endcmd);

   if ((start == temp.end()) || (end == temp.end()) || (start == end))
      return false;

   buf.assign(start + startcmd.size(), end);
   return true;
}

/**********************************************************************************************
 * wrapCmd - wraps the command brackets around the passed-in data
 *
 *    Params: buf = the string to wrap around
 *            startcmd - the command at the beginning of the data
 *            endcmd - the command at the end of the data
 *
 **********************************************************************************************/

void TCPConn::wrapCmd(std::vector<uint8_t> &buf, std::vector<uint8_t> &startcmd,
                                                    std::vector<uint8_t> &endcmd) {
   std::vector<uint8_t> temp = startcmd;
   temp.insert(temp.end(), buf.begin(), buf.end());
   temp.insert(temp.end(), endcmd.begin(), endcmd.end());

   buf = temp;
}


/**********************************************************************************************
 * getReplData - Returns the data received on the socket and marks the socket as done
 *
 *    Params: buf = the data received
 *
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getInputData(std::vector<uint8_t> &buf) {

   // Returns the replication data off this connection, then prepares it to be removed
   buf = _inputbuf;

   _data_ready = false;
   _status = s_none;
}

/**********************************************************************************************
 * connect - Opens the socket FD, attempting to connect to the remote server
 *
 *    Params:  ip_addr - ip address string to connect to
 *             port - port in host format to connect to
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPConn::connect(const char *ip_addr, unsigned short port) {

   // Set the status to connecting
   _status = s_connecting;

   // Try to connect
   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

// Same as above, but ip_addr and port are in network (big endian) format
void TCPConn::connect(unsigned long ip_addr, unsigned short port) {
   // Set the status to connecting
   _status = s_connecting;

   if (!_connfd.connectTo(ip_addr, port))
      throw socket_error("TCP Connection failed!");

   _connected = true;
}

/**********************************************************************************************
 * assignOutgoingData - sets up the connection so that, at the next handleConnection, the data
 *                      is sent to the target server
 *
 *    Params:  data - the data stream to send to the server
 *
 **********************************************************************************************/

void TCPConn::assignOutgoingData(std::vector<uint8_t> &data) {

   _outputbuf.clear();
   _outputbuf = c_rep;
   _outputbuf.insert(_outputbuf.end(), data.begin(), data.end());
   _outputbuf.insert(_outputbuf.end(), c_endrep.begin(), c_endrep.end());
}
 

/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
   _connected = false;
   _status = s_none;
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connected;
   // return _connfd.isOpen(); // This does not work very well
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
const char *TCPConn::getIPAddrStr(std::string &buf) {
   _connfd.getIPAddrStr(buf);
   return buf.c_str();
}


/**********************************************************************************************
 * sendChallenge - Sends a challenge to the connected entity.
 * 
 * Challenges are randomly-generated strings, wrapped in c_auth <AUT></AUT> tags. The challenge
 * is sent in plaintext. The recieving entity is supposed to take that string, encrypt it, and send
 * it back in response to prove it has the correct shared key.
 *
 **********************************************************************************************/
void TCPConn::sendChallenge()
{
   //Generate a challenge string
   std::vector<uint8_t> challenge_str = generateChallengeString();
   challenge = challenge_str;
   //Wrap it
   wrapCmd(challenge_str, c_auth, c_endauth);
   //Send it out
   sendData(challenge_str);

   

}

/**********************************************************************************************
 * waitForChallenge - Waits for a challenge to be send by the connected entity. Returns 
 * true if recieved, false if not.
 * 
 * For reason that are beyond me, we never actually seem to flow into the main body of this function.
 * From debugging I can tell we're sending our challenges, but it seems like _connfd.hasData() is always returning
 * false despite that. As a result, we end up waiting forever for a challenge to reach us.
 * 
 * This is the exact same method the unaltered code uses to determine if data is available to be read.
 * I can't think of a logical reason we wouldn't flow into this function when I know we have data on the line.
 *
 **********************************************************************************************/
bool TCPConn::waitForChallenge()
{
    if (_connfd.hasData()) {
      std::vector<uint8_t> buf;
      if (!getData(buf)) {return false;}

      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::stringstream msg;
         msg << "Challenge recieved in invalid format. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
         disconnect();
         return false;
      }


      //Challenge recieved. Send back encrypted response.
      std::vector<uint8_t> response = buf;
      wrapCmd(response, c_auth, c_endauth);
      encryptData(response);
      sendData(response);
      //sendEncryptedData(response);

      // std::stringstream msg;
      // msg << _svr_id << ": Challenge recieved.";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";

      return true;
   }
   return false;
}

/**********************************************************************************************
 * waitForResponse - Waits for a challenge response to be sent by the connected entity. 
 * Returns true if the challenge response has been recieved and passes, false if not.
 * 
 * As mentioned above, for some reason _connfd.hasData() is always returning false, when it shouldn't.
 * This means that the body of waitForChallenge() never executes, so challenge responses don't get sent.
 * Since the server and client appear to never receive a challenge, their respective clients/servers never
 * send a response. As a result, this function is never executed. 
 **********************************************************************************************/
bool TCPConn::waitForResponse()
{
   if (_connfd.hasData()) {
      std::vector<uint8_t> buf;

      if (!getData(buf)) {return false;}
      decryptData(buf);

      if (!getCmdData(buf, c_auth, c_endauth)) {
         std::stringstream msg;
         msg << "Challenge response received " << std::string(buf.begin(), buf.end()) << " is invalid. Cannot authenticate.";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
         disconnect();
         return false;
      }

      if(buf != challenge)
      {
         std::stringstream msg;
         msg << "Decrypted challenge response " << std::string(buf.begin(), buf.end()) << " does not match sent challenge " << std::string(challenge.begin(), challenge.end()) << "\n";
         _server_log.writeLog(msg.str().c_str());
         std::cout << msg.str() << "\n";
         disconnect();
         return false;
      }

      // std::stringstream msg;
      // msg << _svr_id << ": Successful challenge response.";
      // _server_log.writeLog(msg.str().c_str());
      // std::cout << msg.str() << "\n";
      //std::cout << __FUNCTION__ << "(" << __LINE__ << "): " << " buffer matches to challenge string.\n";

      return true;
   }
   return false;

}

/**********************************************************************************************
 * generateChallengeString- Generates a randomly-generated  string (well, a vector of chars/uint8's)
 * for use in challenges.
 * Returns an std::vector<uint8_t> with random data.
 *
 **********************************************************************************************/
std::vector<uint8_t> TCPConn::generateChallengeString()
{
      std::string challenge_string;

      //Generating a random output using Crypto++'s library and examples
      SecByteBlock key(32); //Save a block of memory for our random value/string
      OS_GenerateRandomBlock(false, key, key.size()); //Have the OS generate a random block, save it in key
      
      HexEncoder encoder(new StringSink(challenge_string)); //Create an encoder to encode our key, save it in our challenge string
      encoder.Put(key, key.size()); //Encode our key and put it in challenge_string
      encoder.MessageEnd(); //Finish encoding

      //Convert string to vector of chars to make this easier to implement in other functions (everything else here uses vectors)
      std::vector<uint8_t> vec(challenge_string.begin(), challenge_string.end());

      //Let's shorten the vector to make sure we're not cutting it off when sending it
      vec.resize(16);

      //std::cout << "Generating challenge string " << std::string(vec.begin(), vec.end()) << "\n";
      //Return our vector
      return vec;
}
