#include <iostream>
#include <exception>
#include "ReplServer.h"

const time_t secs_between_repl = 20;
const unsigned int max_servers = 10;

/*********************************************************************************************
 * ReplServer (constructor) - creates our ReplServer. Initializes:
 *
 *    verbosity - passes this value into QueueMgr and local, plus each connection
 *    _time_mult - how fast to run the simulation - 2.0 = 2x faster
 *    ip_addr - which ip address to bind the server to
 *    port - bind the server here
 *
 *********************************************************************************************/
ReplServer::ReplServer(DronePlotDB &plotdb, float time_mult)
                              :_queue(1),
                               _plotdb(plotdb),
                               _shutdown(false), 
                               _time_mult(time_mult),
                               _verbosity(1),
                               _ip_addr("127.0.0.1"),
                               _port(9999)
{
   _start_time = time(NULL);
}

ReplServer::ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port, int offset, 
                        float time_mult, unsigned int verbosity)
                                 :_queue(verbosity),
                                  _plotdb(plotdb),
                                  _shutdown(false), 
                                  _time_mult(time_mult), 
                                  _verbosity(verbosity),
                                  _ip_addr(ip_addr),
                                  _port(port)

{
   _start_time = time(NULL) + offset;
}

ReplServer::~ReplServer() {

}


/**********************************************************************************************
 * getAdjustedTime - gets the time since the replication server started up in seconds, modified
 *                   by _time_mult to speed up or slow down
 **********************************************************************************************/

time_t ReplServer::getAdjustedTime() {
   return static_cast<time_t>((time(NULL) - _start_time) * _time_mult);
}

/**********************************************************************************************
 * replicate - the main function managing replication activities. Manages the QueueMgr and reads
 *             from the queue, deconflicting entries and populating the DronePlotDB object with
 *             replicated plot points.
 *
 *    Params:  ip_addr - the local IP address to bind the listening socket
 *             port - the port to bind the listening socket
 *             
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void ReplServer::replicate(const char *ip_addr, unsigned short port) {
   _ip_addr = ip_addr;
   _port = port;
   replicate();
}

void ReplServer::replicate() {

   // Track when we started the server
   _start_time = time(NULL);
   _last_repl = 0;

   // Set up our queue's listening socket
   _queue.bindSvr(_ip_addr.c_str(), _port);
   _queue.listenSvr();

   if (_verbosity >= 2)
      std::cout << "Server bound to " << _ip_addr << ", port: " << _port << " and listening\n";

  
   // Replicate until we get the shutdown signal
   while (!_shutdown) {

      // Check for new connections, process existing connections, and populate the queue as applicable
      _queue.handleQueue();     

      // See if it's time to replicate and, if so, go through the database, identifying new plots
      // that have not been replicated yet and adding them to the queue for replication
      if (getAdjustedTime() - _last_repl > secs_between_repl) {

         queueNewPlots();
         _last_repl = getAdjustedTime();
      }
      
      // Check the queue for updates and pop them until the queue is empty. The pop command only returns
      // incoming replication information--outgoing replication in the queue gets turned into a TCPConn
      // object and automatically removed from the queue by pop
      std::string sid;
      std::vector<uint8_t> data;
      while (_queue.pop(sid, data)) {

         // Incoming replication--add it to this server's local database
         addReplDronePlots(data);         
      } 

      
      usleep(1000);
   }   
}

/**********************************************************************************************
 * queueNewPlots - looks at the database and grabs the new plots, marshalling them and
 *                 sending them to the queue manager
 *
 *    Returns: number of new plots sent to the QueueMgr
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

unsigned int ReplServer::queueNewPlots() {
   std::vector<uint8_t> marshall_data;
   unsigned int count = 0;

   if (_verbosity >= 3)
      std::cout << "Replicating plots.\n";

   // Loop through the drone plots, looking for new ones
   std::list<DronePlot>::iterator dpit = _plotdb.begin();
   for ( ; dpit != _plotdb.end(); dpit++) {

      // If this is a new one, marshall it and clear the flag
      if (dpit->isFlagSet(DBFLAG_NEW)) {
         
         dpit->serialize(marshall_data);
         dpit->clrFlags(DBFLAG_NEW);

         count++;
      }
      if (marshall_data.size() % DronePlot::getDataSize() != 0)
         throw std::runtime_error("Issue with marshalling!");

   }
  
   if (count == 0) {
      if (_verbosity >= 3)
         std::cout << "No new plots found to replicate.\n";

      return 0;
   }
 
   // Add the count onto the front
   if (_verbosity >= 3)
      std::cout << "Adding in count: " << count << "\n";

   uint8_t *ctptr_begin = (uint8_t *) &count;
   marshall_data.insert(marshall_data.begin(), ctptr_begin, ctptr_begin+sizeof(unsigned int));

   // Send to the queue manager
   if (marshall_data.size() > 0) {
      _queue.sendToAll(marshall_data);
   }

   if (_verbosity >= 2) 
      std::cout << "Queued up " << count << " plots to be replicated.\n";

   return count;
}

/**********************************************************************************************
 * addReplDronePlots - Adds drone plots to the database from data that was replicated in. 
 *                     Deconflicts issues between plot points.
 * 
 * Params:  data - should start with the number of data points in a 32 bit unsigned integer, 
 *                 then a series of drone plot points
 *
 **********************************************************************************************/
//We're trying to correct our recorded data. The problem is that each server has a bad/offset clock, so we end up with a bunch of slightly offset data points.
      //E.g. a drone at a certain position at a certain time is recorded as being in that position two seperate times because the
      //two nodes that detected it are offset.

      //So we're not allowed to synchronize clocks directly to ensure our database data is consistent- ideally, we'd have
      //a "sync clock" command that runs between the servers so they can dynamically adjust their offset. But we can't.

      //HOWEVER, the replication currently works great- the data on any server is the same as on 
      //EVERY server. What we can do instead is validate our database when we add our plots- since this operation is deterministic
      //and operating on the same data, the results will be the same on all servers.

      //One approach could be to do the validation at the very end- clean and simple, but probably not in the spirit of the assignment?
      //Servers are going to be replicating "bad" data which only gets "fixed" at the very end.

      //Another approach would be to validate the local DB after we're done taking in data. Also works, but this is going to be slow-
      //comparing every item in the DB to every other item in the DB- O(n^2) and slow. 

      //Instead, we can compare our incoming entries to the local DB, so we're comparing a smaller number. If we take the latest time to be the truth, then
      //we'll still get the same result.

void ReplServer::addReplDronePlots(std::vector<uint8_t> &data) {
   if (data.size() < 4) {
      throw std::runtime_error("Not enough data passed into addReplDronePlots");
   }

   if ((data.size() - 4) % DronePlot::getDataSize() != 0) {
      throw std::runtime_error("Data passed into addReplDronePlots was not the right multiple of DronePlot size");
   }

   // Get the number of plot points
   unsigned int *numptr = (unsigned int *) data.data();
   unsigned int count = *numptr;

   // Store sub-vectors for efficiency
   std::vector<uint8_t> plot;
   auto dptr = data.begin() + sizeof(unsigned int);

   //For each of our new drone plots,
   for (unsigned int i=0; i<count; i++)
   {
      //plot.clear();
      //plot.assign(dptr, dptr + DronePlot::getDataSize());
      // addSingleDronePlot(plot);
      // dptr += DronePlot::getDataSize();      

      //Convert to a data structure we can use
      plot.clear();
      plot.assign(dptr, dptr + DronePlot::getDataSize());
      DronePlot IncomingPlot;
      IncomingPlot.deserialize(plot);

      //Compare our incoming data plot to each item (X) in the local DB
      for (auto x : _plotdb)
      {
         //If both plots have the same drone at the same location at different times, we have a conflict.
         if((x.drone_id == IncomingPlot.drone_id) && (x.latitude == IncomingPlot.latitude) && (x.longitude == IncomingPlot.longitude) && (x.node_id != IncomingPlot.node_id) && (x.timestamp != IncomingPlot.timestamp)) //*breathe*
         {

            //Check difference between incoming and existing time- if it's greater than the maximum deviation, we assume these are two different plots and we ignore the conflict.
            if(std::abs(x.timestamp - IncomingPlot.timestamp) > _max_clock_deviation)
            {
               continue;
            }
            if(_verbosity >=3) std::cout << "Found conflict for Drone " << IncomingPlot.drone_id << " at location [" << IncomingPlot.latitude << ", " << IncomingPlot.longitude << "] for timestamps X:" << x.timestamp << " and I: " << IncomingPlot.timestamp << ".\n"; 
            //If our incoming plot has a later timestamp...
            if(IncomingPlot.timestamp > x.timestamp)
            {  
               //... use that time instead and update the existing entry.
               if(_verbosity >= 3) std::cout << "Using later timestamp " << IncomingPlot.timestamp << " (new).\n";
               x.timestamp = IncomingPlot.timestamp;
            }
            else //Otherwise, X's time stamp is later than our existing timestamp- let's use that instead.
            {
               if(_verbosity >= 3) std::cout << "Using later timestamp " << IncomingPlot.timestamp << " (existing).\n";
               IncomingPlot.timestamp = x.timestamp;
            }
         }
      }

      //Add our new entry to the database.
      IncomingPlot.serialize(plot); //seems ridiculous to serialize if we're going to immediateley deserialize, but that's what we're working with (and I don't want to break anything)
      addSingleDronePlot(plot);
      dptr += DronePlot::getDataSize();  
   }

   if (_verbosity >= 2)
      std::cout << "Replicated in " << count << " plots\n";   
}


/**********************************************************************************************
 * addSingleDronePlot - Takes in binary serialized drone data and adds it to the database. 
 *
 **********************************************************************************************/

void ReplServer::addSingleDronePlot(std::vector<uint8_t> &data) {
   DronePlot tmp_plot;

   tmp_plot.deserialize(data);
   _plotdb.addPlot(tmp_plot.drone_id, tmp_plot.node_id, tmp_plot.timestamp, tmp_plot.latitude,
                                                         tmp_plot.longitude);
}


void ReplServer::shutdown() {

   _shutdown = true;
}
