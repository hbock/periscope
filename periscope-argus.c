/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
/*
 * Periscope - Argus Client Interface
 * Copyright (c) 2009 Harry Bock <harry@oshean.org>
 * 
 * Modified from 'ra', written by Carter Bullard.
 * Argus Software
 * Copyright (c) 2000-2009 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#include <unistd.h>
#include <stdlib.h>

#include <compat.h>

#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>

#include "periscope.h"

extern struct ArgusParserStruct *ArgusParser;
extern struct PeriscopeCollector g_collector;
pthread_attr_t argus_attr;

/* Stub function, required by Argus library. */
void usage ()
{
   fprintf(stderr, "BUG: periscope stub: You shouldn't see this message.\n");
}

/* Stuff to know:
 *  ArgusAddFileList(parser, pathname, ARGUS_DATA_SOURCE, -1, -1); (NULL error)
 *  ArgusAddHostList(parser, hostname, ARGUS_DATA_SOURCE); (NULL error)
 */

void
ArgusClientInit (struct ArgusParserStruct *parser)
{
   /* Do nossing yet. */
}

void RaArgusInputComplete (struct ArgusInput *input)
{
   periscope_callback(&g_collector, input_complete, input);
}

void
RaParseComplete (int sig)
{
   /* Do nossing yet. */
}

void
ArgusClientTimeout ()
{
}

int RaSendArgusRecord(struct ArgusRecordStruct *argus)
{
   /* Periscope doesn't handle this. */
   return 0;
}

void ArgusWindowClose(void) 
{
   /* Periscope doesn't handle this. */
}

int
periscope_argus_client_init(struct PeriscopeCollector *collector)
{
   /* Initialize threading parameters. */
#if defined(ARGUS_THREADS)
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
   size_t stacksize;
#endif

#if defined(ARGUS_THREADS)
   if ((status = pthread_attr_init(&argus_attr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");
 
#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN)
   if ((status = pthread_attr_getschedpolicy(&argus_attr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((status = pthread_attr_getschedparam(&argus_attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((status = pthread_attr_setschedpolicy(&argus_attr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((status = pthread_attr_setschedparam(&argus_attr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
   pthread_attr_setschedpolicy(&argus_attr, SCHED_RR);
#endif

#if defined(_POSIX_THREAD_ATTR_STACKSIZE)
#define ARGUS_MIN_STACKSIZE	524288

   if (pthread_attr_getstacksize(&argus_attr, &stacksize))
      ArgusLog (LOG_ERR, "pthreads get stacksize error");

   if (stacksize < ARGUS_MIN_STACKSIZE) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "setting stacksize from %d to %d", stacksize, ARGUS_MIN_STACKSIZE);
#endif
      if (pthread_attr_setstacksize(&argus_attr, ARGUS_MIN_STACKSIZE))
         ArgusLog (LOG_ERR, "pthreads set stacksize error");
   }
#endif
 
   pthread_attr_setdetachstate(&argus_attr, PTHREAD_CREATE_JOINABLE);
#endif

   if((ArgusParser = collector->parser = ArgusNewParser("periscope")) == NULL) {
     ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));
     return -1;
   }

   //ArgusMainInit(ArgusParser, argc, argv);
   ArgusClientInit(ArgusParser);   

   return 0;
}

int
periscope_argus_add_file(struct PeriscopeCollector *collector, char *pathname)
{
   if(!(collector && pathname))
      return -1;

   /* Argus will try to process the file whether it exists or not; don't let files
    * that don't exist through. */
   if(access(pathname, F_OK) == -1)
      return -1;

   if(ArgusAddFileList(collector->parser, pathname, ARGUS_DATA_SOURCE, -1, -1) == 0)
      return -1;

   return 0;      
}

int
periscope_argus_add_remote(struct PeriscopeCollector *collector, char *hoststr)
{
   if(ArgusAddHostList(collector->parser, hoststr, ARGUS_DATA_SOURCE) == 0) {
      return -1;
   }

   return 0;
}

int
periscope_argus_read_local(struct PeriscopeCollector *collector)
{
   struct ArgusParserStruct *parser = collector->parser;

   /* Read in all the files, for as many passes as needed. */
   if (parser->ArgusInputFileList != NULL) {
      struct ArgusInput *file; 

      while (parser->ArgusPassNum) {
         file = parser->ArgusInputFileList;
         while (file && parser->eNflag) {
            if (strlen(file->filename)) {
               if (file->fd < 0) {
                  if ((file->file = fopen(file->filename, "r")) == NULL) {
#ifdef ARGUSDEBUG
                     ArgusDebug (0, "open '%s': %s", file->filename, strerror(errno));
#endif
                  }
                  
               } else {
                  fseek(file->file, 0, SEEK_SET);
               }
               
               if ((file->file != NULL) && ((ArgusReadConnection (parser, file, ARGUS_FILE)) >= 0)) {
                  parser->ArgusTotalMarRecords++;
                  parser->ArgusTotalRecords++;
                  
                  if (parser->RaPollMode) {
                     ArgusHandleDatum (parser, file, &file->ArgusInitCon, &parser->ArgusFilterCode);
                     ArgusCloseInput(parser, file);  
                  } else {
                     if (file->ostart != -1) {
                        file->offset = file->ostart;
                        if (fseek(file->file, file->offset, SEEK_SET) >= 0)
                           ArgusReadFileStream(parser, file);
                     } else
                        ArgusReadFileStream(parser, file);
                  }
                  
               } else
                  file->fd = -1;
               
               if (file->file != NULL) {
                  ArgusCloseInput(parser, file);  
               }
            }
            
            RaArgusInputComplete(file);
            file = (struct ArgusInput *)file->qhdr.nxt;
         }
         
         parser->ArgusPassNum--;
      }
   }
   return 0;
}

int
periscope_argus_read_remote(struct PeriscopeCollector *collector)
{
/*
   Now we're going to deal with remote data sources.  To implement
   reliable connections effeciently, we need to put the input blocks
   in a data structure so that our reliable thread can do the right
   thing with them.
   
   The idea is that if they are in the queue we need to get a connection
   with the input.  If they are not in the queue, we have a connection or
   we are going to delete/forget them  because of massive errors.

   So, if we are reliably connected, first we put them all on the queue.
   If not we just connect to them sequentially.
*/
   int hosts;
   struct ArgusInput *addr;
   struct ArgusParserStruct *parser = collector->parser;

   if (parser->Sflag) {
      if (parser->ArgusRemoteHosts && (parser->ArgusRemoteHosts->count > 0)) {
         struct ArgusQueueStruct *tqueue = ArgusNewQueue();
         int flags;

         parser->ArgusRemotes = parser->ArgusRemoteHosts->count;

#if defined(ARGUS_THREADS)
         if (parser->ArgusReliableConnection) {
            if (parser->ArgusRemoteHosts && (hosts = parser->ArgusRemoteHosts->count)) {
               if ((pthread_create(&parser->remote, &argus_attr, ArgusConnectRemotes,
                                   parser->ArgusRemoteHosts)) != 0)
                  ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
            }

         } else {
#else
         {
#endif
            while ((addr = (void *)ArgusPopQueue(parser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
               if ((addr->fd = ArgusGetServerSocket (addr, 5)) >= 0) {
                  if ((ArgusReadConnection (parser, addr, ARGUS_SOCKET)) >= 0) {
                     parser->ArgusTotalMarRecords++;
                     parser->ArgusTotalRecords++;

                     if ((flags = fcntl(addr->fd, F_GETFL, 0L)) < 0)
                        ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                     if (fcntl(addr->fd, F_SETFL, flags | O_NONBLOCK) < 0)
                        ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));

                     if (parser->RaPollMode) {
                        ArgusHandleDatum (parser, addr, &addr->ArgusInitCon, &parser->ArgusFilterCode);
                        ArgusCloseInput (parser, addr);
                     } else {
                        ArgusAddToQueue(parser->ArgusActiveHosts, &addr->qhdr, ARGUS_LOCK);
                        parser->ArgusHostsActive++;
                     }
                  } else
                     ArgusAddToQueue(tqueue, &addr->qhdr, ARGUS_LOCK);
               } else
                  ArgusAddToQueue(tqueue, &addr->qhdr, ARGUS_LOCK);
#if !defined(ARGUS_THREADS)
            }
#else
            }
#endif
         }

         while ((addr = (void *)ArgusPopQueue(tqueue, ARGUS_LOCK)) != NULL)
            ArgusAddToQueue(parser->ArgusRemoteHosts, &addr->qhdr, ARGUS_LOCK);

         ArgusDeleteQueue(tqueue);
      }

#if defined(ARGUS_THREADS) 
      if (parser->ArgusReliableConnection || parser->ArgusActiveHosts->count)
#else
         if (parser->ArgusActiveHosts->count)
#endif
            ArgusReadStream(parser, parser->ArgusActiveHosts);

   } else {
#if defined(ARGUS_THREADS) 
      parser->RaDonePending++;
#else
      parser->RaParseDone++;
#endif
   }
   return 0;
}

static int
argus_close_remote(struct PeriscopeCollector *collector)
{
#if defined(ARGUS_THREADS)
   struct ArgusInput *addr;
   
   if (collector->parser->Sflag) {
      void *retn = NULL;

      if (collector->parser->ArgusReliableConnection)
         pthread_attr_destroy(&argus_attr);

      while ((addr = (void *)ArgusPopQueue(collector->parser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, &retn);
         }
      }
   }
#endif

   return 0;
}

int
periscope_argus_client_close(struct PeriscopeCollector *collector)
{
   struct ArgusParserStruct *parser = collector->parser;
   
   argus_close_remote(collector);

   ArgusShutDown (0);

#if defined(ARGUS_THREADS)
   if (parser->dns != (pthread_t) 0)
      pthread_join(parser->dns, NULL);
#endif

   ArgusCloseParser(parser);

   return 0;
}

inline struct ArgusFlow *
record_flow(struct ArgusRecordStruct *record)
{
   return (struct ArgusFlow *)record->dsrs[ARGUS_FLOW_INDEX];
}

inline struct ArgusVlanStruct *
record_vlan(struct ArgusRecordStruct *record)
{
   return (struct ArgusVlanStruct *)record->dsrs[ARGUS_VLAN_INDEX];
}

inline struct ArgusMetricStruct *
record_metric(struct ArgusRecordStruct *record)
{
   return (struct ArgusMetricStruct *)record->dsrs[ARGUS_METRIC_INDEX];
}

inline struct ArgusTimeObject *
record_time(struct ArgusRecordStruct *record)
{
   return (struct ArgusTimeObject *)record->dsrs[ARGUS_TIME_INDEX];
}

inline struct ArgusNetworkStruct *
record_network(struct ArgusRecordStruct *record)
{
   return (struct ArgusNetworkStruct *)record->dsrs[ARGUS_NETWORK_INDEX];
}

int
periscope_argus_record_dsrs(struct ArgusRecordStruct *record,
                            struct PeriscopeDSRs *dsrs)
{
   if(dsrs && record) {
      dsrs->flow = (struct ArgusFlow *)record->dsrs[ARGUS_FLOW_INDEX];
      dsrs->vlan = (struct ArgusVlanStruct *)record->dsrs[ARGUS_VLAN_INDEX];
      dsrs->metric = (struct ArgusMetricStruct *)record->dsrs[ARGUS_METRIC_INDEX];
      dsrs->time   = (struct ArgusTimeObject *)record->dsrs[ARGUS_TIME_INDEX];
      dsrs->net    = (struct ArgusNetworkStruct *)record->dsrs[ARGUS_NETWORK_INDEX];

      return 0;
   } else {
      return -1;
   }
}

struct ArgusInput *
PeriscopeProcessArgusSource(struct PeriscopeCollector *collector, struct ArgusInput *source)
{
   if(!source) {
      return NULL;
   }
   
   periscope_callback(collector, input_complete, source);

   return (struct ArgusInput *)source->qhdr.nxt;
}
