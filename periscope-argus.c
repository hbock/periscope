/* -*- mode: C; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
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

   /* Create new ArgusParserStruct. */
   if((collector->parser = ArgusNewParser("periscope")) == NULL) {
     ArgusLog (LOG_ERR, "ArgusNewParser failed %s", strerror(errno));
     return -1;
   }

   /* This is a hack - ArgusParserStruct has no agnostic pointer field for an application-
    * specific context, so this will have to do for now.  grepping through the source
    * shows that this pointer is untouched if RaClearConfiguration is never called. */
   collector->parser->RaFlowModelFile = (char *)collector;
   
   return 0;
}

int
periscope_argus_local_add(struct PeriscopeCollector *collector, char *pathname)
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

struct ArgusInput *
periscope_argus_remote_add(struct PeriscopeCollector *collector, char *hoststr)
{
   int ret;
   struct ArgusParserStruct *parser = collector->parser;

   if((ret = ArgusAddHostList(parser, hoststr, ARGUS_DATA_SOURCE)) < 0) {
      return NULL;
   }

   /* The Argus library seems to require this flag be set when remote data
    * sources are used. */
   parser->Sflag = 1;
   parser->nflag = 1; /* We will do our own DNS queries, if necessary. */

   /* This may be a race condition.  It shouldn't matter right now, but there
    * should be a better way to do this... */
   return (struct ArgusInput *)parser->ArgusRemoteHosts->end;
}

int
periscope_argus_remote_direct_connect(struct PeriscopeCollector *collector, char *hoststr)
{
   struct ArgusInput *input = periscope_argus_remote_add(collector, hoststr);

   if(input != NULL) {
      ArgusRemoveFromQueue(collector->parser->ArgusRemoteHosts,
                           (struct ArgusQueueHeader *)input, ARGUS_LOCK);
   } else {
      return -1;
   }
   return periscope_argus_remote_connect(collector, input);
}

int
periscope_argus_remote_connect(struct PeriscopeCollector *collector, struct ArgusInput *remote)
{
   struct ArgusParserStruct *parser = collector->parser;
   
   if ((remote->fd = ArgusGetServerSocket (remote, 5)) >= 0) {
      if ((ArgusReadConnection (parser, remote, ARGUS_SOCKET)) >= 0) {
         int flags;
         
         parser->ArgusTotalMarRecords++;
         parser->ArgusTotalRecords++;
         
         printf("Connected to %s:%d, Argus server version %d.%d\n",
                remote->hostname, remote->portnum, remote->major_version, remote->minor_version);
         
         if ((flags = fcntl(remote->fd, F_GETFL, 0L)) < 0)
            ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));
         
         if (fcntl(remote->fd, F_SETFL, flags | O_NONBLOCK) < 0)
            ArgusLog (LOG_ERR, "ArgusConnectRemote: fcntl error %s", strerror(errno));
         
         ArgusAddToQueue(parser->ArgusActiveHosts, &remote->qhdr, ARGUS_LOCK);
         parser->ArgusHostsActive++;

         return 0;
      } else {
         return -1;
      }
   }
   return -1;
}

int
periscope_argus_local_process(struct PeriscopeCollector *collector)
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
                 
                  if (file->ostart != -1) {
                     file->offset = file->ostart;
                     if (fseek(file->file, file->offset, SEEK_SET) >= 0)
                        ArgusReadFileStream(parser, file);
                  } else
                     ArgusReadFileStream(parser, file);
               } else
                  file->fd = -1;

               /* When will this branch ever occur?
                * ArgusReadFileStream always seems to close its input before returning
                * to caller. */
               if (file->file != NULL) {
                  ArgusCloseInput(parser, file);  
               }
            }
            
            periscope_callback(collector, input_complete, file);

            file = (struct ArgusInput *)file->qhdr.nxt;
         }
         
         parser->ArgusPassNum--;
      }
   }
   return 0;
}

int
periscope_argus_remote_connect_all(struct PeriscopeCollector *collector)
{
   int failed = 0;
   struct ArgusInput *addr;
   struct ArgusParserStruct *parser = collector->parser;

   if (parser->Sflag) {
      if (parser->ArgusRemoteHosts && (parser->ArgusRemoteHosts->count > 0)) {
         parser->ArgusRemotes = parser->ArgusRemoteHosts->count;
         
#if defined(ARGUS_THREADS)
         if (parser->ArgusReliableConnection) {
            if (parser->ArgusRemoteHosts && parser->ArgusRemoteHosts->count) {
               if ((pthread_create(&parser->remote, &argus_attr, ArgusConnectRemotes,
                                   parser->ArgusRemoteHosts)) != 0)
                  ArgusLog (LOG_ERR, "ArgusNewOutput() pthread_create error %s\n", strerror(errno));
            }

         } else {
#else
         {
#endif
            while ((addr = (void *)ArgusPopQueue(parser->ArgusRemoteHosts, ARGUS_LOCK)) != NULL) {
               if(periscope_argus_remote_connect(collector, addr) < 0) {
                  fprintf(stderr, "Periscope: connecting to %s failed!\n", addr->hostname);
                  periscope_argus_close_input(collector, addr);
                  failed++;
               }
#if !defined(ARGUS_THREADS)
            }
#else
            }
#endif
         }
      }
   } else {
#if defined(ARGUS_THREADS) 
      parser->RaDonePending++;
#else
      parser->RaParseDone++;
#endif
   }

   return failed;
}

int
periscope_argus_remote_process(struct PeriscopeCollector *collector)
{
   struct ArgusParserStruct *parser = collector->parser;

#if defined(ARGUS_THREADS) 
      if (parser->ArgusReliableConnection || parser->ArgusActiveHosts->count)
#else
         if (parser->ArgusActiveHosts->count)
#endif
            ArgusReadStream(parser, parser->ArgusActiveHosts);

   return 0;
}

/* Close input source and free associated data.
 * If 'input' is enqueued, it is dequeued before being freed by ArgusCloseInput.
 * If the input is associated with a thread, it is joined. */
int
periscope_argus_close_input(struct PeriscopeCollector *collector,
                            struct ArgusInput *input)
{
   ArgusCloseInput(collector->parser, input);
   if (input->hostname != NULL)
      free (input->hostname);
   if (input->filename != NULL)
      free (input->filename);
#if defined(HAVE_GETADDRINFO)
   if (input->host != NULL)
      freeaddrinfo (input->host);
#endif

#if defined(ARGUS_THREADS) 
         if (input->tid != (pthread_t) 0)
            pthread_join(input->tid, NULL);
#endif

   ArgusFree(input);

   return 0;
}

static int
argus_close_remote(struct PeriscopeCollector *collector)
{
   struct ArgusParserStruct *parser = collector->parser;
#if defined(ARGUS_THREADS)
   struct ArgusInput *addr;

   if (parser->Sflag) {
      /* Why are these threads joined twice in the main Argus code? */
#if 0
      while ((addr = (void *)ArgusPopQueue(parser->ArgusActiveHosts, ARGUS_LOCK)) != NULL) {
         if (addr->tid != (pthread_t) 0) {
            pthread_join(addr->tid, NULL);
         }
      }
#endif
   }
#endif

   /* Close remote host connections.
    * 
    * Copied from ArgusShutDown, with unnecessary signal checking and log file writing
    * removed.  Also made thread-safe by using the collector's parser struct, not the
    * global instance. */
   if (parser->ArgusRemoteHosts != NULL) {
      struct ArgusQueueStruct *queue =  parser->ArgusRemoteHosts;
      struct ArgusInput *input = NULL;
      
      while (queue->count > 0) {
         if ((input = (struct ArgusInput *) ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
            periscope_argus_close_input(collector, input);
         }
      }
      /*
      */
   }

   /* Close active hosts?
    * Also copied from ArgusShutDown, made thread-safe. */
   if (parser->ArgusActiveHosts != NULL) {
      struct ArgusQueueStruct *queue =  parser->ArgusActiveHosts;
      struct ArgusInput *input = NULL;
      
      while ((input = (void *)ArgusPopQueue(queue, ARGUS_LOCK)) != NULL) {
         periscope_argus_close_input(collector, input);
         parser->ArgusHostsActive--;
      }
   }   
   return 0;
}

int
periscope_argus_client_stop(struct PeriscopeCollector *collector)
{
   return argus_close_remote(collector);
}

int
periscope_argus_client_free(struct PeriscopeCollector *collector)
{
   struct ArgusParserStruct *parser = collector->parser;

   /* If this function is called with remote sources active, close them now. */
   if(parser->ArgusActiveHosts || parser->ArgusRemoteHosts) {
      argus_close_remote(collector);
   }
   
   if (parser->ArgusReliableConnection)
      pthread_attr_destroy(&argus_attr);

   /* Free all data associated with the ArgusParserStruct. */
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
