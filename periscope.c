/* -*- mode: C; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
/*
 * Argus Software
 * Copyright (c) 2000-2009 QoSient, LLC
 * All rights reserved.
 *
 * Periscope - Argus Client Interface
 * Copyright (c) 2009 Harry Bock <harry@oshean.org>
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

/* Periscope - Argus Client Interface
 *
 * Modified from 'ra', written by Carter Bullard.
 * Copyright (c) 2000-2009 QoSient, LLC
 */
#include <unistd.h>
#include <stdlib.h>

#include <compat.h>

#include <rabins.h>
#include <argus_util.h>
#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>

#include <signal.h>
#include <ctype.h>

#include "periscope.h"

int
periscope_collector_init(struct PeriscopeCollector *collector)
{
   memset(collector, 0, sizeof(struct PeriscopeCollector));

   if(periscope_argus_client_init(collector) == -1) {
        fprintf(stderr, "Initializing Argus client failed!\n");
        return -1;
   }
   return 0;
}

int
periscope_collector_start(struct PeriscopeCollector *collector)
{
   int ret;

   if(collector->running)
      return -1;
   
   collector->running = 1;

   /* Process all local files first, before we try to handle remote connections. */
   periscope_argus_local_process(collector);

   /* Connect to all requested probes.
    * TODO: currently we don't handle situations where some or all connections failed,
    * we just report that it happened. In the future we should allow for atomic
    * startup (i.e., all or nothing). */
   if(periscope_argus_remote_connect_all(collector) != 0) {
      fprintf(stderr, "Periscope: some connections failed!\n");
   }

   /* Process all remote sources.
    * This function will return when:
    *  - There are no remote sources to process.
    *  - The remote end closes the connection, or the connection fails.
    *  - periscope_argus_client_close is called.
    * In the last case - when the app wants to close down gracefully - it must be
    * done asynchronously, either in another thread or via a signal handler. */
   ret = periscope_argus_remote_process(collector);
   collector->running = 0;

   return ret;
}

void
periscope_collector_stop(struct PeriscopeCollector *collector)
{
   if(collector->running) {
      periscope_argus_client_stop(collector);
      collector->running = 0;
   }
}

void
periscope_collector_free(struct PeriscopeCollector *collector)
{
   if(collector->running) {
      periscope_collector_stop(collector);
   }
   periscope_argus_client_free(collector);
}

int
periscope_collector_is_running(struct PeriscopeCollector *collector)
{
   return collector->running;
}

void
periscope_reset_metrics(struct PeriscopeCollector *collector)
{
   memset(&collector->metrics, 0, sizeof(struct PeriscopeMetrics));
}

void
RaProcessRecord (struct ArgusParserStruct *parser,
                 struct ArgusRecordStruct *argus)
{
   struct PeriscopeCollector *collector = (struct PeriscopeCollector *)parser->RaFlowModelFile;
   
   switch (record_type(argus)) {
      case ARGUS_MAR:
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct PeriscopeDSRs dsrs;
         periscope_argus_record_dsrs(argus, &dsrs);
         
         switch(flow_subtype(dsrs.flow)) {
         case ARGUS_FLOW_CLASSIC5TUPLE:
         case ARGUS_FLOW_LAYER_3_MATRIX:
            periscope_callback(collector, process_flow, flow_type(dsrs.flow), argus, &dsrs);
            break;

         case ARGUS_FLOW_ARP:
            printf("TODO: ARP support?\n");
            break;
            
         default:
            printf("Record flow subtype: %02X\n", dsrs.flow->hdr.subtype);
         }
      }
   }
}

void
RaProcessManRecord (struct ArgusParserStruct *parser,
                    struct ArgusRecordStruct *argus)
{
   struct ArgusRecord *rec = (struct ArgusRecord *)argus->dsrs[0];
   if(rec) {
      struct ArgusMarStruct *mar = &rec->ar_un.mar;
      
      printf("Received MAR: status %u local net %08x, netmask %08x, ver %hhu.%hhu, %llu received packets.\n",
             mar->status, mar->localnet, mar->netmask, mar->major_version, mar->minor_version,
             mar->pktsRcvd);
   }
}

void
PeriscopeWriteEventRecord(struct ArgusParserStruct *parser,
                          struct ArgusRecordStruct *argus)
{
   struct ArgusWfileStruct *wfile = NULL;
   struct ArgusListObjectStruct *lobj = NULL;
   int i, count = parser->ArgusWfileList->count;
   
   if ((lobj = parser->ArgusWfileList->start) != NULL) {
      for (i = 0; i < count; i++) {
         if ((wfile = (struct ArgusWfileStruct *) lobj) != NULL) {
            int retn = 1;
            if (wfile->filterstr) {
               struct nff_insn *wfcode = wfile->filter.bf_insns;
               retn = ArgusFilterRecord (wfcode, argus);
            }
            
            if (retn != 0) {
               if ((parser->exceptfile == NULL) || strcmp(wfile->filename, parser->exceptfile)) {
                  struct ArgusRecord *argusrec = NULL;
                  static char sbuf[0x10000];
                  if ((argusrec = ArgusGenerateRecord (argus, 0L, sbuf)) != NULL) {
#ifdef _LITTLE_ENDIAN
                     ArgusHtoN(argusrec);
#endif
                     ArgusWriteNewLogfile (parser, argus->input, wfile, argusrec);
                  }
               }
            }
         }
         
         lobj = lobj->nxt;
      }
   }  
}

void
RaProcessEventRecord (struct ArgusParserStruct *parser,
                      struct ArgusRecordStruct *argus)
{
   printf("Event\n");

   if (parser->ArgusWfileList != NULL) {
      PeriscopeWriteEventRecord(parser, argus);
   } else {
#if 0
      if ((parser->ArgusPrintEvent) && (!parser->qflag)) {
         if (parser->Lflag && !(parser->ArgusPrintXml)) {
            if (parser->RaLabel == NULL)
               parser->RaLabel = ArgusGenerateLabel(parser, argus);
 
            if (!(parser->RaLabelCounter++ % parser->Lflag))
               printf ("%s\n", parser->RaLabel);
 
            if (parser->Lflag < 0)
               parser->Lflag = 0;
         }

         bzero (buf, sizeof(buf));
         ArgusPrintRecord(parser, buf, argus, MAXSTRLEN);

         fprintf (stdout, "%s\n", buf);
         fflush (stdout);
      }
#endif
   }
}
