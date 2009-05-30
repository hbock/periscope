/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
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

extern struct ArgusParserStruct *ArgusParser;
extern struct PeriscopeCollector g_collector;

void
periscope_collector_init(struct PeriscopeCollector *collector)
{
   memset(collector, 0, sizeof(struct PeriscopeCollector));
}

void
periscope_collector_start(struct PeriscopeCollector *collector)
{
   periscope_argus_read_local(collector);
   periscope_argus_read_remote(collector);
}

void
periscope_collector_stop(struct PeriscopeCollector *collector)
{
   periscope_argus_client_close(collector);
}

void
periscope_reset_metrics(struct PeriscopeCollector *collector)
{
   memset(&collector->metrics, 0, sizeof(struct PeriscopeMetrics));
}

void
parse_arg (int argc, char**argv)
{}

void
RaProcessRecord (struct ArgusParserStruct *parser,
                 struct ArgusRecordStruct *argus)
{
   switch (record_type(argus)) {
      case ARGUS_MAR:
         printf("MAR\n");
         RaProcessManRecord (parser, argus);
         break;

      case ARGUS_EVENT:
         printf("Event\n");
         RaProcessEventRecord (parser, argus);
         break;

      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (parser->RaMonMode) {
#if 0
            //struct ArgusRecordStruct *tns = ArgusCopyRecordStruct(argus);
            RaProcessThisRecord(parser, argus);
            ArgusReverseRecord(tns);

            if ((flow = (void *)tns->dsrs[ARGUS_FLOW_INDEX]) != NULL) {
               flow->hdr.subtype &= ~ARGUS_REVERSE;
               flow->hdr.argus_dsrvl8.qual &= ~ARGUS_DIRECTION;
            }

            RaProcessThisRecord(parser, tns);
            ArgusDeleteRecordStruct(parser, tns);
#endif
         } else {
            struct PeriscopeDSRs dsrs;
            periscope_argus_record_dsrs(argus, &dsrs);

            switch(flow_subtype(dsrs.flow)) {
            case ARGUS_FLOW_CLASSIC5TUPLE:
            case ARGUS_FLOW_LAYER_3_MATRIX:
               periscope_callback(&g_collector, process_flow, flow_type(dsrs.flow),
                                  argus, &dsrs);
               break;
               
            default:
               printf("Record flow subtype: %02X\n", dsrs.flow->hdr.subtype);
            }
         }
      }
   }
}

void
RaProcessManRecord (struct ArgusParserStruct *parser,
                    struct ArgusRecordStruct *argus)
{
   /* Do nothing yet. */
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