/* -*- mode: C; c-file-style: "k&r"; c-basic-offset: 3; indent-tabs-mode: nil; -*- */
/*
 * Argus Software
 * Copyright (c) 2000-2008 QoSient, LLC
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

/*
 * argus_main - main routine for parsing argus output.
 *       this module performs all the argus(1) related connection parsing,
 *       selects datum from a set of criteria, and then calls specific
 *       protocol dependant routines, depending on the selected datum.
 *       at the end of processing, argus_parse calls an application
 *       specific finish routine, RaParseComplete(), and when
 *       connected to a remote data source, it supplies a periodic
 *       timeout routine;
 *
 *       this module defines all things, except:
 *
 *   (void) usage ((char *) argv[0]);
 *                    this routine should print the standard usage message
 *                    for the specific application.
 *
 *   (void) ArgusClientInit ();  this is the application specific init
 *                    routine, which is called after all parsing
 *                    initialization is done, prior to reading the
 *                    first monitor(1) datum.
 *
 *   (void) ArgusClientTimeout ();
 *                    this routine is called every second, when
 *                    argus_parse is connected to a remote data source.
 *
 *   (void) RaParseComplete (0);
 *                    this routine will be called after all the
 *                    monitor data has been read.
 *
 *
 * written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/clients/common/argus_main.c#55 $
 * $DateTime: 2009/03/24 23:29:19 $
 * $Change: 1688 $
 */

#include <sys/types.h>
#include <unistd.h>

#if defined(ARGUS_THREADS) 
#include <pthread.h>
#endif

#define ArgusMain

#include <compat.h>

#include <argus_def.h>
#include <argus_out.h>

#include <signal.h>

#include <argus_util.h>

#include <argus_client.h>
#include <argus_main.h>
#include <argus_filter.h>
#include <argus_grep.h>
#include <dscodepoints.h>

#include <ctype.h>
#include <strings.h>

#if defined(HAVE_SOLARIS)
#include <string.h>
#endif

#include <sys/wait.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#include <arpa/inet.h>
#include "periscope.h"

struct PeriscopeCollector g_collector;

void
usage ()
{
   fprintf(stderr,
           "Periscope client version 0.1.\n"
           "Built against Argus version %d.%d.\n\n", VERSION_MAJOR, VERSION_MINOR);

   fprintf (stderr,
            "usage: %1$s\n"
            "usage: %1$s [options] -S remoteServer  [- filter-expression]\n"
            "usage: %1$s [options] -r argusDataFile [- filter-expression]\n\n",
            ArgusParser->ArgusProgramName);

   fprintf (stderr, "options: -A                    print record summaries on termination.\n");
   fprintf (stderr, "         -b                    dump packet-matching code.\n");
   fprintf (stderr, "         -c <char>             specify a delimiter <char> for output columns.\n");
   fprintf (stderr, "         -C <[host]:port>      specify Cisco Netflow source.\n");
#if defined (ARGUSDEBUG)
   fprintf (stderr, "         -D <level>            specify debug level\n");
#endif
   fprintf (stderr, "         -e <regex>            match regular expression in flow user data fields.\n");
   fprintf (stderr, "                               Prepend the regex with either \"s:\" or \"d:\" to limit the match\n");
   fprintf (stderr, "                               to either the source or destination user data fields.\n");
   fprintf (stderr, "         -E <file>             write records that are rejected by the filter into <file>\n");
   fprintf (stderr, "         -F <conffile>         read configuration from <conffile>.\n");
   fprintf (stderr, "         -h                    print help.\n");
   fprintf (stderr, "         -M <option>           specify a Mode of operation.\n");
   fprintf (stderr, "            rmon               convert bi-directional flow data to RMON in/out stats\n");
   fprintf (stderr, "            poll               attach to remote server to get MAR and then disconnect\n");
   fprintf (stderr, "            xml                pritn output in xml format\n");
   fprintf (stderr, "            TZ='timezone'      set TZ environment variable with timezone string\n");
   fprintf (stderr, "            saslmech='mech'    specify the sasl mechanism to use for this connection\n");
   fprintf (stderr, "            label='str'        specify label matching expression\n");
   fprintf (stderr, "            dsrs='strip str'   specify input dsrs (see rastrip.1)\n");
   fprintf (stderr, "            sql='str'          use str as \"WHERE\" clause in sql call.\n");
   fprintf (stderr, "            disa               Use US DISA diff-serve encodings\n");
   fprintf (stderr, "            hex                process user data using hex encoding\n");
   fprintf (stderr, "            ascii              process user data using ascii encoding\n");
   fprintf (stderr, "            encode32           process user data using encode32 encoding\n");
   fprintf (stderr, "            encode64           process user data using encode64 encoding\n");
   fprintf (stderr, "         -n                    don't convert numbers to names.\n");
   fprintf (stderr, "         -p <digits>           print fractional time with <digits> precision.\n");
   fprintf (stderr, "         -q                    quiet mode. don't print record outputs.\n");
   fprintf (stderr, "         -r <file>             read argus data <file>. '-' denotes stdin.\n");
   fprintf (stderr, "         -R <dir>              recursively process files in directory\n");
   fprintf (stderr, "         -s [-][+[#]]field[:w] specify fields to print.\n");
   fprintf (stderr, "                   fields:     srcid, stime, ltime, sstime, dstime, sltime, dltime,\n");
   fprintf (stderr, "                               trans, seq, flgs, dur, avgdur, stddev, mindur, maxdur,\n");
   fprintf (stderr, "                               saddr, daddr, proto, sport, dport, stos, dtos, sdsb, ddsb\n");
   fprintf (stderr, "                               sco, dco, sttl, dttl, sipid, dipid, smpls, dmpls, svlan, dvlan\n");
   fprintf (stderr, "                               svid, dvid, svpri, dvpri, [s|d]pkts, [s|d]bytes,\n");
   fprintf (stderr, "                               [s||d]appbytes, [s|d]load, [s|d]loss, [s|d]ploss, [s|d]rate,\n");
   fprintf (stderr, "                               smac, dmac, dir, [s|d]intpkt, [s|d]jit, state, suser, duser,\n");
   fprintf (stderr, "                               swin, dwin, trans, srng, erng, stcpb, dtcpb, tcprtt, inode,\n");
   fprintf (stderr, "                               offset, smaxsz, dmaxsz, sminsz, dminsz\n");
   fprintf (stderr, "         -S <host[:port]>      specify remote argus and optional port number\n");
   fprintf (stderr, "         -t <timerange>        specify <timerange> for reading records.\n");
   fprintf (stderr, "                   format:     timeSpecification[-timeSpecification]\n");
   fprintf (stderr, "                               timeSpecification: [[[yyyy/]mm/]dd.]hh[:mm[:ss]]\n");
   fprintf (stderr, "                                                    [yyyy/]mm/dd\n");
   fprintf (stderr, "                                                    -%%d{yMdhms}\n");
   fprintf (stderr, "         -T <secs>             attach to remote server for T seconds.\n");
   fprintf (stderr, "         -u                    print time in Unix time format.\n");
#ifdef ARGUS_SASL
   fprintf (stderr, "         -U <user/auth>        specify <user/auth> authentication information.\n");
#endif
   fprintf (stderr, "         -w <file>             write output to <file>. '-' denotes stdout.\n");
   fprintf (stderr, "         -X                    don't read default rarc file.\n");
   fprintf (stderr, "         -z                    print Argus TCP state changes.\n");
   fprintf (stderr, "         -Z <s|d|b>            print actual TCP flag values.\n");
   fprintf (stderr, "                               <'s'rc | 'd'st | 'b'oth>\n");
   exit(1);
}

void
process_flow(struct PeriscopeCollector *collector,
             unsigned char type,
             struct ArgusRecordStruct *record,
             struct PeriscopeDSRs *dsrs)
{
   struct ArgusFlow *flow = dsrs->flow;

   if(!flow)
      printf("lol?\n");

   switch(type) {
   case ARGUS_TYPE_IPV4: {
      unsigned int ipaddr1, ipaddr2;
      char ip1[INET_ADDRSTRLEN];
      char ip2[INET_ADDRSTRLEN];
      struct ArgusIPFlow *ip = &flow->ip_flow;

      ipaddr1 = htonl(ip->ip_src);
      ipaddr2 = htonl(ip->ip_dst);
      
      inet_ntop(AF_INET, (struct in_addr *)&ipaddr1, ip1, sizeof(ip1));
      inet_ntop(AF_INET, (struct in_addr *)&ipaddr2, ip2, sizeof(ip2));

      switch(ip->ip_p) {
      case IPPROTO_TCP:
         printf("tcp: "); collector->metrics.tcp_count++;
         switch(net_subtype(dsrs->net)) {
         case ARGUS_TCP_PERF: {
            struct ArgusTCPObject *tcp = net_tcp(dsrs->net);
            printf("status: %08x ", tcp->status);
            if(tcp->status & ARGUS_RESET) {
               printf("RESET - ");
            }
            if(tcp->status & ARGUS_PKTS_RETRANS)
               printf("RETRANSMIT - ");
            if(tcp->status & ARGUS_NORMAL_CLOSE)
               printf("NORMAL CLOSE - ");
         }
            break;

         case ARGUS_TCP_STATUS:
            printf("status");
            break;

         case ARGUS_TCP_INIT:
            printf("init");
            break;

         default:
            printf("???");
            break;
         }
         printf("\n");

         break;
      case IPPROTO_UDP: collector->metrics.udp_count++; break;
      case IPPROTO_ICMP:
         if(dsrs->net) {
            struct ArgusICMPObject *icmp = net_icmp(dsrs->net);
            printf("ICMP (net subtype %02X): ", net_subtype(dsrs->net));
            printf("%15s %15s\n", ip1, ip2);
            printf("Type %02X Code %02X %04X seq\n", icmp->icmp_type, icmp->icmp_code, icmp->iseq);
         }
         collector->metrics.icmp_count++;
         break;
      default: collector->metrics.other_count++; break;
      }

      break;
   }

   default:
      printf("Unhandled flow type %02X.\n.", type);
   }
   
   if(dsrs->vlan) {
        
   }
   if(dsrs->metric) {
      struct ArgusMetricStruct *metric = dsrs->metric;
   }
   collector->metrics.flows++;
}

void
input_source_completed(struct PeriscopeCollector *collector,
                       struct ArgusInput *input)
{
   printf("Completed processing input source ");
   if(input->hostname)
      printf("%s:%d", input->hostname, input->portnum);
   else if(input->filename)
      printf("(file '%s')", input->filename);
   printf(".\n");

   printf("Processed %u flows (%u TCP, %u UDP, %u ICMP, %u other).\n",
          collector->metrics.flows, collector->metrics.tcp_count,
          collector->metrics.udp_count, collector->metrics.icmp_count,
          collector->metrics.other_count);
   
   collector->sources++;
   
   periscope_reset_metrics(collector);
}

int
main (int argc, char **argv)
{
   periscope_collector_init(&g_collector);

   g_collector.callbacks.process_flow = process_flow;
   g_collector.callbacks.input_complete = input_source_completed;

   if(periscope_argus_client_init(&g_collector, argc, argv) == -1) {
        fprintf(stderr, "Initializing Argus client failed!\n");
        exit(1);
   }

   periscope_collector_start(&g_collector);
   periscope_collector_stop(&g_collector);
}
