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
#include <stdio.h>

#include "periscope.h"

struct PeriscopeCollector g_collector;

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

      if(dsrs->vlan) {
         printf("vlan sid=%04x,did=%04x\n", dsrs->vlan->sid, dsrs->vlan->did);
      }

      switch(ip->ip_p) {
      case IPPROTO_TCP:
         printf("tcp: cause %02x ", (record->hdr.cause & 0xF0));
         switch(net_subtype(dsrs->net)) {
         case ARGUS_TCP_PERF: {
            struct ArgusTCPObject *tcp = net_tcp(dsrs->net);
            printf("status: %08x ", tcp->status);
            if(tcp->status & ARGUS_RESET) {
               printf("RESET - ");
            }
            if(tcp->status & ARGUS_PKTS_RETRANS)
               printf("RETRANSMIT - ");
            if(tcp->status & (ARGUS_FIN|ARGUS_FIN_ACK)) {
               printf("NORMAL CLOSE - ");
               collector->metrics.tcp_count++;
            } else if(tcp->status & ARGUS_RESET) {
               collector->metrics.tcp_count++;
            }
         }
            break;

         case ARGUS_TCP_STATUS:
            printf("status only");
            break;

         case ARGUS_TCP_INIT: {
            struct ArgusTCPInitStatus *tcp = net_tcp_init(dsrs->net);
            printf("init status: %08x ", tcp->status);
            break;
         }
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

   case ARGUS_TYPE_ETHER: {
      int i;
      struct ArgusEtherMacFlow *ether = &flow_ether(flow);
      
      printf("Ether: %04x dest ", ether->ehdr.ether_type);
      for(i = 0; i < ETH_ALEN; i++)
         printf("%02hhx", ether->ehdr.ether_dhost[i]);
      printf(" src ");
      for(i = 0; i < ETH_ALEN; i++)
         printf("%02hhx", ether->ehdr.ether_shost[i]);
      printf("\n");
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

void sighandler(int signal)
{
   switch(signal) {
   case SIGINT:
      periscope_collector_stop(&g_collector);
      break;

   case SIGHUP:
      printf("Attempting asynchronous connection to 127.0.0.1...\n");
      
      if(periscope_argus_remote_direct_connect(&g_collector, "127.0.0.1") == NULL)
         printf("Asynchronous connect failed!\n");

      break;
   }
}

int
periscope_test_suite(int *ntest)
{
   int i, fail = 0, tests = 0;
   /* Test suite */
   tests++;
   if(periscope_argus_remote_add(&g_collector, "")) {
      printf("FAIL Added an empty string hostname.\n");
      fail++;
   } else printf("PASS Adding empty string hostname failed.\n");

   tests++;
   if(periscope_argus_remote_add(&g_collector, "a")) {
      printf("FAIL Added non-resolving remote w/hostname 'a'\n");
      fail++;
   } printf("PASS Adding non-resolving hostname string failed.\n");
   
   {
      tests++;
      struct ArgusInput *input = periscope_argus_remote_add(&g_collector, "127.0.0.1");
      if(input == NULL) {
         printf("FAIL add 127.0.0.1.\n");
         fail++;
      } else {
         printf("PASS add 127.0.0.1.\n");
      }

      tests++;
      for (i = 0; i < 5; i++) {
         if (periscope_argus_remote_add(&g_collector, "127.0.0.1") != NULL) {
            printf("FAIL duplicate host add must return error.\n");
            fail++;
            break;
         }
      }
      if(i == 5)
         printf("PASS duplicate host add returned error.\n");

      tests++;
      if(periscope_argus_remote_remove(&g_collector, input) < 0) {
         printf("FAIL remove 127.0.0.1\n");
         fail++;
      } else {
         printf("PASS remove 127.0.0.1\n");
      }
   }

   tests++;
   {
      struct ArgusQueueHeader *hdr;
      struct ArgusInput *input;
      struct PeriscopeInputInfo info;
      
      input = periscope_argus_remote_add(&g_collector, "tinderbox:561");
      hdr = periscope_argus_remote_pending_queue(&g_collector);
      i = 0;

      do {
         hdr = hdr->nxt;
         i++;
      } while(hdr != hdr->queue->end);
      printf("Official count: %d Recorded count: %d\n", hdr->queue->count, i);

      if(periscope_argus_remote_info(input, &info) < 0) {
         fail++;
         printf("FAIL remote info get!\n");
      } else {
         printf("PASS remote info: Ver. %d.%d host %s port %hu\n",
                info.major_version, info.minor_version,
                info.hostname, info.port);
      }
      periscope_argus_remote_remove(&g_collector, input);
      
   }
         

   if(ntest) *ntest = tests;
   return fail;
}

int
main (int argc, char **argv)
{
   int i, sources = (argc - 1);
   struct sigaction signals;
   char *filter = "tcp and fin and finack";

   /* Set up signal handling for SIGINT. */
   signals.sa_handler = sighandler;
   signals.sa_flags = 0;
   sigemptyset(&signals.sa_mask);

   sigaction(SIGINT, &signals, NULL);
   sigaction(SIGHUP, &signals, NULL);

   /* Initialize Periscope. */
   if(periscope_collector_init(&g_collector) < 0) {
      fprintf(stderr, "Error initializing Periscope!\n");
      exit(1);
   }

   g_collector.callbacks.process_flow = process_flow;
   g_collector.callbacks.input_complete = input_source_completed;

   if(argc >= 2 && strcmp(argv[1], "unittest") == 0) {
      int tests, fail;

      printf("Running libperiscope C Unit Test Suite.\n");
      fail = periscope_test_suite(&tests);

      if(fail > 0) {
         printf("Failed %d of %d tests!\n", fail, tests);
      } else
         printf("All %d tests passed!\n", tests);
   } else {
      for(i = 0; i < sources; i++) {
         if(strcmp(argv[1+i], "remote") == 0) {
            i++;
            break;
         }
         
         if(periscope_argus_local_add(&g_collector, argv[1+i]) == -1) {
            fprintf(stderr, "Periscope: file '%s' doesn't exist.\n", argv[1+i]);
            exit(1);
         }
      }
      for(; i < sources; i++) {
         if(periscope_argus_remote_add(&g_collector, argv[1+i]) == NULL) {
            fprintf(stderr, "Periscope: host '%s' is not valid, or duplicate!\n", argv[1+i]);
         }
      }
      
      if(filter) {
         if(periscope_argus_set_filter(&g_collector, filter) < 0) {
            fprintf(stderr, "Periscope: syntax error in filter '%s'!\n", filter);
            periscope_collector_free(&g_collector);
            exit(1);
         }
      }
      
      /* Runs the Argus processor on both local and remote sources.
       * Eventually we will want to separate this, so local files can be
       * processed at any time with another parser in another thread. */
      periscope_collector_run(&g_collector);

      /* Once Argus completes processing local and remote data sources,
       * close all sources and free memory associated with Periscope and
       * Argus. */
      periscope_collector_free(&g_collector);
      
      printf("Periscope: Shutting down after normal operation.\n");
   }
   return 0;
}
