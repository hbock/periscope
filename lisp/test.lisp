;;;; Periscope - Network auditing tool
;;;; Copyright (C) 2009 Harry Bock <harry@oshean.org>

;;;; This file is part of Periscope.

;;;; periscope is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2 of the License, or
;;;; (at your option) any later version.

;;;; periscope is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.

;;;; You should have received a copy of the GNU General Public License
;;;; along with periscope; if not, write to the Free Software
;;;; Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
(in-package :periscope)

(define-report-handler (split-test "/time-split" "Time Split Test") ()
  (with-periscope-page ("TIME-SPLIT test")
    (when *flow-list*
      (let* ((time-list
	      (time-split *flow-list*))
	     (reports (mapcar (lambda (list)
				(make-instance 'periodic-report :flow-list list)) time-list)))
	(htm
	 (:div
	  :class "stats"
	  (loop
	     for i from 0 upto (length time-list)
	     for report in reports do
	     (htm
	      
	      (:h3 (fmt "Report for flows from ~a -> ~a"
			(iso8661-date-string (start-time (first (nth i time-list))))
			(iso8661-date-string (start-time (first (last (nth i time-list)))))))
	      (:p (fmt "Generated at ~a"
		       (iso8661-date-string
			(universal-to-timestamp (report-time report)))))
	      (:table
	       (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
	       (print-html (total report) :title "Total")
	       (print-html (internal report) :title "Internal Only")
	       (print-html (external report) :title "External Only")
	       (print-html (incoming report) :title "Incoming")
	       (print-html (outgoing report) :title "Outgoing"))
	      (:table
	       (:tr (:th :colspan 4 "Source") (:th :colspan 4 "Destination")
		    (:th :colspan 3 "Flow information"))
	       (:tr (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		    (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		    (:th "Protocol") (:th "First Seen") (:th "Last Seen"))
	       (loop :for flow :in (nth i time-list) :repeat 100 :do
		  (print-html flow)))))))))))

(define-report-handler (test "/vlan-test" "VLAN Filter Test") ()
  (with-periscope-page ("Test data")
    (:h2 (who:fmt "Flow List (~d flows processed)" (length *flow-list*)))
    (when *flow-list*
      (let* ((filtered-flows
	      (append (list *flow-list*)
		      (apply-filters *flow-list* (list (vlan-filter 100) (vlan-filter 200)))))
	     (reports (mapcar (lambda (list)
				(make-instance 'periodic-report :flow-list list)) filtered-flows)))
	(who:htm
	 (:div
	  :class "stats"
	  (loop
	     for i from 0 upto (length filtered-flows)
	     for report in reports do
	       (htm
		(:h3 (fmt "Report generated at ~a" (iso8661-date-string
						    (local-time:universal-to-timestamp
						     (report-time report)))))
		(:table
		 (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
		 (print-html (total report) :title "Total")
		 (print-html (internal report) :title "Internal Only")
		 (print-html (external report) :title "External Only")
		 (print-html (incoming report) :title "Incoming")
		 (print-html (outgoing report) :title "Outgoing"))
		(:table
		 (:tr (:th :colspan 4 "Source") (:th :colspan 4 "Destination")
		      (:th :colspan 3 "Flow information"))
		 (:tr (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		      (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		      (:th "Protocol") (:th "First Seen") (:th "Last Seen"))
		 (loop :for flow :in (nth i filtered-flows) :repeat 100 :do
		    (print-html flow)))))))))))