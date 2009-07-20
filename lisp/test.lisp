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
	      (time-split *flow-list* #'next-hour))
	     (reports (mapcar (lambda (list)
				(make-instance 'periodic-report :flow-list list)) time-list)))
	(htm
	 (:div
	  :class "stats"
	  (loop
	     for i from 0 upto (length time-list)
	     for report in reports do
	     (print-html report)
	     (htm
	      (:table
	       (:tr (:th :colspan 4 "Source") (:th :colspan 4 "Destination")
		    (:th :colspan 3 "Flow information"))
	       (:tr (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		    (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
		    (:th "Protocol") (:th "First Seen") (:th "Last Seen"))
	       (loop :for flow :in (nth i time-list) :repeat 100 :do
		  (print-html flow)))))))))))

(define-report-handler (test "/vlan-test" "VLAN Filter Test") ()
  (with-periscope-page ("VLAN Filter Test")
    (:h2 (fmt "VLAN Filter Test - ~d flows processed" (length *flow-list*)))
    (when *flow-list*
      (let* ((filtered-flows
	      (if (and (user) (filters (user)))
		  (apply-filters *flow-list* (filter-predicates (user)))
		  (list *flow-list*)))
	     (reports
	      (mapcar (lambda (list)
			(make-instance 'periodic-report :flow-list list)) filtered-flows)))
	(htm
	 (:div
	  :class "stats"
	  (if (user)
	      (loop
		 for report in reports
		 for filter in (filters (user)) do
		 (print-html report :filter filter))
	      (loop
		 for report in reports do
		 (print-html report)))
	  (:h3 "First 100 Flows")
	  (print-flows (first filtered-flows))))))))

(defun print-flows (flow-list &optional (limit 100))
  (with-html-output (*standard-output*)
    (:table
     (:tr (:th :colspan 4 "Source")
	  (:th :colspan 4 "Destination")
	  (:th :colspan 3 "Flow information"))
     (:tr (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
	  (:th "IP") (:th "Port") (:th "Packets") (:th "VLAN")
	  (:th "Protocol") (:th "First Seen") (:th "Last Seen"))
     (loop :for flow :in flow-list :repeat limit :do
	(print-html flow)))))