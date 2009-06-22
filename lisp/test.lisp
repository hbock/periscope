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

(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4
     (let ((ip (get-ip (get-flow dsrs))))
       (with-foreign-slots ((ip-src ip-dst ip-proto source-port dest-port) ip argus-ip-flow)
	 (multiple-value-bind (src-packets src-bytes) (source-metrics dsrs)
	   (multiple-value-bind (dst-packets dst-bytes) (dest-metrics dsrs)
	     (let ((flow (make-instance 'flow
					:ip-source ip-src :ip-dest ip-dst
					:port-source source-port :port-dest dest-port
					:protocol ip-proto
					:packets-source src-packets :packets-dest dst-packets
					:bytes-source src-bytes :bytes-dest dst-bytes)))
	       (unless (null-pointer-p (get-vlan dsrs))
		 (with-foreign-slots ((sid did) (get-vlan dsrs) argus-vlan)
		   (with-slots (vlan-source vlan-dest) flow
		     (setf vlan-source sid
			   vlan-dest did))))
	       (push flow *flow-list*)))))))))

(defun init-basic-collector ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    collector))

(defun test-start-periscope ()
  (start-web)
  (setf *collector* (init-basic-collector)))

(defun test-argus (&optional (file "argus.1"))
  (setf *flow-list* nil)
  (let ((collector (init-basic-collector)))
    (add-file collector file)
    (run collector)))

(define-report-handler (test "/test" "Last 100 Flows") ()
  (with-periscope-page ("Test data")
    (:h2 (who:fmt "Flow List (~d flows processed)" (length *flow-list*)))
    (when *flow-list*
      (let ((report (make-instance 'periodic-report :flow-list *flow-list*)))
	(who:htm
	 (:h3 (fmt "Report generated at ~a" (utc-date-string (report-time report))))
	 (:div
	  :class "stats"
	  (:table
	   (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
	   (print-html (total report) :title "Total")
	   (print-html (internal report) :title "Internal Only")
	   (print-html (external report) :title "External Only")
	   (print-html (incoming report) :title "Incoming")
	   (print-html (outgoing report) :title "Outgoing"))
	  (:table
	   (:tr (:th :colspan 3 "Source") (:th :colspan 3 "Destination") (:th "Flow information"))
	   (:tr (:th "IP") (:th "Port") (:th "Packets") (:th "IP") (:th "Port") (:th "Packets")
		(:th "Protocol"))
	   (loop :for flow :in *flow-list* :repeat 100 :do
	      (print-html flow)))))))))