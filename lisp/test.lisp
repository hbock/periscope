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

(defvar *flows* 0)
(defvar *ipv4* 0)
(defvar *this-flow* nil)
(defvar *flow-list* nil)

(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4
     (incf *ipv4*)
     (let ((ip (get-ip (foreign-slot-value dsrs 'periscope-dsrs 'flow))))
       (with-foreign-slots ((ip-src ip-dst ip-proto source-port dest-port) ip argus-ip-flow)
	 (push (make-instance 'flow :ip-source ip-src :ip-dest ip-dst :port-source source-port
			      :port-dest dest-port :protocol ip-proto)
	       *flow-list*))))
    (:ipv6 (format t "IPV6!~%")))
  
  (incf *flows*))

(defun init-basic-collector ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    collector))

(defun test-start-periscope ()
  (start-web)
  (setf *collector* (init-basic-collector)))

(defun test-argus (&optional (file "argus.1"))
  (let ((collector (init-basic-collector)))
    (add-file collector file)
    (run collector)))

(hunchentoot:define-easy-handler (stop-page :uri "/stop") ()
  (stop *collector*)
  (with-periscope-page ("Stopping collector.")
    (:h3 "Collector stopped")
    "Please put your trays in the upright position before landing Periscope."))

(hunchentoot:define-easy-handler (test :uri "/test") ()
  (with-periscope-page ("Test data")
    (:h2 (who:fmt "Flow List (~d flows processed)" *flows*))
    (when *flow-list*
      (who:htm
       (:div
	:class "stats"
	(:table
	 (:tr (:th "Source") (:th "Destination") (:th "Protocol"))
	 (dolist (flow *flow-list*)
	   (with-slots (ip-source ip-dest port-source port-dest protocol) flow
	     (who:htm
	      (:tr
	       (:td (who:fmt "~a:~d" (ip-string ip-source) port-source))
	       (:td (who:fmt "~a:~d" (ip-string ip-dest) port-dest))
	       (:td (who:str
		     (case protocol
		       (1 "ICMP")
		       (2 "IGMP")
		       (6 "TCP")
		       (17 "UDP"))))))))))))))