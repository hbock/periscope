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
(defvar *collector* nil)

(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4
     (incf *ipv4*)
     (let ((ip (get-ip (foreign-slot-value dsrs 'periscope-dsrs 'flow))))
       (with-foreign-slots ((ip-src ip-dst ip-proto) ip argus-ip-flow)
	 (case (foreign-enum-keyword 'ip-protocols ip-proto :errorp nil)
	   (:icmp (format t "ICMP!~%"))
	   (:tcp (format t "TCP!~%"))
	   (:udp (format t "UDP!~%"))))))
    (:ipv6 (format t "IPV6!~%")))
  
  (incf *flows*))

(defun init-basic-collector ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    collector))

(defun test-argus (&optional (file "argus.1"))
  (let ((collector (init-basic-collector)))
    (add-file collector file)
    (run collector)
    (stop collector)
    1))

(hunchentoot:define-easy-handler (stop-page :uri "/stop") ()
  (stop *collector*)
  (with-periscope-page ("Stopping collector.")
    (:h3 "Collector stopped")
    "Please put your trays in the upright position before landing Periscope."))

(hunchentoot:define-easy-handler (start-page :uri "/start") ()
  (setf *flows* 0
	*ipv4* 0)
  (start *collector*)
  (with-periscope-page ("Starting collector.")
    (:h3 "Collector started")
    "AYEEEEEEEEEEE"))

(hunchentoot:define-easy-handler (test :uri "/test") (file remote)
  
  (when file
    (test-argus file))
  (when remote
    (add-remote *collector* remote))
  (with-periscope-page ("Testing Argus! (BOOM?)")
    (:h3 "Testing the Argus processor...")
    (when remote
      (who:htm
       (who:fmt "Added remote source ~a to collector!" remote)
       (:br)))
    (who:fmt "Processed ~a flows, with ~a IPv4!" *flows* *ipv4*)))