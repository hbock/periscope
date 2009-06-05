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

(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type)
    (:ipv4
     (incf *ipv4*)
     (let ((ip (get-ip (foreign-slot-value dsrs 'periscope-dsrs 'flow))))
       (with-foreign-slots ((ip-src ip-dst ip-proto) ip argus-ip-flow)
	 (case (foreign-enum-keyword 'ip-protocols ip-proto)
	   (:icmp (format t "ICMP!~%"))
	   (:tcp (format t "TCP!~%"))
	   (:udp (format t "UDP!~%"))))))
    (:ipv6 (format t "IPV6!~%")))
  
  (incf *flows*))

(defun test-argus ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
      (setf process_flow (callback receive-flow)))
    (setf *flows* 0
	  *ipv4* 0)
    (add-file collector "argus.1")
    (start collector)
    (stop collector)
    (format t "Handled ~a flows (~a IPv4)!~%" *flows* *ipv4*)
    1))


