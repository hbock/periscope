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

(defclass service (report)
  (hash))

(defclass service-stats ()
  ((bytes-source :accessor bytes-source :initform 0)
   (bytes-dest :accessor bytes-dest :initform 0)
   (packets-source :accessor packets-source :initform 0)
   (packets-dest :accessor packets-dest :initform 0)))

(defmethod initialize-instance :after ((object service) &key
				       (flows (error "Need flowz!"))
				       (ports *notable-ports*))
  (with-slots (hash) object
    (setf hash (make-hash-table :size (length ports)))
    (dolist (flow flows)
      (with-slots (protocol port-source port-dest bytes-source bytes-dest
			    packets-source packets-dest) flow
	(case protocol
	  ((#.+ip-proto-udp+ #.+ip-proto-tcp+)
	   (when (find port-source ports)
	     (let ((service (gethash port-source hash (make-instance 'service-stats))))
	       (incf (bytes-source service) bytes-source)
	       (incf (packets-source service) packets-source)
	       (setf (gethash port-source hash) service)))
	   (when (find port-dest ports)
	     (let ((service (gethash port-dest hash (make-instance 'service-stats))))
	       (incf (bytes-dest service) bytes-dest)
	       (incf (packets-dest service) packets-dest)
	       (setf (gethash port-dest hash) service)))))))))

(defmethod print-report ((object service))
  (with-slots (hash) object
    (loop :for port :being :the :hash-keys :in hash :using (:hash-value service) :do
       (format t "Port ~d: (source ~d bytes ~d packets) (dest ~d bytes ~d packets~%"
	       port (bytes-source service) (packets-source service)
	       (bytes-dest service) (packets-dest service)))))

(defmethod print-html ((object service) &key)
  (with-html-output (*standard-output*)
    (:div
     :class "stats"
     (:table
      (:tr (:th "") (:th :colspan 2 "Source") (:th :colspan 2 "Destination"))
      (:tr (:th "Service") (:th "Bytes") (:th "Packets") (:th "Bytes") (:th "Packets"))
      (with-slots (hash) object
	(loop :for port :being :the :hash-keys :in hash :using (:hash-value service) :do
	   (htm
	    (:tr (:td (str port))
		 (:td (str (bytes-source service)))
		 (:td (str (packets-source service)))
		 (:td (str (bytes-dest service)))
		 (:td (str (packets-dest service)))))))))))

(hunchentoot:define-easy-handler (service :uri "/service") (time)
  (with-periscope-page ("Service Statistics")
    (print-html
     (make-instance 'service :flows *flow-list*))))


