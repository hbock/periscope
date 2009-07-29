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
				       (flow-list (error "Need flowz!"))
				       (ports *notable-ports*))
  (with-slots (hash) object
    (setf hash (make-hash-table :size (length ports)))
    (dolist (flow flow-list)
      (with-slots (protocol source dest) flow
	(case protocol
	  ((#.+ip-proto-udp+ #.+ip-proto-tcp+)
	   (when (find (host-port source) ports)
	     (let* ((port (host-port source))
		    (service (gethash port hash (make-instance 'service-stats))))
	       (incf (bytes-source service) (host-bytes source))
	       (incf (packets-source service) (host-packets source))
	       (setf (gethash port hash) service)))
	   (when (find (host-port dest) ports)
	     (let* ((port (host-port dest))
		    (service (gethash port hash (make-instance 'service-stats))))
	       (incf (bytes-dest service) (host-bytes dest))
	       (incf (packets-dest service) (host-packets dest))
	       (setf (gethash port hash) service)))))))))

(defmethod print-html ((object service) &key)
  (with-html-output (*standard-output*)
    (:h3 "Service Statistics")
    (:b "Tracked services, port numbers: ")
    (fmt "~{~a~^, ~}" (mapcar #'service-name *notable-ports*))
    (when (and (user) (admin-p (user)))
      (htm (:a :href "/config" "(edit)")))

    (:div
     :class "stats"
     (:table
      (:tr (:th "") (:th :colspan 2 "Source") (:th :colspan 2 "Destination"))
      (:tr (:th "Service") (:th "Bytes") (:th "Packets") (:th "Bytes") (:th "Packets"))
      (with-slots (hash) object
	(loop :for port :being :the :hash-keys :in hash :using (:hash-value service) :do
	   (htm
	    (:tr (:td (str (or (service-name port) port)))
		 (:td (str (byte-string (bytes-source service))))
		 (:td (fmt "~:d" (packets-source service)))
		 (:td (str (byte-string (bytes-dest service))))
		 (:td (fmt "~:d" (packets-dest service)))))))))))

(define-report-handler (service "/service" "Service Type") ()
  (with-periscope-page ("Service Statistics")
    (print-html (make-instance 'service :flow-list *flow-list*))))

(defun make-service-report (flow-list)
  (make-instance 'service :flow-list flow-list))