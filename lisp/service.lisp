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
  ((total :accessor total :type stats :initform (make-instance 'stats))
   (incoming :accessor incoming :type stats :initform (make-instance 'stats))
   (outgoing :accessor outgoing :type stats :initform (make-instance 'stats))))

(defmethod initialize-instance :after ((object service) &key
				       (flow-list (error "Need flowz!"))
				       (ports *notable-ports*))
  (with-slots (hash) object
    (setf hash (make-hash-table :size (length ports)))
    (dolist (flow flow-list)
      (with-slots (protocol source dest) flow
	(case protocol
	  ((#.+ip-proto-udp+ #.+ip-proto-tcp+)
	   (when (find (host-port dest) ports)
	     (let* ((port (host-port dest))
		    (bytes (+ (host-bytes source) (host-bytes dest)))
		    (packets (+ (host-packets source) (host-packets dest)))
		    (service (gethash port hash (make-instance 'service-stats))))

	       (with-slots (total incoming outgoing) service
		 (add-stats total :bytes (host-bytes dest) :packets (host-packets dest))
		 (case (classify flow)
		   (:incoming (add-stats incoming :bytes bytes :packets packets))
		   (:outgoing (add-stats outgoing :bytes bytes :packets packets))))
	       (setf (gethash port hash) service)))))))))

(defmethod print-html ((object service) &key)
  (with-html-output (*standard-output*)
    (:h3 "Service Statistics")
    (:b "Tracked services, port numbers: ")
    (fmt "~{~a~^, ~} " (mapcar #'service-name *notable-ports*))
    (when (and (user) (admin-p (user)))
      (htm (:a :href "/config" "(edit)")))

    (:div
     :class "stats"
     (:table
      (:tr (:th "")
	   (:th :colspan 3 "Incoming")
	   (:th :colspan 3 "Outgoing")
	   (:th :colspan 3 "Total"))
      (:tr (:th "Service")
	   (:th "Packets") (:th "Bytes") (:th "Flows")
	   (:th "Packets") (:th "Bytes") (:th "Flows")
	   (:th "Packets") (:th "Bytes") (:th "Flows"))
      (with-slots (hash) object
	(loop :for port :being :the :hash-keys :in hash :using (:hash-value service) :do
	   (with-slots (total incoming outgoing) service
	     (htm
	      (:tr
	       (:td (str (service-name port)))
	       (print-html incoming :with-row nil)
	       (print-html outgoing :with-row nil)
	       (print-html total :with-row nil))))))))))

(defun make-service-report (flow-list)
  (make-instance 'service :flow-list flow-list))