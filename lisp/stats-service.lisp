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

(defclass service-stats (statistics-report)
  (hash
   (ports :initform *notable-ports* :accessor service-ports)))

(defclass service-traffic-stats ()
  ((total :accessor total :type stats :initform (make-instance 'stats))
   (incoming :accessor incoming :type stats :initform (make-instance 'stats))
   (outgoing :accessor outgoing :type stats :initform (make-instance 'stats))))

(defmethod initialize-instance :after ((object service-stats) &key
				       (ports *notable-ports*))
  (setf (slot-value object 'hash) (make-hash-table :size (* 3 (length ports)))
	(service-ports object) ports))

(defmethod add-flow ((report service-stats) (flow flow))
  (with-slots (hash ports) report
    (with-slots (protocol source dest) flow
      (case protocol
	;; We are only interested in TCP/UDP services and ICMP requests/replies.
	((#.+ip-proto-udp+ #.+ip-proto-tcp+ #.+ip-proto-icmp+)
	 (let ((bytes (+ (host-bytes source) (host-bytes dest)))
	       (packets (+ (host-packets source) (host-packets dest))))
	   ;; Calculate statistics about the transport layer protocol of the flow
	   (let* ((type (case protocol
			  (#.+ip-proto-tcp+ :tcp)
			  (#.+ip-proto-udp+ :udp)
			  (#.+ip-proto-icmp+ :icmp)))
		  (service (gethash type hash (make-instance 'service-traffic-stats))))
	     (add-to-service service flow bytes packets)
	     (setf (gethash type hash) service))
	   ;; We are only interested in the destination port of the flow, which
	   ;; tells us the intended service.
	   (when (find (host-port dest) ports)
	     (let* ((port (host-port dest))
		    (service (gethash port hash (make-instance 'service-traffic-stats))))
	       (add-to-service service flow bytes packets)
	       (setf (gethash port hash) service)))))))))

(defmethod finalize-report ((report service-stats))
  (format t "Finalized service report."))

(defmethod add-to-service ((object service-traffic-stats) flow bytes packets)
  (with-slots (total incoming outgoing) object
    (add-stats total :bytes bytes :packets packets)
    (case (classify flow)
      (:incoming (add-stats incoming :bytes bytes :packets packets))
      (:outgoing (add-stats outgoing :bytes bytes :packets packets)))))

(defmethod print-matched-stats ((object service-stats) predicate &optional label-fun)
  "Print statistics for services matching predicate, optionally transforming the name
of the service with label-fun."
  (with-html-output (*standard-output*)
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
	(loop :for port :being :the :hash-keys :in hash :using (:hash-value service-stats)
	   :when (funcall predicate port) :do
	   (with-slots (total incoming outgoing) service-stats
	     (htm
	      (:tr
	       (:td (str (if label-fun (funcall label-fun port) port)))
	       (print-html incoming :with-row nil)
	       (print-html outgoing :with-row nil)
	       (print-html total :with-row nil))))))))))

(defmethod print-html ((object service-stats) &key)
  (with-html-output (*standard-output*)
    (:h3 "Service Statistics")
    (:b "Tracked services: ")
    (fmt "~{~a~^, ~} " (mapcar #'service-name *notable-ports*))
    (when (configure-p)
      (htm (:a :href "/network-config" "(edit)")))
    (print-matched-stats object (lambda (val) (typep val 'port-number))	#'service-name)
    
    (:h3 "Protocol Statistics")
    (:b "Tracked protocols: " )
    (fmt "~{~a~^, ~} " '(:tcp :udp :icmp))
    (print-matched-stats object #'keywordp)))

(defun make-service-stats ()
  (make-instance 'service-stats))