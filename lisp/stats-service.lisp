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

(defclass service-report (statistics-report)
  (hash
   (ports :initform *notable-ports* :accessor service-ports)))

(defclass service-traffic-stats (traffic-stats)
  ((service-type :col-type integer :initarg :service-type :accessor service-type
		 :documentation "Service type (TCP/UDP port, protocol, etc.)")
   (identifier :col-type integer :initarg :identifier :reader service-identifier
	       :documentation "Port or protocol number."))
  (:metaclass pomo:dao-class)
  (:keys service-type identifier))

(defclass service-stats ()
  ((filter    :initarg :filter   :type filter :reader filter)
   (timestamp :initarg :timestamp :type simple-date:timestamp :reader report-time)
   (total    :accessor total    :type service-traffic-stats)
   (incoming :accessor incoming :type service-traffic-stats)
   (outgoing :accessor outgoing :type service-traffic-stats)))

(defmethod initialize-instance :after ((object service-report) &key
				       (ports *notable-ports*))
  (setf (slot-value object 'hash) (make-hash-table :size (* 3 (length ports)))
	(service-ports object) ports))

(defmethod initialize-instance :after ((object service-stats) &key service-type identifier)
  (with-slots (filter) object
    (loop :for stats :in '(incoming outgoing total)
       ;; :INCOMING starts at 3, rest are sequential.
       ;; TODO: Make me less hard-coded.
       :for i = 3 :then (1+ i) :do
       (setf (slot-value object stats)
	     (make-instance 'service-traffic-stats :type i
			    :filter-id (filter-id filter)
			    :timestamp (report-time object)
			    :service-type service-type
			    :identifier identifier)))))

(defmethod print-html ((object service-traffic-stats) &key (flows t))
  (with-html-output (*standard-output*)
    (htm
     (:td (fmt "~:d" (packets object)))
     (:td (str (byte-string (bytes object))))
     (when flows
       (htm (:td (fmt "~:d" (flows object))))))))

(defun sql-enum->service-stats-type (sql-enum)
  (ecase sql-enum
    (0 :port)
    (1 :protocol)))

(defun service-stats-type->sql-enum (type)
  (etypecase type
    (integer type)
    (keyword
     (ecase type
       (:port     0)
       (:protocol 1)))))

(defmethod commit ((object service-traffic-stats) &key)
  (let ((type (service-type object)))
    (unwind-protect
	 (progn
	   (setf (service-type object) (service-stats-type->sql-enum type))
	   (pomo:save-dao object)
	   (setf (service-type object) type)))))

(defmethod commit ((report service-report) &key)
  (maphash (lambda (identifier service-stats)
	     (with-slots (incoming outgoing total) service-stats
	       (commit incoming)
	       (commit outgoing)
	       (commit total)))
	   (slot-value report 'hash)))

(defmethod add-flow ((report service-report) (flow flow))
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
		  (service (gethash type hash
				    (make-instance 'service-stats
						   :filter (filter report)
						   :timestamp (report-time report)
						   :service-type :protocol
						   :identifier protocol))))
	     (add-to-service service flow bytes packets)
	     (setf (gethash type hash) service))
	   ;; We are only interested in the destination port of the flow, which
	   ;; tells us the intended service.
	   (when (find (host-port dest) ports)
	     (let* ((port (host-port dest))
		    (service (gethash port hash 
				      (make-instance 'service-stats
						     :filter (filter report)
						     :timestamp (report-time report)
						     :service-type :port
						     :identifier port))))
	       (add-to-service service flow bytes packets)
	       (setf (gethash port hash) service)))))))))

(defmethod add-to-service ((object service-stats) flow bytes packets)
  (with-slots (total incoming outgoing) object
    (add-traffic-stats total bytes packets)
    (case (classify flow)
      (:incoming (add-traffic-stats incoming bytes packets))
      (:outgoing (add-traffic-stats outgoing bytes packets)))))

(defmethod print-matched-stats ((object service-report) predicate &optional label-fun)
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

(defmethod print-service-stats ((object service-report) &optional (type :port) label-fun)
  (flet ((unique-identifiers ()
	   ;; Find all unique identifiers (ports or protocols) matching this filter and
	   ;; service type (port/protocol).
	   ;; Return as a list of single values instead of a list of lists with a single value.
	   (query (:select (:distinct 'identifier) :from 'service-traffic-stats
			   :where (:and (:= 'filter-id (filter-id object))
					(:= 'timestamp (report-time object))
					(:= 'service-type (service-stats-type->sql-enum type))))
		  :column)))
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
	(dolist (identifier (unique-identifiers))
	  (htm
	   (:tr
	    (:td (str (if label-fun (funcall label-fun identifier) identifier)))
	    ;; Grab each category of traffic for each individual identifier recorded.
	    ;; ORDER BY type - Incoming, Outgoing, Total, in that order.
	    (dolist (stat (pomo:select-dao 'service-traffic-stats
					   (:and (:= 'filter-id (filter-id object))
						 (:= 'timestamp (report-time object))
						 (:= 'service-type (service-stats-type->sql-enum type))
						 (:= 'identifier identifier)) 'type))
	      (print-html stat))))))))))

(defmethod print-html ((object service-report) &key)
  (with-html-output (*standard-output*)
    (:h3 "Service Statistics")
    (:b "Tracked services: ")
    (fmt "~{~a~^, ~} " (mapcar #'service-name *notable-ports*))
    (when (configure-p)
      (htm (:a :href "/network-config" "(edit)")))
    (print-service-stats object :port #'service-name)
    
    (:h3 "Protocol Statistics")
    (:b "Tracked protocols: " )
    (fmt "~{~a~^, ~} " '(:tcp :udp :icmp))
    (print-service-stats object :protocol #'protocol-name)))

;;; DEPRECATED. DO NOT USE!
(defun make-service-stats ()
  (make-instance 'service-stats))