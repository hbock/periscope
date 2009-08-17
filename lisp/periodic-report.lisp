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

(defvar *periodic-report-format-version* 0
  "Current version of the PERIOD-REPORT file/class format. Used to ensure older report formats
are processed correctly, or a proper error is signalled when a report format is no longer
supported.")

(defclass periodic-report (report)
  ((total :accessor total :type stats :initform (make-instance 'stats))
   (internal :accessor internal :type stats :initform (make-instance 'stats))
   (external :accessor external :type stats :initform (make-instance 'stats))
   (incoming :accessor incoming :type stats :initform (make-instance 'stats))
   (outgoing :accessor outgoing :type stats :initform (make-instance 'stats))
   (host-stats :initform (make-hash-table :size 100000))
   (format-version :initarg :version :initform *periodic-report-format-version*)
   (filter :initarg :filter :reader filter :initform nil :type filter)
   (report-time :initarg :time :reader report-time :initform (now))))

(defclass host-stats ()
  ((ip :initarg :ip :accessor host-ip :initform (error "Must provide IP!"))
   (total :accessor total :type stats)
   (sending :accessor sending :type stats :initform (make-instance 'stats))
   (receiving :accessor receiving :type stats :initform (make-instance 'stats))
   (local-contacts :initform (make-hash-table))
   (remote-contacts :initform (make-hash-table))))

(defmethod add-host-stats ((table hash-table) (host flow-host) (other flow-host))
  (multiple-value-bind (host-stat existsp)
      (gethash (host-ip host) table (make-instance 'host-stats :ip (host-ip host)))
    (with-slots (sending receiving local-contacts remote-contacts) host-stat
      (let ((other-ip (host-ip other)))
	(incf (gethash other-ip (if (remote-host-p other-ip) remote-contacts local-contacts) 0)))
      (add-stats sending   :bytes (host-bytes host) :packets (host-packets host))
      (add-stats receiving :bytes (host-bytes other) :packets (host-packets other)))
    (unless existsp
      (setf (gethash (host-ip host) table) host-stat))))

(defmethod initialize-instance :after ((object periodic-report) &key (flow-list nil flow-list-p))
  (declare (ignore flow-list flow-list-p))
  (setf (slot-value object 'format-version) *periodic-report-format-version*))

(defmethod nadd ((report periodic-report) (flow flow))
  (with-slots (total internal external incoming outgoing host-stats) report
    (with-slots (source dest) flow
      (let ((bytes (+ (host-bytes source) (host-bytes dest)))
	    (packets (+ (host-packets source) (host-packets dest))))
	(add-stats total :bytes bytes :packets packets)
	(case (classify flow)
	  (:internal-only (add-stats internal :bytes bytes :packets packets))
	  (:external-only (add-stats external :bytes bytes :packets packets))
	  (:incoming  (add-stats incoming :bytes bytes :packets packets))
	  (:outgoing  (add-stats outgoing :bytes bytes :packets packets)))

	(add-host-stats host-stats source dest)
	(add-host-stats host-stats dest source)))))

(defmethod local-contact-count ((host host-stats))
  (hash-table-count (slot-value host 'local-contacts)))

(defmethod remote-contact-count ((host host-stats))
  (hash-table-count (slot-value host 'remote-contacts)))

(defmethod hosts-collect-if ((object periodic-report) predicate)
  (with-slots (host-stats) object
    (loop :for host-ip :being :the :hash-keys :in host-stats :using (:hash-value stats)
       :when (funcall predicate host-ip)
       :collect stats)))

(defmethod remote-hosts ((object periodic-report))
  (hosts-collect-if object #'remote-host-p))

(defmethod local-hosts ((object periodic-report))
  (hosts-collect-if object #'local-host-p))

(defun busiest-hosts (stat-list)
  (sort stat-list #'> :key (lambda (stats)
			     (+ (bytes (receiving stats)) (bytes (sending stats))))))

(defmethod incoming-scan-hosts ((report periodic-report))
  (sort (remove-if #'zerop (remote-hosts report) :key #'local-contact-count)
	#'> :key #'local-contact-count))

(defmethod outgoing-scan-hosts ((report periodic-report))
  (sort (remove-if #'zerop (local-hosts report) :key #'remote-contact-count)
	#'> :key #'remote-contact-count))

(defun print-scan-hosts (title host-type list &key key)
  (with-html-output (*standard-output*)
    (:table
     (:tr (:th :colspan 4 (str title)))
     (:tr (:th "Host") (:th "Hostname") (:th (fmt "~a Hosts Contacted" host-type)))
     (loop :with row-switch = t
	:for host :in list :repeat 15 :do
	(htm
	 (:tr
	  :class (if row-switch "rowa" "rowb")
	  (:td (str (ip-string (host-ip host))))
	  (:td (str (hostname (host-ip host))))
	  (:td (str (funcall key host)))))
	(setf row-switch (not row-switch))))))

(defun print-busiest-hosts (title list)
  (with-html-output (*standard-output*)
    (:table
     (:tr (:th :colspan 9 (str title)))
     (:tr (:th) (:th)
	  (:th :colspan 2 "Sending")
	  (:th :colspan 2 "Receiving")
	  (:th :colspan 3 "Total"))
     (:tr (:th "Host") (:th "Hostname")
	  (:th "Packets") (:th "Bytes")
	  (:th "Packets") (:th "Bytes")
	  (:th "Packets") (:th "Bytes") (:th "Flows"))
     (loop :with row-switch = t
	:for host :in list :repeat 15 :do
	(htm
	 (:tr
	  :class (if row-switch "rowa" "rowb")
	  (:td (str (ip-string (host-ip host))))
	  (:td (str (hostname (host-ip host))))
	  (print-html (receiving host) :with-row nil :flows nil)
	  (print-html (sending host)   :with-row nil :flows nil)
	  (print-html (combine-stats (receiving host) (sending host)) :with-row nil)))
	(setf row-switch (not row-switch))))))

(defmethod object-forms ((object stats))
  (with-slots (flows bytes packets) object
    `(make-instance 'stats :flows ,flows :bytes ,bytes :packets ,packets)))

(defmethod object-forms ((report periodic-report))
  (with-slots (total internal external incoming outgoing) report
    `(let ((report (make-instance 'periodic-report
				  :time ,(report-time report)
				  :version ,(report-format-version report))))
       (with-slots (total internal external incoming outgoing) report
	 (setf total ,(object-forms total))
	 (setf internal ,(object-forms internal))
	 (setf external ,(object-forms external))
	 (setf incoming ,(object-forms incoming))
	 (setf outgoing ,(object-forms incoming)))
       report)))

(defmethod print-object ((report periodic-report) stream)
  (print-unreadable-object (report stream :type t :identity t)
    (format stream "~:[~;~:*Filter ~S, ~]version ~d"
	    (when (filter report) (filter-title (filter report)))
	    (report-format-version report))))

(defmethod save-report ((object report))
  (with-open-file (stream (in-report-directory (format nil "report-~d" (report-time object)))
			  :direction :output :if-does-not-exist :create :if-exists :supersede)
    (format stream "~S" (object-forms object))))

(defmethod load-report (file)
  (with-open-file (stream file :direction :input)
    (eval (read stream))))

(defmethod print-html ((report periodic-report) &key title)
  (with-html-output (*standard-output*)
    (:h3 "General Statistics")
    (with-slots (host-stats) report
      (fmt "Report generated at ~a" (iso8661-date-string (generation-time report))))
    
    (cond
      ((zerop (flows (total report)))
       (htm (:b "No flows matched this filter.")))
      (t
       (htm
	(:table
	 (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
	 (print-html (internal report) :title "Internal Only")
	 (print-html (external report) :title "External Only")
	 (print-html (incoming report) :title "Incoming")
	 (print-html (outgoing report) :title "Outgoing")
	 (print-html (total report) :title "Total")))
       (print-scan-hosts "Possible Incoming Scan Hosts" "Local"
			 (incoming-scan-hosts report) :key #'local-contact-count)
       (print-scan-hosts "Possible Outgoing Scan Hosts" "Remote"
			 (outgoing-scan-hosts report) :key #'remote-contact-count)
       (print-busiest-hosts "Busiest Local Hosts" (busiest-hosts (local-hosts report)))
       (print-busiest-hosts "Busiest Remote Hosts" (busiest-hosts (remote-hosts report)))))))

(defun combine-stats (&rest stats)
  (make-instance 'stats
		 :flows (flows (first stats));(reduce #'+ stats :key #'flows)
		 :bytes (reduce #'+ stats :key #'bytes)
		 :packets (reduce #'+ stats :key #'packets)))

(defun make-periodic-report (flow-list &optional filter)
  (make-instance 'periodic-report :flow-list flow-list :filter filter))

