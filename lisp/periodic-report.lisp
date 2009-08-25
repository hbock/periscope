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
(defvar *host-cache-default-size* 30000)
(defconstant +min-host-cache-size+ 30000)

(defclass periodic-report (report)
  ((total :accessor total :type stats :initform (make-instance 'stats))
   (internal :accessor internal :type stats :initform (make-instance 'stats))
   (external :accessor external :type stats :initform (make-instance 'stats))
   (incoming :accessor incoming :type stats :initform (make-instance 'stats))
   (outgoing :accessor outgoing :type stats :initform (make-instance 'stats))
   (format-version :initarg :version :initform *periodic-report-format-version*)
   (filter :initarg :filter :reader filter :initform nil :type filter)
   (report-time :initarg :time :reader report-time :initform (this-hour (now)))
   (host-cache       :accessor host-cache)
   (cache-visit     :accessor cache-visit :initform 0)
   (cache-last-flush :accessor cache-last-flush :initform -1)
   (cache-hits       :accessor cache-hits   :initform 0)
   (cache-misses     :accessor cache-misses :initform 0)
   (using-db         :accessor using-db-p   :initform nil)))

(defclass host-stat ()
  ((host-ip :col-type inet :initarg :host-ip :accessor host-ip)
   (host-type :col-type integer :initarg :host-type :reader host-type)
   (hour :col-type smallint :initarg :hour)
   (date :col-type smallint :initarg :date)
   (month :col-type smallint :initarg :month)
   (sent-flows   :col-type bigint :col-default 0 :initform 0 :accessor sent-flows)
   (sent-bytes   :col-type bigint :col-default 0 :initform 0 :accessor sent-bytes)
   (sent-packets :col-type bigint :col-default 0 :initform 0 :accessor sent-packets)
   (received-flows   :col-type bigint :col-default 0 :initform 0 :accessor received-flows)
   (received-bytes   :col-type bigint :col-default 0 :initform 0 :accessor received-bytes)
   (received-packets :col-type bigint :col-default 0 :initform 0 :accessor received-packets)
   (refcount :initform 1 :accessor refcount))
  (:metaclass pomo:dao-class)
  (:keys host-ip hour date month))

(defclass host-stats ()
  ((ip :initarg :ip :accessor host-ip :initform (error "Must provide IP!"))
   (total :accessor total :type stats)
   (sending :accessor sending :type stats :initform (make-instance 'stats))
   (receiving :accessor receiving :type stats :initform (make-instance 'stats))
   (local-contacts :initform (make-hash-table))
   (remote-contacts :initform (make-hash-table))))

(defmethod initialize-instance :after ((object periodic-report) &key
				       (cache-size *host-cache-default-size*))
  (with-slots (format-version host-cache) object
    (setf host-cache (make-hash-table :test 'eql :size cache-size))
    (setf format-version *periodic-report-format-version*)))

(defmethod cache-stats ((report periodic-report))
  (with-slots (host-cache cache-visit) report
    (loop 
       :with visit-list = (make-array (1+ cache-visit))
       :for ip being the hash-keys in host-cache using (:hash-value (host . visit))
       :do (incf (aref visit-list visit))
       :finally (return visit-list))))

(defmethod finalize-report ((report periodic-report))
  ""
  (maphash (lambda (key host-entry)
  	     (declare (ignore key))
  	     (pomo:save-dao (car host-entry))) (host-cache report))
  (clrhash (host-cache report)))

(defun cache-flush (report &optional (flush-levels 3))
  (with-slots (using-db cache-visit cache-last-flush host-cache) report
    (setf using-db t)
    (format t "Flushing @ visit ~d~%" cache-visit)
    (let ((purged-entries 0))
      (maphash (lambda (key value)
		 (destructuring-bind (host . last-visit) value
		   (when (<= last-visit (+ flush-levels cache-last-flush))
		     (incf purged-entries)
		     (pomo:save-dao host)
		     (remhash key host-cache))))
	       host-cache)
      (format t "Flushed ~d entries.~%" purged-entries))
    (incf cache-last-flush flush-levels)))

;;; Our method for host statistics lookup is based on an LRU-like caching algorithm.
(defmethod find-host-stats ((report periodic-report) (host flow-host)
			    &key (check-db-p (using-db-p report)))
  (with-slots (host-cache cache-visit cache-hits cache-misses) report
    (multiple-value-bind (cached-value existsp)
	(gethash (host-ip host) host-cache)
      (flet ((new-entry ()
	       (make-instance 'host-stat :host-ip host
			      :host-type (flow-host-type host)
			      :hour (timestamp-hour (report-time report))
			      :date (timestamp-day (report-time report))
			      :month (timestamp-month (report-time report))))
	     (cache-insert (host host-entry)
	       (when (= (hash-table-size host-cache)
			(hash-table-count host-cache))
		 (cache-flush report))
	     
	       ;; Insert an element into the cache, with usage information.
	       (setf (gethash (host-ip host) host-cache)
		     (cons host-entry cache-visit))
	       host-entry))
	(cond
	  ;; Host stats entry was found (cache hit) - return immediately
	  (existsp
	   (incf cache-hits)
	   ;; Update the victim time of the host entry in the cache.
	   (setf (cdr cached-value) cache-visit)
	   (incf (refcount (car cached-value)))
	   (car cached-value))
      
	  ;; The host entry is not present in the cache, so we must either find it
	  ;; in the backing database, or if this is a new host, we simply create a
	  ;; new entry and add to the cache.
	  ((and (not existsp) check-db-p)
	   ;; We first try to SELECT this IP from the database...
	   (let ((host-entry (first (pomo:select-dao 'host-stat (:= 'host-ip host)))))
	     (incf cache-misses)
	     (if host-entry
		 ;; If found, it's a true cache miss, re-cache the entry.
		 (progn
		   (setf (host-ip host-entry) (make-instance 'flow-host :ip (host-ip host-entry)))
		   (cache-insert host host-entry))
		 ;; And if it is not found, we create, cache, and return a new entry.
		 (cache-insert host (new-entry)))))

	  ;; We can't (or don't need to) look in the database for the host, so we create a
	  ;; new one and add it to the cache.
	  (t (cache-insert host (new-entry))))))))

(defmethod update-host-stats ((report periodic-report) (source flow-host) (dest flow-host))
  (with-slots (host-cache) report
    (let ((source-host (find-host-stats report source))
	  (dest-host (find-host-stats report dest)))
      (incf (sent-flows source-host))
      (incf (sent-bytes source-host) (host-bytes source))
      (incf (sent-packets source-host) (host-packets source))
      (incf (received-bytes source-host) (host-bytes dest))
      (incf (received-packets source-host) (host-packets dest))
    
      (incf (received-flows dest-host))
      (incf (sent-bytes dest-host) (host-bytes dest))
      (incf (sent-packets dest-host) (host-packets dest))
      (incf (received-bytes dest-host) (host-bytes source))
      (incf (received-packets dest-host) (host-packets source)))))

(defmethod nadd ((report periodic-report) (flow flow))
  (with-slots (total internal external incoming outgoing host-cache) report
    (with-slots (source dest) flow
      (let ((bytes (+ (host-bytes source) (host-bytes dest)))
	    (packets (+ (host-packets source) (host-packets dest))))
	(add-stats total :bytes bytes :packets packets)
	(case (classify flow)
	  (:internal-only (add-stats internal :bytes bytes :packets packets))
	  (:external-only (add-stats external :bytes bytes :packets packets))
	  (:incoming  (add-stats incoming :bytes bytes :packets packets))
	  (:outgoing  (add-stats outgoing :bytes bytes :packets packets)))

	(update-host-stats report source dest)))))

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

(defun print-busiest-hosts (report title &key (type :local))
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
	:with list =
	(pomo:query-dao
	 'host-stat
	 (:limit (:order-by (:select '* :from 'host-stat
				     :where (:= 'host-type (flow-host-type type)))
			    (:desc 'sent-bytes)) 20))
	:for host :in list :do
	(htm
	 (:tr
	  :class (if row-switch "rowa" "rowb")
	  (:td (str (host-ip host)))
	  (:td (str (hostname (parse-ip-string (host-ip host)))))
	  (:td (fmt "~:d" (sent-packets host)))
	  (:td (str (byte-string (sent-bytes host))))
	  (:td (fmt "~:d" (received-packets host)))
	  (:td (str (byte-string (received-bytes host))))
	  (:td (fmt "~:d" (+ (received-packets host) (sent-packets host))))
	  (:td (str (byte-string (+ (received-bytes host) (sent-bytes host)))))
	  (:td (fmt "~:d" (+ (received-flows host) (sent-flows host))))))
	
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

(defmethod unique-hosts ((report periodic-report) &key type)
  (if type
      (query (:select (:count 'host-ip) :from 'host-stat
		      :where (:= 'host-type (flow-host-type type))) :single)
      (query (:select (:count 'host-ip) :from 'host-stat) :single)))

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
	(:h3 "Unique Hosts")
	(:table
	 (:tr (:th :colspan 2 "Unique Hosts"))
	 (:tr (:th "Type") (:th "Count"))
	 (loop :for (desc type) :in '(("Local" :local) ("Remote" :remote)
				      ("Broadcast" :broadcast) ("Multicast" :multicast)
				      ("Total" nil)) :do
	    (htm
	     (:tr (:td (:b (str desc)))
		  (:td (fmt "~:d" (unique-hosts report :type type)))))))
	(:table
	 (:tr (:th :colspan 4 "Flow Statistics"))
	 (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
	 (print-html (internal report) :title "Internal Only")
	 (print-html (external report) :title "External Only")
	 (print-html (incoming report) :title "Incoming")
	 (print-html (outgoing report) :title "Outgoing")
	 (print-html (total report) :title "Total")))

       (print-busiest-hosts report "Busiest Local Hosts" :type :local)
       (print-busiest-hosts report "Busiest Remote Hosts" :type :remote)
       ;; (print-scan-hosts "Possible Incoming Scan Hosts" "Local"
       ;; 			 (incoming-scan-hosts report) :key #'local-contact-count)
       ;; (print-scan-hosts "Possible Outgoing Scan Hosts" "Remote"
       ;; 			 (outgoing-scan-hosts report) :key #'remote-contact-count)
       ))))

(defun combine-stats (&rest stats)
  (make-instance 'stats
		 :flows (flows (first stats));(reduce #'+ stats :key #'flows)
		 :bytes (reduce #'+ stats :key #'bytes)
		 :packets (reduce #'+ stats :key #'packets)))

(defun make-periodic-report (flow-list &optional filter)
  (make-instance 'periodic-report :flow-list flow-list :filter filter))

