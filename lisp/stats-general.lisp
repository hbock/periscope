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

(defvar *general-stats-format-version* 0
  "Current version of the PERIOD-REPORT file/class format. Used to ensure older report formats
are processed correctly, or a proper error is signalled when a report format is no longer
supported.")
(defvar *host-cache-default-size* 30000)
(defconstant +min-host-cache-size+ 30000)

(defclass traffic-stats (report-base)
  ((bytes   :col-type bigint  :initarg :bytes   :initform 0 :accessor bytes)
   (packets :col-type bigint  :initarg :packets :initform 0 :accessor packets)
   (flows   :col-type bigint  :initarg :flows   :initform 0 :accessor flows)
   (type    :col-type integer :initarg :type :reader stats-type))
  (:metaclass pomo:dao-class)
  (:keys type))

(defclass general-stats (statistics-report)
  ((total :accessor total :type traffic-stats)
   (internal :accessor internal :type traffic-stats)
   (external :accessor external :type traffic-stats)
   (incoming :accessor incoming :type traffic-stats)
   (outgoing :accessor outgoing :type traffic-stats)
   (format-version :initarg :version :initform *general-stats-format-version*)
   (host-cache       :accessor host-cache)
   (host-on-disk     :accessor host-on-disk)
   (cache-visit      :accessor cache-visit :initform 0)
   (cache-last-flush :accessor cache-last-flush :initform -1)
   (cache-hits       :accessor cache-hits   :initform 0)
   (cache-misses     :accessor cache-misses :initform 0)
   (cache-lookups    :accessor cache-lookups :initform 0)
   (using-db         :accessor using-db-p   :initform nil)))

(defclass host-stat (report-base)
  ((host-ip :col-type inet :initarg :host-ip :accessor host-ip)
   (host-type :col-type integer :initarg :host-type :reader host-type)
   (sent-flows   :col-type bigint :col-default 0 :initform 0 :accessor sent-flows)
   (sent-bytes   :col-type bigint :col-default 0 :initform 0 :accessor sent-bytes)
   (sent-packets :col-type bigint :col-default 0 :initform 0 :accessor sent-packets)
   (received-flows   :col-type bigint :col-default 0 :initform 0 :accessor received-flows)
   (received-bytes   :col-type bigint :col-default 0 :initform 0 :accessor received-bytes)
   (received-packets :col-type bigint :col-default 0 :initform 0 :accessor received-packets)
   (refcount :initform 1 :accessor refcount))
  (:metaclass pomo:dao-class)
  (:keys host-ip))

(defmethod initialize-instance :after ((object general-stats) &key
				       (cache-size *host-cache-default-size*))
  (with-slots (filter) object
    (loop :for stats :in '(internal external incoming outgoing total)
       :for i = 1 :then (1+ i) :do
       (setf (slot-value object stats)
	     (make-instance 'traffic-stats :type i
			    :filter-id (filter-id filter)
			    :timestamp (report-time object))))
  
    (with-slots (format-version host-cache host-on-disk) object
      (setf host-cache (make-hash-table :test 'eql :size cache-size))
      (setf host-on-disk (make-hash-table :test 'eql :size (* 10 cache-size)))
      (setf format-version *general-stats-format-version*))))

(defmethod cache-stats ((report general-stats))
  (with-slots (host-cache cache-visit) report
    (loop 
       :with visit-list = (make-array (1+ cache-visit))
       :for ip being the hash-keys in host-cache using (:hash-value (host . visit))
       :do (incf (aref visit-list visit))
       :finally (return visit-list))))

(defmacro with-fast-insert ((stream &optional (output-file #p"sql.csv")) &body body)
  `(prog1
       (with-open-file (,stream ,output-file
				:direction :output
				:if-exists :supersede
				:if-does-not-exist :create)
	 (flet ((insert-host (host)
		  (with-slots (host-ip host-type timestamp filter-id
				       sent-flows sent-bytes sent-packets
				       received-flows received-bytes received-packets) host
		    (format ,stream "~a,~d,~a,~d,~d,~d,~d,~d,~d,~d~%"
			    (ip-string (host-ip host-ip)) host-type (timestamp-string timestamp)
			    filter-id sent-flows sent-bytes sent-packets
			    received-flows received-bytes received-packets))))
	   ,@body))
     (copy-host-data ,output-file)))

(defmethod commit ((report general-stats) &key)
  ;; TODO: Remove me when done debugging!
  (with-slots (cache-hits cache-misses) report
      (unless (= 0 cache-hits cache-misses)
	(format t "Cache hits/miss: ~d/~d (~$%)~%" cache-hits cache-misses
		(* 100 (/ cache-hits (+ cache-hits cache-misses))))))

  (insert-slots (internal external incoming outgoing total) report)
  
  (with-fast-insert (insert-stream)
    (maphash (lambda (key host-entry)
	       (if (gethash key (host-on-disk report))
		   (update-host (car host-entry))
		   (insert-host (car host-entry))))
	     (host-cache report)))
  (clrhash (host-cache report)))

(defun copy-host-data (file)
  (execute
   (format nil
	   "COPY host_stat (host_ip, host_type, timestamp, filter_id, sent_flows, sent_bytes, 
sent_packets, received_flows, received_bytes, received_packets) FROM '~a' WITH CSV"
	   (truename file))))

(defmacro fast-update ()
  (flet ((placeholder (n) (make-symbol (format nil "$~d" n))))
    (let* (set-fields
	   (last-field-num
	    (loop :for i = 1 :then (1+ i)
	       :for symbol :in '(sent-flows sent-bytes sent-packets
				 received-flows received-bytes received-packets) :do
	       (push symbol set-fields)
	       (push (placeholder i) set-fields)
	       :finally (return i))))
      (s-sql:sql-compile
       `(:update 'host-stat :set ,@(nreverse set-fields)
		 :where (:= host-ip ,(placeholder last-field-num)))))))

(pomo:defprepared host-stat-update
    (fast-update))

(defmethod update-host ((host host-stat))
  (with-slots (host-ip sent-flows sent-bytes sent-packets received-flows received-bytes
		       received-packets) host
    (host-stat-update sent-flows sent-bytes sent-packets received-flows
		      received-bytes received-packets
		      (let ((ip (host-ip host-ip)))
			(if (stringp ip) ip (ip-string ip))))))

(defun cache-flush (report &optional (flush-levels 3))
  (with-slots (using-db cache-visit cache-last-flush host-cache host-on-disk cache-hits
			cache-misses cache-lookups) report
    (setf using-db t)
    (format t "Flushing @ visit ~d (h/m/l ~:d/~:d/~:d)~%" cache-visit
	    cache-hits cache-misses cache-lookups)
    (let ((purged-entries 0)
	  (updates 0) (inserts 0) (time (get-universal-time)))
      (with-fast-insert (insert-stream)
	(maphash (lambda (key value)
		   (destructuring-bind (host . last-visit) value
		     (when (<= last-visit (+ flush-levels cache-last-flush))
		       (incf purged-entries)
		       (cond
			 ;; We know the host is already on disk - do a prepared update
			 ((gethash key (host-on-disk report))
			  (incf updates)
			  (update-host host))
			 ;; We know the host is not yet on disk - insert it
			 (t
			  (incf inserts)
			  (insert-host host)
			  (setf (gethash key host-on-disk) t)))
		       (remhash key host-cache))))
		 host-cache))
      (format t "Flushed ~d entries (~d updates, ~d inserts) in ~d seconds.~%"
	      purged-entries updates inserts (- (get-universal-time) time)))
    (incf cache-last-flush flush-levels)))

;;; Our method for host statistics lookup is based on an LRU-like caching algorithm.
(defmethod find-host-stats ((report general-stats) (host flow-host)
			    &key (check-db-p (using-db-p report)))
  (with-slots (host-cache host-on-disk cache-visit cache-hits cache-misses cache-lookups) report
    (multiple-value-bind (cached-value existsp)
	(gethash (host-ip host) host-cache)
      (flet ((new-entry ()
	       (make-instance 'host-stat :host-ip host
			      :host-type (flow-host-type host)
			      :timestamp (report-time report)
			      :filter-id (filter-id (filter report))))
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
	   (multiple-value-bind (on-disk-p seen-p)
	       (gethash (host-ip host) host-on-disk)
	     (declare (ignore seen-p))
	     (if on-disk-p
		 ;; We first try to SELECT this IP from the database...
		 (let ((host-entry (first (pomo:select-dao 'host-stat (:= 'host-ip host)))))
		   (incf cache-misses)
		   (unless host-entry
		     (error "Shit."))
		   (incf cache-lookups)
		   (setf (host-ip host-entry) (make-instance 'flow-host :ip (host-ip host-entry)))
		   (cache-insert host host-entry))
		 (cache-insert host (new-entry)))))

	  ;; We can't (or don't need to) look in the database for the host, so we create a
	  ;; new one and add it to the cache.
	  (t (cache-insert host (new-entry))))))))

(defmethod update-host-stats ((report general-stats) (source flow-host) (dest flow-host))
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

(defmethod add-traffic-stats ((stats traffic-stats) &optional (bytes 0) (packets 0) (flows 1))
  (incf (flows stats) flows)
  (incf (bytes stats) bytes)
  (incf (packets stats) packets))

(defmethod add-flow ((report general-stats) (flow flow))
  (when (zerop (mod (flows (total report)) 1000))
    (incf (cache-visit report)))

  (with-slots (total internal external incoming outgoing host-cache) report
    (with-slots (source dest) flow
      (let ((bytes (+ (host-bytes source) (host-bytes dest)))
	    (packets (+ (host-packets source) (host-packets dest))))
	(add-traffic-stats total bytes packets)
	(case (classify flow)
	  (:internal-only (add-traffic-stats internal bytes packets))
	  (:external-only (add-traffic-stats external bytes packets))
	  (:incoming  (add-traffic-stats incoming bytes packets))
	  (:outgoing  (add-traffic-stats outgoing bytes packets)))

	(update-host-stats report source dest)))))

;; (defmethod local-contact-count ((host host-stats))
;;   (hash-table-count (slot-value host 'local-contacts)))

;; (defmethod remote-contact-count ((host host-stats))
;;   (hash-table-count (slot-value host 'remote-contacts)))

(defun traffic-stats-type (sql-enum &key (format :keyword))
  (ecase format
    (:keyword
     (ecase sql-enum
       (1 :internal-only)
       (2 :external-only)
       (3 :incoming)
       (4 :outgoing)
       (5 :total)))
    (:string
     (ecase sql-enum
       (1 "Internal only")
       (2 "External only")
       (3 "Incoming")
       (4 "Outgoing")
       (5 "Total")))))

(defmethod busiest-hosts ((report general-stats) &key (limit 20) (type :local))
  (pomo:query-dao
   'host-stat
   (:limit (:order-by (:select '* :from 'host-stat :where
			       (:and (:= 'host-type (flow-host-type type))
				     (:= 'filter-id (filter-id report))
				     (:= 'timestamp (report-time report))))
		      (:desc 'sent-bytes)) limit)))

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
     (let ((row-switch t))
       (dolist (host (busiest-hosts report :type type))
	 (let ((ip (if (stringp (host-ip host))
		       (parse-ip-string (host-ip host))
		       (host-ip host))))
	   (htm
	    (:tr
	     :class (if row-switch "rowa" "rowb")
	     (:td (str (ip-string ip)))
	     (:td (str (hostname ip)))
	     (:td (fmt "~:d" (sent-packets host)))
	     (:td (str (byte-string (sent-bytes host))))
	     (:td (fmt "~:d" (received-packets host)))
	     (:td (str (byte-string (received-bytes host))))
	     (:td (fmt "~:d" (+ (received-packets host) (sent-packets host))))
	     (:td (str (byte-string (+ (received-bytes host) (sent-bytes host)))))
	     (:td (fmt "~:d" (+ (received-flows host) (sent-flows host)))))))
	 (setf row-switch (not row-switch)))))))

(defmethod print-object ((report general-stats) stream)
  (print-unreadable-object (report stream :type t)
    (format stream "version ~d" (report-format-version report))))

(defmethod load-report (file)
  (with-open-file (stream file :direction :input)
    (eval (read stream))))

(defmethod unique-hosts ((report general-stats) &key type)
  (if type
      (query (:select (:count 'host-ip) :from 'host-stat
		      :where (:and (:= 'host-type (flow-host-type type))
				   (:= 'timestamp (report-time report))
				   (:= 'filter-id (filter-id report)))) :single)
      (query (:select (:count 'host-ip) :from 'host-stat
		      :where (:and (:= 'timestamp (report-time report))
				   (:= 'filter-id (filter-id report)))) :single)))

(defmethod print-html ((object traffic-stats) &key (title "General Stats") (with-row t) (flows t))
  (with-html-output (*standard-output*)
    (if with-row
	(htm
	 (:tr (:td (:b (str title)))
	      (:td (fmt "~:d" (packets object)))
	      (:td (str (byte-string (bytes object))))
	      (:td (fmt "~:d" (flows object)))))
	(htm
	 (:td (fmt "~:d" (packets object)))
	 (:td (str (byte-string (bytes object))))
	 (when flows
	   (htm (:td (fmt "~:d" (flows object)))))))))

(defmethod print-html ((report general-stats) &key)
  (with-html-output (*standard-output*)
    (:h3 "General Statistics")    
    (cond
      ((zerop (flows (total report)))
       (htm (:b "No flows matched this filter.")))
      (t
       (htm
	(:table
	 (:tr (:th :colspan 4 "Flow Statistics"))
	 (:tr (:th "") (:th "Packets") (:th "Bytes") (:th "Flows"))
	 (loop :for stats :in
	    (pomo:select-dao 'traffic-stats
			     (:and (:= 'filter-id (filter-id report))
				   (:= 'timestamp (report-time report)))
			     'type)
	    :do (print-html stats :title (traffic-stats-type (stats-type stats) :format :string))))

	(:table
	 (:tr (:th :colspan 2 "Unique Hosts"))
	 (:tr (:th "Type") (:th "Count"))
	 (loop :for (desc type) :in '(("Local" :local)
				      ("Remote" :remote)
				      ("Broadcast" :broadcast)
				      ("Multicast" :multicast)
				      ("Total" nil)) :do
	    (htm
	     (:tr (:td (:b (str desc)))
		  (:td (fmt "~:d" (unique-hosts report :type type))))))))

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

(defun make-general-stats (time)
  (make-instance 'general-stats :time time))
