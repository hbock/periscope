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

(defclass collector ()
  ((ptr :initform nil :accessor get-ptr)
   (remote :initform nil :accessor remote-sources)))

(defclass source ()
  ((ptr :initarg :ptr :initform nil :accessor get-ptr)
   (path :initarg :path :initform nil :accessor source-path)
   (major-version :initarg :major-version :reader major-version)
   (minor-version :initarg :minor-version :reader minor-version)
   (port :initarg :port :reader port)))

(defparameter *flows-seen* 0)

(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4
     (unless (null-pointer-p (get-metrics dsrs))
       (let* ((ip (get-ip (get-flow dsrs)))
	      (flow (build-flow dsrs ip)))
	 (destructuring-bind (filter &rest reports) *current-report*
	   (when (filter-pass-p filter flow)
	     (dolist (report reports)
	       (add-flow report flow)))))))))

(defmethod initialize-instance :after ((object collector) &key)
  (let ((ptr (foreign-alloc 'periscope-collector)))
    (setf (get-ptr object) ptr)
    (when (minusp (%collector-init ptr))
      (foreign-free ptr)
      (error "Unable to initialize collector!"))
    (tg:finalize object (lambda ()
			  (%collector-free ptr)
			  (foreign-free ptr)))))

(defmethod run ((object collector))
  "Start the collector."
  (when (running-p object)
    (error "Collector is already running."))
  (when (minusp (%collector-run (get-ptr object)))
    (error "Failed to start collector."))
  (setf (remote-sources object) nil)
  object)

(defmethod stop ((object collector))
  "Stop the collector, closing all open files and connections."
  (%collector-stop (get-ptr object))
  object)

(defmethod add-remote ((collector collector) (host string) &optional (port 561))
  "Add a remote host to be processed when START is called."
  (let* ((hoststr (format nil "~a:~d" host port))
	 (ptr (%argus-remote-add (get-ptr collector) hoststr)))
    (when (null-pointer-p ptr)
      (error "Error adding host ~a to the collector." hoststr))
    (let ((source (make-instance 'source :ptr ptr :path host)))
      (push source (remote-sources collector)))))

(defgeneric add-file (collector file)
  (:documentation "Add a local Argus file to be processed when START is called."))

(defmethod add-file ((collector collector) (file string))
  (when (minusp (%argus-local-add (get-ptr collector) file))
    (if (not (probe-file file))
	(periscope-file-error "File ~a does not exist!" file)
	(periscope-file-error "Failed to add file ~a to the collector." file)))
  file)

(defmethod add-file ((collector collector) (file pathname))
  (add-file collector (namestring file)))

(defmethod connect ((collector collector) (host string))
  "Connect directly to a remote Argus server at HOST."
  (when (not (running-p collector))
    (error "Can't direct connect to hosts when collector is not running!"))
  (let ((ptr (%argus-remote-direct-connect (get-ptr collector) host)))
    (when (null-pointer-p ptr)
      (error "Failed to connect to host ~a!" host))
    (let ((source (make-instance 'source :ptr ptr :path host)))
      (push source (remote-sources collector)))))

(defmethod running-p ((collector collector))
  (plusp (%collector-running-p (get-ptr collector))))

(defmethod connected-p ((object source))
  (plusp (%argus-connected-p (get-ptr object))))

(defmethod filter ((object collector))
  (%argus-get-filter (get-ptr object)))

(defmethod (setf filter) ((filter string) (object collector))
  (when (minusp
	 (%argus-set-filter (get-ptr object) filter))
    (periscope-error "Syntax error in filter: '~a'" filter)))

(defun init-basic-collector (&key (default-filter *collector-default-filter*))
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    (when default-filter
      (setf (filter collector) default-filter))
    collector))

(defun process-local-file (file &key (collector (init-basic-collector)) user filter)
  (when filter
    (setf (filter collector) filter))
  (add-file collector file)
  
  (setf *current-report* (list
			  (when (and user (filters user))
			    (first (filters user)))
			  (make-periodic-report)
			  (make-service-report)))
  
  (with-database ("periscope")
    (execute "TRUNCATE TABLE host_stat")
    (run collector)
    (dolist (report (rest *current-report*))
      (finalize-report report))))

;;; Collector stuff for racollector script.
(defun collector-connect-string (&optional (hostname *collector-argus-server*)
				 (port *collector-argus-port*))
  (declare (type (unsigned-byte 16) port))
  (format nil "~a:~d" hostname port))

(defun run-collector (server time-period)
  "Run the rastream client as a child process, specifying the remote Argus server
and the time period for which it will split its output logs."
  (let ((start-time (get-universal-time))
	(time-period-string
	 (ecase time-period
	   (:test "10s")
	   (:hour "1h")
	   (:half-hour "30m")))
	(output-spec
	 (in-report-directory (ecase time-period
				(:test "test/%Y%m%d-%H:%M:%S")
				(:five-minute-chunks "temp/temp.%Y%m%d-%H:%M")
				(:hour "hourly.%Y%m%d-%H")
				(:half-hour "halfhour.%Y%m%d-%H.%M")))))
    (setf *collector-process*
	  (process-create *rastream-binary* nil
			  ;; Arguments
			  ;; rastream -S <server> -M time <period> -B 20s -f <post-split-script>
			  ;;          -w <output-format>
			  "-S" server
			  "-M" "time" time-period-string
			  "-B" "20s"
			  "-f" (namestring *collector-script*)
			  "-w" (namestring output-spec)))
    (process-wait *collector-process*)
    (when (< (- (get-universal-time) start-time) 2)
      (periscope-config-error "Failed to connect to server '~a'!" server))))

(defun stop-collector (collector-process)
  "Terminate the collector-process by sending it SIGTERM, and wait for it to exit."
  (bt:with-lock-held (*collector-shutdown-lock*)
    (setf *collector-shutdown-p* t))
  (when (process-alive-p collector-process)
    (process-wait (process-signal collector-process))))

(defun collector-running-p ()
  "Is the collector child process running?"
  (process-alive-p *collector-process*))

(defun collector-aborted-p ()
  (and (not (process-alive-p *collector-process*)) *collector-error-p*))

(defun collector-thread ()
  "Thread that runs and monitors the collector until *SHUTDOWN-P* is T."
  (bt:with-lock-held (*collector-shutdown-lock*)
    (setf *collector-shutdown-p* nil))
  (loop :named watchdog-loop :do
     (handler-case (run-collector (collector-connect-string) :hour)
       (periscope-config-error ()
	 (setf *collector-error-p* t)
	 (format t "Error starting rastream occured, aborting!~%")
	 (return-from watchdog-loop)))
     (bt:with-lock-held (*collector-shutdown-lock*)
       (if *collector-shutdown-p*
	   (return-from watchdog-loop)
	   (format t "Collector stopped unexpectedly. Restarting!~%")))))

;;; This code is defunct for now - we are no longer handling remote Argus
;;; sources directly.
(defmethod remote-port ((object source))
  (%argus-remote-port (get-ptr object)))

(defmethod remote-ip ((object source))
  (%argus-remote-ip (get-ptr object)))

(defun get-argus-sources (queue)
  (let (sources)
    (dolist (input (argus-queue-list queue))
      (with-foreign-object (info 'periscope-input-info)
	(unless (zerop (%argus-remote-info input info))
	  (error "Error getting info for ArgusInput ~a" input))
	(with-foreign-slots ((major-version minor-version hostname port) info periscope-input-info)
	  (push (make-instance 'source :major-version major-version
			       :minor-version minor-version
			       :hostname hostname
			       :port port
			       :ptr input
			       :path "NONE")
		sources))))
    sources))

(defmethod remove-source ((src source) (collector collector))
  (if (null-pointer-p (get-ptr src))
      (error "Cannot remove a NULL source!")
      (unless (zerop
	       (%argus-remote-remove (get-ptr collector) (get-ptr src)))
	(error "Failed to remove source at ~a!" (get-ptr src)))))

(defmethod available-sources ((object collector))
  (get-argus-sources (%argus-remote-pending-queue (get-ptr object))))

(defmethod active-sources ((object collector))
  (get-argus-sources (%argus-remote-active-queue (get-ptr object))))
