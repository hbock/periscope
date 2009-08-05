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
  
(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4
     (let ((ip (get-ip (get-flow dsrs))))
       (push (build-flow dsrs ip) *flow-list*)))))

(defun init-basic-collector ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    (setf (filter collector) "tcp or icmp or udp")
    collector))

(defun run-collector (server time-period)
  (let ((time-period-string
	 (ecase time-period
	   (:test "10s")
	   (:hour "1h")
	   (:half-hour "30m")))
	(output-spec
	 (ensure-directories-exist
	  (in-report-directory (ecase time-period
				 (:test "test/%Y%m%d-%H:%M:%S")
				 (:hour "hourly.%Y%m%d-%H")
				 (:half-hour "halfhour.%Y%m%d-%H.%M"))))))
    (setf *collector-process*
	  (process-create (probe-file *collector-script*) nil
			  ;; Arguments
			  server time-period-string (namestring output-spec)))
    (process-wait *collector-process*)))

(defun stop-collector (collector-process)
  (process-wait (process-signal collector-process)))

(defun collector-running-p ()
  (process-alive-p *collector-process*))

(defun collector-thread ()
  (format t "OK.~%")
  (loop :until *shutdown-p* :do
     (run-collector "tinderbox" :hour)
     (unless *shutdown-p*
       (format t "Collector stopped unexpectedly. Restarting!"))))

(defun shutdown ()
  (setf *shutdown-p* t)
  (stop-collector *collector-process*)
  (bt:condition-notify *shutdown-cond*))

(defun repl-main ()
  (main :with-collector nil))

(defun main (&key (with-collector t))
  (let ((*package* (in-package :periscope)))
    (handler-bind ((periscope-config-error
		    (lambda (c)
		      (declare (ignore c))
		      (invoke-restart 'create-new-config-file))))
      (load-config))

    (format t "Starting Periscope ~a...~%" *periscope-version*)
    (start-web)
    (format t "Web front-end started.~%")

    (format t "Initializing internal Argus parser. ")
    (setf *collector* (init-basic-collector))
    (format t "OK.~%")

    (format t "Starting DNS reverse lookup thread. ")
    (when *dns-available-p*
      (start-dns))
    (format t "OK.~%")
 
    (format t "Starting racollector. ")
    (when with-collector
      (bt:join-thread
       (bt:make-thread #'collector-thread :name "racollector: external process watchdog")))

    (format t "Received shutdown command.  Terminating web interface.~%")
    (format t "You may have to navigate to the web interface before it will shut down.~%")
    (stop-web)

    (format t "Completed.")
    (return-from main 0)))