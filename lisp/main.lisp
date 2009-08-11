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

(defun enable-interrupts ()
  #+sbcl
  (dolist (interrupt (list sb-unix:sigterm sb-unix:sigint sb-unix:sighup))
    (sb-sys:enable-interrupt interrupt #'signal-handler))
  #-sbcl (not-implemented 'enable-interrupts))

#+sbcl
(defun signal-handler (signal code scp)
  (declare (ignore code scp))
  (flet ((shutdown ()
	   ;; We call SHUTDOWN in a separate thread because
	   ;; BT:CONDITION-NOTIFY does not seem to work in an interrupt
	   ;; handler (at least on SBCL).
	   (bt:make-thread #'shutdown)))
    (ecase signal
      ((#.sb-unix:sigint #.sb-unix:sigterm)
       (format t "Shutting down on signal.~%")
       (shutdown))

      ;; SIGHUP reloads the configuration file.
      (#.sb-unix:sighup
       (format t "Reloading configuration file.")
       (load-config)))))

(defun shutdown ()
  (setf *shutdown-p* t)
  (stop-collector *collector-process*)
  (bt:condition-notify *shutdown-cond*))

(defun main ()
  (let ((*package* (in-package :periscope)))
    ;; Ignore no-config-file at load time.
    (handler-case (load-config)
      (file-error () nil))

    (enable-interrupts)
    (format t "Starting Periscope ~a...~%" *periscope-version*)
    (handler-case
	(start-web)
      (usocket:address-in-use-error ()
	(format t "Web address in use - cannot start web interface.~%")
	(return-from main 1)))
    
    (format t "Web front-end started.~%")

    (format t "Initializing internal Argus parser. ")
    (setf *collector* (init-basic-collector))
    (format t "OK.~%")

    (format t "Starting DNS reverse lookup thread. ")
    (when *dns-available-p*
      (start-dns))
    (format t "OK.~%")

    (loop :named main-wait :do
       (bt:with-lock-held (*shutdown-lock*)
	 (bt:condition-wait *shutdown-cond* *shutdown-lock*)
	 (when *shutdown-p* (return-from main-wait))))

    (format t "Received shutdown command.  Terminating web interface.~%")
    (format t "You may have to navigate to the web interface before it will shut down.~%")
    (stop-dns)
    ;; HUNCHENTOOT:STOP seems to wait for the acceptor process/thread to complete, but
    ;; it never does until you hit the web server at least once. Force STOP-WEB to timeout
    ;; within 1 second to let us actually exit, which SHOULD be harmless. [famous last words]
    (with-timeout (1)
      (stop-web))

    (return-from main 0)))
