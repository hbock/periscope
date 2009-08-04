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

(defun diag-settings-form ()
  (with-html-output (*standard-output*)
    (:form :name "options" :method "post" :action "set-diag"
	   (:div :class "config-header" "Diagnostic Settings")
	   (:div
	    :class "config-section"
	    (:table
	     (:tr (:td "Enable Lisp backtraces in front-end")
		  (:td (checkbox "showbt" :checked hunchentoot:*show-lisp-errors-p*)))
	     (:tr (:td "Show diagnostics panel in sidebar")
		  (:td (checkbox "showdiag" :checked *web-show-diag*)))
	     (:tr (:td "Enable SWANK support for this image")
		  (:td (checkbox "swank" :checked *enable-swank-p*)))
	     (:tr (:td "SWANK connect port")
		  (:td (input "swankport" *swank-port* :size 5)))))
	   (:input :type "submit" :value "Apply Settings"))))

(defun diag-image-parameters ()
  (with-html-output (*standard-output*)
    (:div :class "config-header" "Image Parameters and Statistics")
    (:div
     :class "config-section"
     (:table
      (:tr (:td "Declared version") (:td (str *periscope-version*)))
      (:tr (:td "Compilation time") (:td (str (iso8661-date-string *compilation-time*))))
      (:tr (:td "Hunchentoot version") (:td (str hunchentoot-asd:*hunchentoot-version*)))
      (:tr (:td "Machine hostname") (:td (str (machine-instance))))
      (:tr (:td "Machine hardware") (:td (str (machine-version))))
      (:tr (:td "Host Lisp")
	   (:td (fmt "~a ~a (~a)" (lisp-implementation-type)
		     (lisp-implementation-version) (machine-type))))
      (:tr (:td "Collector foreign pointer")
	   (:td (if *collector*
		    (str (get-ptr *collector*))
		    (str "Not initialized!"))))))
    (collector-diag)
    (dns-diag)
    #+sbcl (sbcl-parameters)))

(defun y-or-n-td (generalized-boolean)
  (with-html-output (*standard-output*)
    (:td (fmt "~:[No~;Yes~]" generalized-boolean))))

(defun dns-diag ()
  (with-config-form ("/nothingtoseehere" "DNS Lookup Thread" "dns")
    (:table
     (:tr (:td "DNS cache size") (:td (fmt "~d entries" (hash-table-count *dns-cache*))))
     (:tr (:td "DNS requests pending lookup")
	  (:td (fmt "~d addresses"
		    (bt:with-lock-held (*dns-lock*) (length *dns-requests*)))))
     (:tr (:td "DNS thread running?") (y-or-n-td (bt:thread-alive-p *dns-thread*))))))

(defun collector-diag ()
  (with-config-form ("/nothingtoseehere" "Collector Process Information" "collector")
    (:table
     (:tr (:td "Collector process running?") (y-or-n-td (process-alive-p *collector-process*)))
     (:tr (:td "Collector PID") (:td (str (if *collector-process*
					      (process-pid *collector-process*)
					      "N/A")))))))
#+sbcl 
(defun sbcl-parameters ()
  (let ((uid (sb-posix:getuid))
	(gid (sb-posix:getgid)))
    (with-config-form ("/nothingtoseehere" "SBCL Parameters" "sbcl")
      (:table
       (:tr (:td "Process ID") (:td (fmt "~d" (sb-posix:getpid))))
       (:tr (:td "Process UID")
	    (:td (fmt "~d (~a)" uid (sb-posix:passwd-name (sb-posix:getpwuid uid)))))
       (:tr (:td "Process GID")
	    (:td (fmt "~d (~a)" gid (sb-posix:group-name (sb-posix:getgrgid gid)))))
       (:tr (:td "Command line arguments") (:td (fmt "~{\"~a\"~^, ~}" sb-ext:*posix-argv*)))
       (:tr (:td "Total GC run time")
	    (:td (fmt "~$ seconds" (/ sb-ext:*gc-run-time* internal-time-units-per-second))))))))

(hunchentoot:define-easy-handler (shutdown :uri "/shutdown") ()
  (shutdown))

;;; Periscope Diagnostics Test Suite
(hunchentoot:define-easy-handler (diagnostic-handler :uri "/uuddlrlrbastart") (begin)
  (declare (ignore begin))
  (with-periscope-page ("Diagnostic Suite" :admin t)
    (:h2 "Periscope Diagnostic Suite")
    (:p (who:fmt "Welcome to the diagnostic test suite for Periscope ~a. " *periscope-version*))
    
    (warning-box
     "This test suite will do many evil things and may crash your Lisp, your browser, 
and your child.  Unfortunately, we cannot reboot your child.")

    (when (running-p *collector*)
      (htm
       (:p (:a :href "/stop" "Stop") "the running collector.")))

    (diag-settings-form)    
    (diag-image-parameters)))

(hunchentoot:define-easy-handler (set-diag :uri "/set-diag")
    (showbt showdiag swank (swankport :parameter-type 'integer))
  (valid-session-or-lose :admin t)

  (setf hunchentoot:*show-lisp-errors-p* (and showbt (string= showbt "showbt")))
  (setf *web-show-diag* (and showdiag (string= showdiag "showdiag")))
  (setf *enable-swank-p* (and swank (string= swank "swank")))
  (when (and swankport (> swankport 1024) (not (= swankport *web-port*)))
    (setf *swank-port* swankport))

  (save-config)
  (hunchentoot:redirect "/uuddlrlrbastart"))

(hunchentoot:define-easy-handler (stop-page :uri "/stop") ()
  (stop *collector*)
  (with-periscope-page ("Stopping collector.")
    (:h3 "Collector stopped")
    "Please put your trays in the upright position before landing Periscope."))
