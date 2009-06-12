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
    (:h3 "Diagnostic Settings")
    (:form :name "options" :method "post" :action "set-diag"
	   (:table :class "options"
		   (:tr (:th "Option") (:th "Setting"))
		   (:tr (:td "Enable Lisp backtraces in front-end")
			(:td (y-or-n-radio "showbt" hunchentoot:*show-lisp-errors-p*)))
		   (:tr (:td "Show diagnostics panel in " (:a :href "/config" "Control Panel"))
			(:td (y-or-n-radio "showdiag" *web-show-diag*)))
		   (:tr (:td "Enable SWANK support for this image")
			(:td (y-or-n-radio "swank" *enable-swank-p*)))
		   (:tr (:td "SWANK connect port")
			(:td (input "swankport" *swank-port* :size 5))))
	   (:input :type "submit" :value "Apply Settings"))))

(defun diag-image-parameters ()
  (with-html-output (*standard-output*)
    (:h3 "Image Parameters and Statistics")
    (:table
     :class "options"
     (:tr (:th "Parameter") (:th "Value"))
     (:tr (:td "Declared version") (:td (str *periscope-version*)))
     (multiple-value-bind (sec min hour date month year) (decode-universal-time *compilation-time*)
       (declare (ignore sec))
       (htm
	(:tr (:td "Compilation time") (:td (fmt "~a-~a-~a ~a:~a" year month date hour min)))))
     (:tr (:td "Hunchentoot version") (:td (str hunchentoot-asd:*hunchentoot-version*)))
     (:tr (:td "Machine hostname") (:td (str (machine-instance))))
     (:tr (:td "Machine hardware") (:td (str (machine-version))))
     (:tr (:td "Host Lisp")
	  (:td (fmt "~a ~a (~a)" (lisp-implementation-type)
		    (lisp-implementation-version) (machine-type))))
     (:tr (:td "Collector foreign pointer")
	  (:td (if *collector*
		   (str (get-ptr *collector*))
		   (str "Not initialized!"))))
     #+sbcl (sbcl-parameters))))

#+sbcl 
(defun sbcl-parameters ()
  (let ((uid (sb-posix:getuid))
	(gid (sb-posix:getgid)))
    (with-html-output (*standard-output*)
      (:tr (:td "Process ID") (:td (fmt "~d" (sb-posix:getpid))))
      (:tr (:td "Process UID")
	   (:td (fmt "~d (~a)" uid (sb-posix:passwd-name (sb-posix:getpwuid uid)))))
      (:tr (:td "Process GID")
	   (:td (fmt "~d (~a)" gid (sb-posix:group-name (sb-posix:getgrgid gid)))))
      (:tr (:td "Command line arguments") (:td (fmt "~{\"~a\"~^, ~}" sb-ext:*posix-argv*)))
      (:tr (:td "Total GC run time")
	   (:td (fmt "~$ seconds" (/ sb-ext:*gc-run-time* internal-time-units-per-second)))))))

;;; Periscope Diagnostics Test Suite
(hunchentoot:define-easy-handler (diagnostic-handler :uri "/uuddlrlrbastart") (begin)
  (declare (ignore begin))
  (with-periscope-page ("Diagnostic Suite")
    (:h2 "Periscope Diagnostic Suite")
    (:p (who:fmt "Welcome to the diagnostic test suite for Periscope ~a. " *periscope-version*))
    
    (warning-box
     "This test suite will do many evil things and may crash your Lisp, your browser, 
and your child.  Unfortunately, we cannot reboot your child.")

    (diag-image-parameters)
    (diag-settings-form)))

(hunchentoot:define-easy-handler (set-diag :uri "/set-diag") (showbt showdiag swank swankport)
  (flet ((string->bool (string) (string= string "true")))
    (setf hunchentoot:*show-lisp-errors-p* (string->bool showbt))
    (setf *web-show-diag* (string->bool showdiag))
    (setf *enable-swank-p* (string->bool swank))
    (let ((port (parse-integer swankport :junk-allowed t)))
      (when (and (> port 1024) (not (= port *web-port*)))
	(setf *swank-port* port))))
  (hunchentoot:redirect "/uuddlrlrbastart"))