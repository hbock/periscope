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

;;; Periscope Diagnostics Test Suite
(hunchentoot:define-easy-handler (diagnostic-handler :uri "/uuddlrlrbastart") (begin)
  (declare (ignore begin))
  (with-periscope-page ("Diagnostic Suite")
    (:h3 "Periscope Diagnostic Suite")
    (:p (who:fmt "Welcome to the diagnostic test suite for Periscope ~a. " *periscope-version*))
    (warning-box
      "This test suite will do many evil things and may crash your Lisp, your browser, 
and your child.  Unfortunately, we cannot reboot your child.")

    (:form :name "options" :method "post" :action "set-diag"
	   (:table :class "options"
		   (:tr (:th "Option") (:th "Setting"))
		   (:tr (:td "Enable Lisp backtraces in front-end")
			(:td (y-or-n-checkbox "showbt" hunchentoot:*show-lisp-errors-p*)))
		   (:tr (:td "Show diagnostics panel in " (:a :href "/config" "Control Panel"))
			(:td (y-or-n-checkbox "showdiag" *web-show-diag*)))
		   (:tr (:td "Enable SWANK support for this image")
			(:td (y-or-n-checkbox "swank" *enable-swank-p*)))
		   (:tr (:td "SWANK connect port")
			(:td (input "swankport" *swank-port* :size 5))))
	   (:input :type "submit" :value "Apply Settings"))))

(hunchentoot:define-easy-handler (set-diag :uri "/set-diag") (showbt showdiag swank swankport)
  (flet ((string->bool (string) (string= string "true")))
    (setf hunchentoot:*show-lisp-errors-p* (string->bool showbt))
    (setf *web-show-diag* (string->bool showdiag))
    (setf *enable-swank-p* (string->bool swank))
    (let ((port (parse-integer swankport :junk-allowed t)))
      (when (and (> port 1024) (not (= port *web-port*)))
	(setf *swank-port* port))))
  (hunchentoot:redirect "/uuddlrlrbastart"))

(defun y-or-n-checkbox (name default &key (on "On") (off "Off"))
  (with-html-output (*standard-output*)
    (:label :for name (str on))
    (:input :type "radio" :name name :value "true" :checked default)
    (:label :for name (str off))
    (:input :type "radio" :name name :value "false" :checked (not default))))

(defun input (name default &key (size 20))
  (with-html-output (*standard-output*)
    (:input :type "text" :name name :value default :size size)))