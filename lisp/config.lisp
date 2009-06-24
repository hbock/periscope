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

(defun find-config-file (&optional (pathnames *configuration-file-pathnames*))
  "Find a suitable configuration file in PATHNAMES."
  (declare (type sequence pathnames))
  (let ((config-file
	 (find-if #'probe-file
		  (mapcar (lambda (pathname)
			    (merge-pathnames "periscope-rc.lisp" pathname)) pathnames))))
    (unless config-file
      (error "Could not find periscope-rc.lisp in any of:~%~{  ~a~^~%~}." pathnames))
    config-file))

(defun load-config (&optional (pathname *configuration-file-pathnames*))
  "Load the configuration Lisp file directly."
  (load (find-config-file pathname)))

(defun save-config (&optional (pathname *configuration-file-pathnames*))
  "Save configuration data to a suitable file as found by FIND-CONFIG-FILE."
  (with-open-file (config-stream (find-config-file pathname) :direction :output
				 :if-does-not-exist :create :if-exists :supersede)
    (write-config config-stream)))

(defun write-config (&optional (stream *standard-output*))
  "Write the configuration data to a stream."
  (format stream "~A~%"
	  (symbol-value-setf-forms
	   '(*web-port* *web-show-diag*
	     *swank-port* *enable-swank-p*
	     *notable-ports*
	     *internal-network* *internal-netmask*))))

(defun symbol-value-setf-forms (symbol-list)
  "Given a list of symbols, construct a SETF form that will properly set all relevant values."
  `(setf
    ,@(let (pairs)
	   (dolist (symbol symbol-list)
	     (push symbol pairs)
	     (let ((value (symbol-value symbol)))
	       (typecase value
		 (list (push (if (null value) nil `(list ,@value)) pairs))
		 (t (push value pairs)))))
	   (nreverse pairs))))