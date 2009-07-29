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
  (or
   (find-if #'probe-file
	    (mapcar (lambda (pathname)
		      (merge-pathnames "periscope-rc.lisp" pathname)) pathnames))
   (restart-case
       (periscope-config-error
	"Could not find periscope-rc.lisp in any of:~%~{  ~a~^~%~}." pathnames)
     (create-new-config-file ()
       :report "Create a blank configuration file in your home directory."
       ;; Hack implementation of "touch"
       (let ((pathname (merge-pathnames "periscope-rc.lisp" (first (last pathnames)))))
	 #+sbcl (ensure-directories-exist pathname :mode #o700)
	 #-sbcl (ensure-directories-exist pathname)
	 (with-open-file (ignoreme pathname :if-does-not-exist :create))
	 pathname)))))

(defun load-config (&optional (pathname *configuration-file-pathnames*))
  "Load the configuration Lisp file directly."
  (clrhash *web-user-db*)
  (load (find-config-file pathname)))

(defun save-config (&optional (pathname *configuration-file-pathnames*))
  "Save configuration data to a suitable file as found by FIND-CONFIG-FILE."
  (with-open-file (config-stream (find-config-file pathname) :direction :output
				 :if-does-not-exist :create :if-exists :supersede)
    (write-config config-stream)))

(defun write-config (&optional (stream *standard-output*))
  "Write the configuration data to a stream."
  (format stream "~S~%"
	  (symbol-value-setf-forms
	   '(*web-port* *web-show-diag*
	     *web-login-required-p*
	     hunchentoot:*show-lisp-errors-p*
	     hunchentoot:*session-max-time*
	     *swank-port* *enable-swank-p*
	     *notable-ports*
	     *internal-network* *internal-netmask*
	     *dns-available-p*)))
  (format stream "~S~%" (dump-hash-tables '(*vlan-names*)))
  (format stream "~S~%" (create-login-forms))
  (dolist (user (user-list))
    ;; Only print the MAKE-FILTER forms if the user has filters.
    (format stream "~:[~;~:*~S~%~]" (create-filter-forms user))))

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

(defun dump-hash-tables (symbol-list)
  "Given a list of symbols representing hash tables, construct forms that will recreate
the hash table when evaluated.  Properly restores hash table size and test."
  `(progn
     ,@(loop :for table-symbol :in symbol-list
	  :for table = (symbol-value table-symbol) :collect
	  `(progn
	     (setf ,table-symbol
		   (make-hash-table :test (quote ,(hash-table-test table))
				    :size ,(hash-table-size table)))
	     (loop :for (key . value) :in
		(list
		 ,@(loop :for key :being :the :hash-keys :in table :using (:hash-value value)
		      :collect `(cons ,key ,value)))
		:do (setf (gethash key ,table-symbol) value))))))