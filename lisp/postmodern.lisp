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

(defconstant +postgres-oid-inet+ 869)

(deftype octet ()
  '(unsigned-byte 8))

(defun inet-sql-reader (inet-string)
  "Convert an IP-string or CIDR netmask as returned by PostgreSQL into forms used
by Periscope."
  (multiple-value-bind (network netmask)
      (parse-ip-string inet-string)
    (if (null netmask)
	network
	(cons network netmask))))

(defun inet-binary-sql-reader (inet-stream size)
  (let ((data (make-array 4 :element-type 'octet))
	(ip (make-array 4 :element-type 'octet)))
    (ecase size
      (8
       (read-sequence data inet-stream :end 4)
       (read-sequence ip inet-stream :end 4)
       (vector-to-ip ip)))))

(eval-when (:compile-toplevel :load-toplevel)
  (defparameter *database-host* "localhost")
  (defparameter *database-user* "periscope")
  (defparameter *database-password* "periscope")

  (defmacro with-database ((database &key (user '*database-user*)
				     (host '*database-host*)
				     (password '*database-password*)) &body body)
    `(pomo:with-connection (list ,database ,user ,password ,host)
       ,@body)))

(defun database-initialize ()
  "Perform initialization of PostgreSQL functionality - sets up readers for special Periscope
data types, etc."
  (cl-postgres:set-sql-reader +postgres-oid-inet+ #'inet-binary-sql-reader :binary-p t)
  (database-connect "periscope")
  (unless (pomo:table-exists-p 'host-stat)
    (create-schema)))

(defun database-connect (database-name &key (user *database-user*)
			 (host *database-host*)
			 (password *database-password*))
  (setf pomo:*database* (pomo:connect database-name user password host)))

(defun database-connected-p ()
  (and pomo:*database* (pomo:connected-p pomo:*database*)))

(defun database-disconnect (&optional (connection pomo:*database*))
  (pomo:disconnect connection))

(defun create-schema ()
  "Create the Periscope database schema on the currently connected database. Creates
table layouts and their relevant indexes."
  (with-database ("periscope")
    (execute (pomo:dao-table-definition 'host-stat))
    (execute (pomo:dao-table-definition 'traffic-stats))
    ;(execute (:create-index 'time :on host-stat :fields hour date month))
    ))

(defmacro insert-slots ((&rest slots) object)
  `(with-slots (,@slots) ,object
     ,@(loop :for slot :in slots
	  :collect `(pomo:insert-dao ,slot))))