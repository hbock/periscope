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

(defparameter *periscope-db-user* "periscope")
(defparameter *periscope-db-host* "localhost")
(defparameter *periscope-db-password* "periscope")
(defparameter *periscope-db-connection* nil)

(defconstant +postgres-oid-inet+ 869)

(defun inet-sql-reader (inet-string)
  "Convert an IP-string or CIDR netmask as returned by PostgreSQL into forms used
by Periscope."
  (multiple-value-bind (network netmask)
      (parse-ip-string inet-string)
    (if (null netmask)
	network
	(cons network netmask))))

(defmethod cl-postgres:to-sql-string ((host flow-host))
  (format nil "'~a'" (ip-string (host-ip host))))

(defun init-postgres ()
  "Perform initialization of PostgreSQL functionality - sets up readers for special Periscope
data types, etc."
  (cl-postgres:set-sql-reader +postgres-oid-inet+ #'inet-sql-reader))

(defun connect-db (database-name &key (user *periscope-db-user*)
		   (host *periscope-db-host*)
		   (password *periscope-db-password*))
  (setf *periscope-db-connection* (pomo:connect database-name user password host)))

(defun disconnect-db (&optional (connection *periscope-db-connection*))
  (pomo:disconnect connection))

(defun create-schema ()
  "Create the Periscope database schema on the currently connected database. Creates
table layouts and their relevant indexes."
  (execute (pomo:dao-table-definition 'host-stat))
  (execute (:create-index 'time :on host-stat :fields hour date month)))
