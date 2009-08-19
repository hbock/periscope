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

(defun connect-db (database-name &key (user *periscope-db-user*)
		   (host *periscope-db-host*)
		   (password *periscope-db-password*))
  (setf *periscope-db-connection* (pomo:connect database-name user password host)))

(defun disconnect-db (&optional (connection *periscope-db-connection*))
  (pomo:disconnect connection))

(defclass host-stat ()
  ((host-ip :col-type bigint :initarg :host-ip :reader host-ip)
   (host-type :col-type integer :initarg :host-type :reader host-type)
   (hour :col-type smallint :initarg :hour)
   (date :col-type smallint :initarg :date)
   (month :col-type smallint :initarg :month)
   (sent-flows :col-type bigint :initform 0 :reader sent-flows)
   (sent-bytes :col-type bigint :initform 0 :reader sent-bytes)
   (sent-packets :col-type bigint :initform 0 :reader sent-packets)
   (received-flows :col-type bigint :initform 0 :reader received-flows)
   (received-bytes :col-type bigint :initform 0 :reader received-bytes)
   (received-packets :col-type bigint :initform 0 :reader received-packets))
  (:metaclass pomo:dao-class)
  (:keys host-ip hour date month))
