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

(defclass argus-log ()
  ((pathname :initarg :pathname :reader argus-log-pathname :type pathname)
   (type     :initarg :type     :reader argus-log-type     :type keyword)
   (timestamp :initarg :timestamp :reader argus-log-timestamp :type simple-date:timestamp)
   (gzip-p :initarg :gzip-p :reader argus-log-gzip-p :type boolean)))

(defmethod parse-log-pathname ((file pathname))
  (ppcre:register-groups-bind (type (#'parse-integer year month date hour minute))
      ("([a-z]+)-(\\d{4})(\\d{2})(\\d{2})-(\\d{2}):?(\\d{2})?" (pathname-name file))
    (make-instance 'argus-log
		   :pathname file
		   :type (string-case type
			   ("test" :test)
			   ("fm" :five-minute)
			   ("hourly" :hour))
		   :timestamp (simple-date:encode-timestamp year month date hour (or minute 0))
		   :gzip-p (string= (pathname-type file) "gz"))))

(defmethod parse-log-pathname ((file string))
  (parse-log-pathname (pathname file)))

(defmethod timestamp-string ((object simple-date:timestamp))
  (multiple-value-bind (year month day hour minute)
      (simple-date:decode-timestamp object)
    (format nil "~4,'0d-~2,'0d-~2,'0d ~2,'0d:~2,'0d" year month day hour minute)))

(defmethod print-object ((object argus-log) stream)
  (print-unreadable-object (object stream :type t)
    (format stream "type ~a, timestamp ~a"
	    (argus-log-type object)
	    (timestamp-string (argus-log-timestamp object)))))