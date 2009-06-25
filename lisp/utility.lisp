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

(defun ip-string (ip)
  "Convert an IPv4 address from an integer to a string in dotted quad notation."
  (declare (type (unsigned-byte 32) ip))
  (format nil "~d.~d.~d.~d"
	  (ldb (byte 8 24) ip)
	  (ldb (byte 8 16) ip)
	  (ldb (byte 8  8) ip)
	  (ldb (byte 8  0) ip)))

(defun network-member-p (ip network netmask)
  "Returns true if IP is a member of the IPv4 network specified by NETWORK and NETMASK."
  (= network (logand ip netmask)))

(defun local-host-p (ip &optional (network *internal-network*) (netmask *internal-netmask*))
  (network-member-p ip network netmask))

(defun remote-host-p (ip &optional (network *internal-network*) (netmask *internal-netmask*))
  (not (network-member-p ip network netmask)))

(defun create-service-cache (&optional (service-file (pathname "/etc/services")))
  "Generate the Internet service name cache for use with SERVICE-NAME.  SERVICE-FILE
is parsed to create the cache; by default, it is created using the system file
/etc/services."
  (clrhash *service-cache*)
  (with-open-file (services service-file :direction :input)
    (loop :for line = (read-line services nil)
       :while line :do
       (cl-ppcre:do-register-groups (name (#'parse-integer port) protocol)
	   ("([a-zA-Z\\d-+./]+)[ \\t\\n\\r]+(\\d+)/(udp|tcp)" line)
	 (let ((service-names (gethash port *service-cache* (cons nil nil))))
	   (cond ((string= protocol "tcp")
		  (setf (car service-names) name))
		 ((string= protocol "udp")
		  (setf (cdr service-names) name))
		 (t (error "Unknown protocol ~a!" protocol)))
	   (setf (gethash port *service-cache*) service-names))))))

(defun service-name (port &key (protocol :tcp))
  "Return the Internet service name for a given PORT and PROTOCOL basic on the system 
services file (default is /etc/services)."
  (when (zerop (hash-table-count *service-cache*))
    (create-service-cache))
  (let ((service-names (gethash port *service-cache*)))
    (ecase protocol
      ((:tcp #.+ip-proto-tcp+) (car service-names))
      ((:udp #.+ip-proto-udp+) (cdr service-names)))))

(defun vlan-name (vlan)
  (gethash vlan *vlan-names* vlan))

(defun (setf vlan-name) (name vlan)
  (setf (gethash vlan *vlan-names*) name))

(defun byte-string (bytes &optional (precision 2))
  "Convert BYTES from an integer to a size string, optionally specifying the precision in
digits following the decimal point."
  (declare (type integer precision))
  (if (< bytes 1024)
      (format nil "~:d B" bytes)
      (loop :for (boundary name) :in
	 '((1099511627776 "TB") (1073741824 "GB") (1048576 "MB") (1024 "kB"))
	 :when (>= bytes boundary) :do
	 (return (format nil "~v$ ~a" precision (/ bytes boundary) name)))))

(defun utc-date-string (&optional (time (get-universal-time)))
  "Convert a universal time to an ISO8661 date string."
  (multiple-value-bind (sec minute hour date month year)
      (decode-universal-time time)
    (declare (ignore sec))
    (format nil "~4,'0d-~2,'0d-~2,'0d ~2,'0d:~2,'0d" year month date hour minute)))