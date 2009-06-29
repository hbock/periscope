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

(defun ip-string (ip &optional subnet)
  "Convert an IPv4 address from an integer to a string in dotted quad notation.
If subnet is specified, a CIDR suffix will be appended to the end of the string."
  (declare (type (unsigned-byte 32) ip))
  (flet ((count-bits (integer)
	   (loop :with ones = 0
	      :for bit :from 0 :upto 31
	      :when (plusp (logand integer (ash #x0001 bit))) 
	      :do (incf ones) :finally (return ones))))
    (format nil "~d.~d.~d.~d~:[~;/~d~]"
	    (ldb (byte 8 24) ip)
	    (ldb (byte 8 16) ip)
	    (ldb (byte 8  8) ip)
	    (ldb (byte 8  0) ip)
	    subnet
	    (when subnet
	      (count-bits subnet)))))

(defun parse-ip-string (string &key junk-allowed)
  "Parse an IPv4 string in dotted quad notation, optionally with a CIDR subnet mask,
to a corresponding 32-bit IPv4 address and corresponding subnet mask. If the subnet mask
portion is not specified, the returned subnet mask will be NIL. Throws an error of type
PARSE-ERROR if string is not a valid IPv4 string unless :junk-allowed is T."
  (flet ((throw-parse-error (string)
	   #-sbcl (error 'parse-error)
	   #+sbcl (error 'sb-int::simple-parse-error
			 :format-control "Junk in IPv4 string: ~S"
			 :format-arguments (list string))))
    (let ((ip-regex "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})(/(\\d{1,2}))?$"))
      (when (not (or (ppcre:scan ip-regex string) junk-allowed))
	(throw-parse-error string))
      (ppcre:register-groups-bind ((#'parse-integer oct1 oct2 oct3 oct4) nil (#'parse-integer subnet))
	  (ip-regex string)
	;; Check to make sure all octets are <= 255, and the bit count for the CIDR subnet mask
	;; is less than or equal to 32.
	(when (or (some (lambda (octet) (< 255 octet)) (list oct1 oct2 oct3 oct4))
		  (and subnet (< 32 subnet)))
	  (if junk-allowed
	      (return-from parse-ip-string nil)
	      (throw-parse-error string)))
	(values
	 ;; We be throwin' around type-safety like its free or somethin
	 (the (unsigned-byte 32)
	   (logior (ash oct1 24) (ash oct2 16) (ash oct3 8) oct4))
	 (when subnet
	   (logand #xFFFFFFFF (ash #xFFFFFFFF (- 32 subnet)))))))))

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
  "Returns the VLAN name associated with identifier vlan (an integer).
Entries can be added using SETF."
  (declare (type (integer 0 4095) vlan))
  (gethash vlan *vlan-names* vlan))

(defun (setf vlan-name) (name vlan)
  (if name
      (setf (gethash vlan *vlan-names*) name)
      (remhash vlan *vlan-names*)))

(defun vlan-name-list ()
  "Returns a list of all VLAN identifiers associated with a name, sorted in ascending
order by VLAN ID."
  (sort
   (loop :for vid :being :the :hash-keys :in *vlan-names* :using (:hash-value name)
      :collect (list vid name)) #'< :key #'first))

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

(defun iso8661-date-string (&optional (time (local-time:now)))
  "Convert a universal time to an ISO8661 date string."
  (let ((format '((:year 4) #\- (:month 2) #\- (:day 2) #\T (:hour 2) #\: (:min 2) #\: (:sec 2))))
    (local-time:format-timestring t time :format format)))

(defun next-hour (timestamp)
  (local-time:timestamp+ (local-time:timestamp-minimize-part timestamp :min) 1 :hour))

(defun previous-hour (timestamp)
  (local-time:timestamp- (local-time:timestamp-minimize-part timestamp :min) 1 :hour))