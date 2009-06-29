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

(defun build-flow (dsrs ip)
  (with-foreign-slots ((ip-src ip-dst ip-proto source-port dest-port) ip argus-ip-flow)
    (let ((flow (make-instance 'flow :ip-source ip-src :ip-dest ip-dst :port-source source-port
			       :port-dest dest-port :protocol ip-proto)))
      (with-slots (packets-source packets-dest bytes-source bytes-dest) flow
	(multiple-value-setq (packets-source bytes-source) (source-metrics dsrs))
	(multiple-value-setq (packets-dest bytes-dest) (dest-metrics dsrs)))

      (with-slots (time-start-source time-end-source time-start-dest time-end-dest) flow
	(multiple-value-setq (time-start-source time-end-source) (source-time dsrs))
	(multiple-value-setq (time-start-dest time-end-dest) (dest-time dsrs)))
      
      (unless (null-pointer-p (get-vlan dsrs))
	(with-foreign-slots ((sid did) (get-vlan dsrs) argus-vlan)
	  (with-slots (vlan-source vlan-dest) flow
	    (setf vlan-source (logand sid +vlan-vid-mask+)
		  vlan-dest (logand did +vlan-vid-mask+)))))
      flow)))
  
(defcallback receive-flow :void ((collector periscope-collector)
				 (type :uchar)
				 (record :pointer)
				 (dsrs periscope-dsrs))
  (declare (ignore collector record))
  (case (foreign-enum-keyword 'argus-flow-types type :errorp nil)
    (:ipv4 (let ((ip (get-ip (get-flow dsrs))))
	     (push (build-flow dsrs ip) *flow-list*)))))

(defun init-basic-collector ()
  (let ((collector (make-instance 'collector)))
    (with-collector-callbacks (process_flow) collector
	(setf process_flow (callback receive-flow)))
    collector))

(defun main ()
  (handler-bind ((simple-error
		  (lambda (c)
		    (declare (ignore c))
		    (invoke-restart 'create-new-config-file))))
    (load-config))

  (start-web)
  (setf *collector* (init-basic-collector))
  
  (return-from main 0))