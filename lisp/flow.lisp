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

(deftype vlan-id ()
  '(unsigned-byte 12))

(defclass flow ()
  ((source :initarg :source :reader source)
   (dest :initarg :dest :reader dest)
   (protocol :initarg :protocol :reader protocol :initform (error "Must supply IP protocol!"))))

(defclass flow-host ()
  ((ip :initarg :ip :reader host-ip :initform (error "Must suppy IP addresss!"))
   (port :initarg :port :reader host-port)
   (packets :initarg :packets :reader host-packets)
   (bytes :initarg :bytes :reader host-bytes)
   (vlan :accessor host-vlan)
   (start-time :reader host-start-time)
   (end-time :reader host-end-time)))

(defun build-flow (dsrs ip)
  "Create a FLOW object given a set of Argus DSRs and an ArgusIPFlow structure."
  (with-foreign-slots ((ip-src ip-dst ip-proto source-port dest-port) ip argus-ip-flow)
    (let* ((source (make-instance 'flow-host :ip ip-src :port source-port))
	   (dest (make-instance 'flow-host :ip ip-dst :port dest-port))
	   (flow (make-instance 'flow :source source :dest dest :protocol ip-proto)))
      
      (with-slots (packets bytes start-time end-time) source
	(multiple-value-setq (packets bytes) (source-metrics dsrs))
	(multiple-value-setq (start-time end-time) (source-time dsrs)))
      
      (with-slots (packets bytes start-time end-time) dest
	(multiple-value-setq (packets bytes) (dest-metrics dsrs))
	(multiple-value-setq (start-time end-time) (dest-time dsrs)))

      (unless (null-pointer-p (get-vlan dsrs))
	(with-foreign-slots ((sid did) (get-vlan dsrs) argus-vlan)
	  (setf (host-vlan source) (logand sid +vlan-vid-mask+)
		(host-vlan dest) (logand did +vlan-vid-mask+))))
      
      flow)))

(defmethod classify ((object flow) &key (network *internal-network*) (netmask *internal-netmask*))
  (with-slots (source dest) object
    (cond ((network-member-p (host-ip source) network netmask)
	   (if (network-member-p (host-ip dest) network netmask)
	       :internal-only
	       :outgoing))
	  ((network-member-p (host-ip dest) network netmask)
	   :incoming)
	  (t :external-only))))

(let ((row-switch t))
  (defmethod print-html ((object flow) &key)
    (flet ((print-host (host)
	     (with-html-output (*standard-output*)
	       (:td (str (ip-string (host-ip host))))
	       (:td (fmt "~d" (host-port host)))
	       (:td (fmt "~:d" (host-packets host)))
	       (:td (str (if (= +vlan-none+ (host-vlan host)) "" (vlan-name (host-vlan host))))))))
      (setf row-switch (not row-switch))
      (with-slots (source dest protocol) object
	(with-html-output (*standard-output*)
	  (:tr :class (if row-switch "rowa" "rowb")
	       (print-host source)
	       (print-host dest)
	       (:td (str (case protocol
			   (1 "ICMP")
			   (2 "IGMP")
			   (6 "TCP")
			   (17 "UDP"))))
	       (:td (str (min (host-start-time source) (host-start-time dest))))
	       (:td (str (max (host-end-time source) (host-end-time dest))))))))))