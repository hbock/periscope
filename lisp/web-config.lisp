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

(defconstant +config-success+ 0)

(hunchentoot:define-easy-handler (sources :uri "/sources") ()
  (with-periscope-page ("Manage Argus Sources")
    (:div :class "config-header" "Collector Operation")
    (unless *collector*
      (warning-box
       "Collector not initialized. This is a bug.")
      (return-from sources))
    
    (when (not (running-p *collector*))
      (if (null (remote-sources *collector*))
	  (warning-box
	   (:p "The collector is not running, and no sources have been defined.")
	   (:p "Please add one or more sources below before starting the collector."))
	  (warning-box
	   "The collector is not running." (:br)
	   (:b (:a :href "/manage-sources?action=run" "Click here to run the collector.")))))
    
    (when *collector*
      (print-remote-sources *collector*))
    
    (:p
     (:form      
      :action "/manage-sources" :method "post"
      (:div :class "config-header" "Add Argus Server")
      (:div
       :class "config-section"
       (:table
	(:tr
	 (:td "Hostname")
	 (:td (input "hostname" "")))
	(:tr
	 (:td "Port")
	 (:td (input "hostname" 561)))
	(:tr
	 (:td "SASL Authentication")
	 (:td (checkbox "sasl"))))
       (:input :type "hidden" :name "action" :value "add")
       (:input :type "submit" :value "Add")
       (:br))))))

(hunchentoot:define-easy-handler (config :uri "/config") ((err :parameter-type 'integer))
  (with-periscope-page ("Control Panel" :login t)
    (unless *collector*
      (warning-box
       "Collector not initialized. This is a bug.")
      (return-from config))

    (when err
      (case err
	(#.+config-success+
	 (htm (:p "Configuration values successfully applied!")))))

    (with-config-form ("/set-config" "Monitoring Configuration" "monitor")
      (:table
       (:tr
	(:td "Traffic Filter")
	(:td (input "filter" (if *collector* (filter *collector*) "")))))
      (:input :type "submit" :value "Apply Configuration"))

    (with-config-form ("/set-config" "Network Configuration" "network")
      (:table
       (:tr
	(:td "Web interface port")
	(:td (input "web-port" *web-port*)))
       (:tr
	(:td "Local Network (CIDR)")
	(:td (input "network" (ip-string *internal-network* *internal-netmask*))))
       (:tr
	(:td "Notable ports (select to remove)")
	(:td
	 (:select
	  :name "remove" :multiple t 
	  (dolist (port *notable-ports*)
	    (htm (:option :value port (fmt "~d (~a)" port (service-name port))))))))
       (:tr
	(:td "Add notable ports:")
	(:td (input "ports" ""))))
      (:input :type "submit" :value "Apply Configuration"))

    (with-config-form ("/set-config" "Add VLAN Identifier" "addvlan")
      (:table
       (:tr
	(:td "VLAN ID")
	(:td (input "vid" "")))
       (:tr
	(:td "VLAN Name")
	(:td (input "vname" ""))))
      (:input :type "submit" :value "Add VLAN"))

    (with-config-form ("/set-config" "Edit VLAN Identifiers" "editvlan")
      (:table
       :class "input"
       (:tr (:th "VLAN ID") (:th "Name") (:th "Remove"))
       (loop :for (vid name) :in (vlan-name-list) :do
	  (htm (:tr
		(:td (input (format nil "vid~d" vid) vid :size 4))
		(:td (input (format nil "vname~d" vid) name))
		(:td (checkbox (format nil "delete~d" vid)))))))
      (:input :type "submit" :value "Commit Changes"))))

(defun ports-from-string (port-string)
  "Take a string of port numbers, separated by spaces and/or commas, and return a sorted list
of integers corresponding to these numbers.  Duplicate and invalid port numbers are removed."
  (parse-integer-list port-string (lambda (port) (> port 65535))))

(hunchentoot:define-easy-handler (set-config :uri "/set-config")
    (action (web-port :parameter-type 'integer) network ports filter
	    (vid :parameter-type 'integer) vname)

  (valid-session-or-lose)

  (flet ((config-error (type)
	   (hunchentoot:redirect (format nil "/config?error=~a" type))))

    (unless *collector*
      (config-error "null-collector"))
  
    (cond ((string= action "monitor")
	   (when filter
	     (setf (filter *collector*) filter)))
	
	  ((string= action "network")
	   ;; TODO: Restart server!	   
	   (when web-port
	     (setf *web-port* web-port))

	   (let ((remove-list
		  (mapcar (lambda (port)
			    (parse-integer (cdr port) :junk-allowed t))
			  (remove-if-not (lambda (param) (string= param "remove"))
					 (hunchentoot:post-parameters*) :key #'car))))
	     (setf *notable-ports*
		   (delete-if (lambda (port)
				(find port remove-list)) *notable-ports*)))

	   (when (not (empty-string-p ports))
	     (if (ppcre:scan "^(\\d{1,5}( *|(, *)))+$" ports)
		 (setf *notable-ports*
		       (sort (union *notable-ports* (ports-from-string ports)) #'<))
		 (config-error "ports")))
	   
	   (when network
	     (handler-case
		 (multiple-value-bind (network netmask)
		     (parse-ip-string network)
		   (unless netmask
		     (config-error "nocidrsuffix"))
		   (setf *internal-network* network)
		   (setf *internal-netmask* netmask))
	       (parse-error ()
		 (config-error "networkparse")))))

	  ((string= action "addvlan")
	   (if (and vid vname)
	       (setf (vlan-name vid) vname)
	       (config-error "missingvlan")))

	  ((string= action "editvlan")
	   (loop :for (name . value) :in (hunchentoot:post-parameters*) :do
	      (ppcre:register-groups-bind ((#'parse-integer vid))
		  ("^vid(\\d{1,4})$" name)
		(when vid
		  (let ((new-vid (parse-integer value :junk-allowed t))
			(name (hunchentoot:post-parameter (format nil "vname~d" vid)))
			(remove (hunchentoot:post-parameter (format nil "delete~d" vid))))
		    (when remove
		      (setf (vlan-name vid) nil))
		    (when (and (not remove) name)
		      (cond
			((and new-vid (= vid new-vid) (not (string= value (vlan-name vid))))
			 ;; Update old VID name.
			 (setf (vlan-name vid) name))
			((and new-vid (/= vid new-vid))
			 ;; The user changed the VID of this field; remove the old
			 ;; name binding and establish a name binding with the newly
			 ;; entered VID
			 (setf (vlan-name vid) nil)
			 (setf (vlan-name new-vid) name))
			(t (config-error "editvlan"))))))))))
  
    (save-config)
    (config-error "success")))

(hunchentoot:define-easy-handler (manage-sources :uri "/manage-sources")
    (action hostname port (sid :parameter-type 'integer))
  (valid-session-or-lose)
  (when (and (not (running-p *collector*))
	     (string= action "run"))
    (web-run-collector *collector*))
  (cond
    ((string= action "add")
     (add-remote *collector* hostname))
    ((string= action "remove")
     (when sid
       (setf (remote-sources *collector*)
	     (delete-if (lambda (src)
			  (= (pointer-address (get-ptr src)) sid))
			(remote-sources *collector*))))))

  ;;(save-config)
  (hunchentoot:redirect "/sources?error=0"))

(defun print-remote-sources (&optional (collector *collector*))
  (when (remote-sources collector)
    (with-html-output (*standard-output*)
      (:div :class "config-header" "Manage Sources")
      (:div
       :class "config-section"
       (:table
	:class "sources"
	(:tr (:th "Hostname") (:th "Port") (:th "Status") (:th "Options"))	 
	(dolist (source (remote-sources collector))
	  (htm
	   (:tr
	    (:td (str (source-path source)))
	    ;; TODO: Implement me!
	    (:td (str 561))
	    (:td (str
		  (if (connected-p source)
		      "Connected"
		      "Not Connected")))
	    (:td
	     (:a :href (format nil "/manage-sources?action=remove&sid=~a"
			       (pointer-address (get-ptr source)))
		 "Remove")
	     " "
	     (:a :href (format nil "/manage-sources?action=connect&id=~a"
			       (pointer-address (get-ptr source)))
		 (str
		  (if (connected-p source)
		      "Disconnect"
		      "Connect"))))))))))))