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

;;; Possible errors:
;;;  - "ports": error parsing port list
;;;  - "nocidrsuffix": network provided without a CIDR subnet mask
;;;  - "networkparse": error parsing network string
;;;  - "missingvlan": bad VLAN when adding
;;;  - "editvlan": error editing VLAN IDs
;;;  - "badvid": no parseable VID when editing VLANs.
;;;  - "novname": no Name specified when editing VLANs.
(hunchentoot:define-easy-handler (config :uri "/config") (error)
  (with-periscope-page ("Control Panel" :login t)
    (flet ((error-message (message &key (table t))
	     (if table
		 (htm (:tr (:td :class "error" :colspan 3 (:b (str message)))))
		 (htm (:b :class "error" (str message))))))
      (unless *collector*
	(warning-box
	 "Collector not initialized. This is a bug.")
	(return-from config))

      (when (string= error "success")
	(htm (:p "Configuration values successfully applied!")))

      (with-config-form ("/set-config" "Web Interface Configuration" "web")
	(:table
	 (:tr
	  (:td "Web interface port")
	  (:td (input "web-port" *web-port*)))
	 (:tr
	  (:td "Perform DNS reverse lookup in reports")
	  (:td (checkbox "dnslookup" :checked *dns-lookup-p*))))
	(:input :type "submit" :value "Apply Configuration"))

      (with-config-form ("/set-config" "Network Configuration" "network")
	(:table
	 (:tr
	  (:td "Traffic Filter")
	  (:td (input "filter" (if *collector* (filter *collector*) ""))))
	 (cond
	   ((string= error "nocidrsuffix")
	    (error-message "Error: Network subnet mask must be specified (e.g., 192.168.10.0/24)."))
	   ((string= error "networkparse")
	    (error-message "Error parsing CIDR network specification.")))
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
	 (when (string= error "ports")
	   (error-message "Error: Port numbers must be separated by spaces or commas."))
	 (:tr
	  (:td "Add notable ports:")
	  (:td (input "ports" ""))))
	(:input :type "submit" :value "Apply Configuration"))

      (with-config-form ("/set-config" "Add VLAN Identifier" "addvlan")
	(when (string= error "missingvlan")
	  (error-message "Error setting VLAN identifier; both a valid VID and non-empty name
must be specified!" :table nil))
	(:table	 
	 (:tr
	  (:td "VLAN ID")
	  (:td (input "newvid" "")))
	 (:tr
	  (:td "VLAN Name")
	  (:td (input "newvname" ""))))
	(:input :type "submit" :value "Add VLAN"))

      (with-config-form ("/set-config" "Edit VLAN Identifiers" "editvlan")
	(cond
	  ((string= error "badvid")
	   (error-message "Bad VLAN ID; must be a positive integer between 0-4095." :table nil))
	  ((string= error "novname")
	   (error-message "VLAN names must not be empty. To delete an ID, please use the
\"Remove\" checkbox." :table nil)))
	(:table
	 :class "input"
	 (:tr (:th "VLAN ID") (:th "Name") (:th "Remove"))
	 (loop :with index = 0
	    :for (vid name) :in (vlan-name-list) :do
	    (htm (:tr
		  (:td (input (format nil "vid[~d]" index) vid :size 4))
		  (:td (input (format nil "vname[~d]" index) name))
		  (:td (checkbox (format nil "delete[~d]" index) :value vid))))
	    (incf index)))
	(:input :type "submit" :value "Commit Changes")))))

(defun ports-from-string (port-string)
  "Take a string of port numbers, separated by spaces and/or commas, and return a sorted list
of integers corresponding to these numbers.  Duplicate and invalid port numbers are removed."
  (parse-integer-list port-string (lambda (port) (> port 65535))))

(hunchentoot:define-easy-handler (set-config :uri "/set-config")
    (action (web-port :parameter-type 'integer) dnslookup
	    network ports filter
	    (newvid :parameter-type 'integer) newvname
	    (vid :parameter-type 'array)
	    (vname :parameter-type 'array)
	    (delete :parameter-type 'array))

  (valid-session-or-lose)

  (flet ((config-error (type)
	   (hunchentoot:redirect (format nil "/config?error=~a" type))))

    (unless *collector*
      (config-error "null-collector"))
  
    (cond ((string= action "monitor")
	   (when filter
	     (setf (filter *collector*) filter)))

	  ((string= action "web")
	   ;; TODO: Restart server!   
	   (when web-port
	     (setf *web-port* web-port))

	   (setf *dns-lookup-p* (not (null dnslookup))))
	  
	  ((string= action "network")
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
	   (if (and newvid newvname)
	       (setf (vlan-name newvid) newvname)
	       (config-error "missingvlan")))

	  ((string= action "editvlan")
	   ;; User is trying to be malicious - these lengths are always equal.
	   (when (/= (length vid) (length vname))
	     (hunchentoot:redirect "/config"))

	   (let ((vids (map 'vector (lambda (s) (parse-integer s :junk-allowed t)) vid)))
	     (cond
	       ;; VLAN ID not parseable.
	       ((some #'null vids) (config-error "badvid"))
	       ;; VLAN number is set, but name is blank
	       ((some #'empty-string-p vname) (config-error "novname")))
	   
	     ;; NOTE: We should only get here if there are NO errors!
	     ;; Otherwise we blow away the VLAN list...
	     (clrhash *vlan-names*)
	     (loop :with ndelete = (length delete)
		:for i :from 0 :below (length vids) :do
		(if (and (> ndelete i) (aref delete i))
		    nil
		    (setf (vlan-name (aref vids i)) (aref vname i)))))))
  
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