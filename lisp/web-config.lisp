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

(defun error-message (message &key (table t))
  (with-html-output (*standard-output*)
    (if table
	(htm (:tr (:td :class "error" :colspan 6 (:b (str message)))))
	(htm (:p (:b :class "error" (str message)))))))

;;; Possible errors:
;;;  - "badfilter": error parsing argus filter.
;;;  - "ports": error parsing port list
;;;  - "nocidrsuffix": network provided without a CIDR subnet mask
;;;  - "networkparse": error parsing network string
;;;  - "missingvlan": bad VLAN when adding
;;;  - "editvlan": error editing VLAN IDs
;;;  - "badvid": no parseable VID when editing VLANs.
;;;  - "novname": no Name specified when editing VLANs.
(hunchentoot:define-easy-handler (network-config :uri "/network-config")
    (error filter badports vid)
  (with-periscope-page ("Control Panel" :admin t)
    (unless *collector*
      (warning-box
       "Collector not initialized. This is a bug.")
      (return-from network-config))

    (with-config-form ("/set-config")
      (with-config-section ("Default Network Settings" "network")
	(:table
	 (when (string= error "badfilter")
	   (error-message (format nil "Syntax error found in Argus filter '~a'." filter))
	   (error-message "Please refer to the ra(1) manual page for Argus filter syntax."))
	 (:tr
	  (:td "Traffic Filter")
	  (:td (input "filter" *collector-default-filter* :size 30)))
	 (cond
	   ((string= error "nocidrsuffix")
	    (error-message "Error: Network subnet mask must be specified (e.g., 192.168.10.0/24)."))
	   ((string= error "networkparse")
	    (error-message "Error parsing CIDR network specification.")))
	 (:tr
	  (:td "Default Local Networks (CIDR)")
	  (:td (input "network" (format nil "~{~a~^, ~}" (network-strings *internal-networks*))
		      :size 30)))
	 (:tr
	  (:td "Notable ports (select to remove)")
	  (:td
	   (:select
	    :name "remove" :multiple t 
	    (dolist (port *notable-ports*)
	      (htm (:option :value port (fmt "~d (~a)" port (service-name port))))))))
	 (when (string= error "ports")
	   (error-message
	    (format nil "Invalid services or port numbers: ~a" badports)))
	 (:tr
	  (:td "Add notable ports:")
	  (:td (input "ports" "")))))

      (with-config-section ("Add VLAN Label" "addvlan")
	(when (string= error "missingvlan")
	  (error-message "VLAN IDs must be integers from 0 - 4095, and labels may not be empty."
			 :table nil))
	(:table	 
	 (:tr
	  (:td "VLAN ID")
	  (:td (input "newvid" "")))
	 (:tr
	  (:td "VLAN Label")
	  (:td (input "newvname" "")))))

      (let ((vlan-list (vlan-name-list)))
	(when vlan-list
	  (with-config-section ("Edit VLAN Labels" "editvlan")
	    (cond
	      ((string= error "badvid")
	       (error-message
		(format nil "'~a' is not a valid VLAN ID; must be a positive integer between 0 - 4095."
			vid) :table nil))
	      ((string= error "novname")
	       (error-message "VLAN IDs and labels cannot be empty. To delete an ID, please use the
\"Remove\" checkbox." :table nil)))
	    (:table
	     :class "input"
	     (:tr (:th "VLAN ID") (:th "Name") (:th "Remove"))
	     (loop :with index = 0
		:for (vid name) :in vlan-list :do
		(htm (:tr
		      (:td (input "vid" vid :index index :size 4))
		      (:td (input "vname" name :index index))
		      (:td (checkbox "delete" :index index :value vid))))
		(incf index)))
	    (:br))))
      (submit "Apply Configuration"))))

(defun ports-from-string (port-string)
  "Take a string of port numbers and/or service names, separated by
spaces and/or commas, and return a sorted list of integers
corresponding to these numbers.  Duplicate port numbers
are removed, and service names that could not be converted into numbers are
returned in a list as the second return value."
  (let (good bad)
    (dolist (token (tokenize port-string '(#\Space #\, #\Tab #\Newline)))
      (let ((port (service-port token)))
	(if (null port)
	    (push token bad)
	    (push port good))))
    (values (sort (remove-duplicates good) #'<)
	    (remove-duplicates (nreverse bad) :test #'equal))))
  
(defun subnets-from-string (subnet-string)
  "Take a string of CIDR subnet specifications, separated by spaces and/or commas, and return 
a list of networks and netmasks corresponding to these specifications.  Each network and netmask
combination form a dotted list, with the CAR representing the network and the CDR the netmask.
Invalid CIDR subnets will signal a PARSE-ERROR."
  (loop :for subnet :in
     (tokenize subnet-string (list #\Space #\Tab #\,)) :collect
     (multiple-value-bind (network netmask)
	 (parse-ip-string subnet)
       (cons network netmask))))

(hunchentoot:define-easy-handler (set-config :uri "/set-config")
    (network ports filter newvid newvname
	     (vid :parameter-type 'array)
	     (vname :parameter-type 'array)
	     (delete :parameter-type 'array))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/network-config"))
    (unless *collector*
      (error-redirect "null-collector"))

    (when filter
      ;; Create a 'scratch' collector, try to compile the filter, and
      ;; redirect if it is invalid.
      (handler-case
	  (let ((collector (init-basic-collector)))
	    (setf (filter collector) filter))
    	(periscope-error ()
    	  (error-redirect "badfilter" :filter filter)))
      ;; Filter is good - set the default filter.
      (setf *collector-default-filter* filter))
    
    ;; Network management options: notable ports, internal network, etc.
    (let ((remove-list
	   (mapcar (lambda (port)
		     (parse-integer (cdr port) :junk-allowed t))
		   (remove-if-not (lambda (param) (string= param "remove"))
				  (hunchentoot:post-parameters*) :key #'car))))
      (setf *notable-ports*
	    (delete-if (lambda (port)
			 (find port remove-list)) *notable-ports*)))

    (when (not (empty-string-p ports))
      (multiple-value-bind (good bad)
	  (ports-from-string ports)
	(unless (null bad)
	  (error-redirect "ports"
			  :badports (format nil "~{~A~^, ~}" bad)))
	(setf *notable-ports* (sort (union *notable-ports* good) #'<))))
	   
    (unless (empty-string-p network)
      (handler-case
	  (setf *internal-networks* (subnets-from-string network))
	(parse-error ()
	  (error-redirect "networkparse"))))

    ;; Edit existing VLAN identifiers.
    (when (/= (length vid) (length vname))
      ;; User is trying to be malicious - these lengths are always equal.
      (hunchentoot:redirect "/config"))

    ;; VLAN ID or label are blank.
    (when (or (some #'empty-string-p vid)
	      (some #'empty-string-p vname))
      (error-redirect "novname"))
    
    (let* ((vids (map 'vector (lambda (s) (parse-integer s :junk-allowed t)) vid))
	   (pos (position-if
		 (lambda (vid)
		   (not (and vid (vlan-p vid)))) vids)))
      (when pos
	(error-redirect "badvid" :vid (aref vid pos)))
      
      ;; NOTE: We should only get here if there are NO errors!
      ;; Otherwise we blow away the VLAN list...
      (clrhash *vlan-names*)
      (loop :with ndelete = (length delete)
	 :for i :from 0 :below (length vids) :do
	 (if (and (> ndelete i) (aref delete i))
	     nil
	     (setf (vlan-name (aref vids i)) (escape-string (aref vname i))))))
    
    ;; Add new VLAN identifier
    (cond ((empty-string-p newvid newvname)
	   ;; do nossing
	   )

	  ((empty-string-p newvname)
	   (error-redirect "missingvlan"))

	  (t
	   (let ((vid (handler-case (parse-integer newvid)
			(parse-error () nil))))
	     (when (or (null vid) (not (vlan-p vid)))
	       (error-redirect "missingvlan"))
	     
	     (setf (vlan-name vid) (escape-string newvname)))))

    (save-config)
    (error-redirect "success")))

(hunchentoot:define-easy-handler (periscope-config :uri "/periscope-config")
    (error host port)
  (with-periscope-page ("Periscope Configuration" :admin t)
    (when (string= error "success")
      (htm (:p :class "success" "Configuration values successfully applied!")))
    (with-config-form ("/set-periscope-config")
      (with-config-section ("Web Interface Settings" "web")
	(:table
	 (:tr
	  (:td "Web interface port")
	  (:td (input "web-port" *web-port*)))
	 (:tr
	  (:td "Perform DNS reverse lookup in reports")
	  (:td (checkbox "dnslookup" :checked *dns-available-p*)))))

      (if *collector-argus-server*
	  (with-config-section ("Data Collection Settings")
	    (cond
	      ((collector-running-p)
	       (htm
		"Currently connected to remote Argus server "
		(:b (str (collector-connect-string)))
		"." (:br)
		(:b (:a :href "/collector?action=stop" "Stop the collector."))))
	      (t (if (collector-aborted-p)
		     (htm
		      (:b :class "error" "Collector process failed to start.")
		      (:p
		       "Ensure Argus is running on " (:b (str (collector-connect-string)))
		       " and is accessible from this machine."
		       (collector-connect-string)))
		     (htm
		      "Data collection from " (:b (str (collector-connect-string))) " is stopped."
		      (:br)
		      (:a :href "/collector?action=start" "Start the collector.")))))))
      
      (with-config-section ("Argus Server Settings" "argus")
	(:table
	 (string-case error
	   ("badhost"
	    (error-message (format nil "Error: could not resolve host '~a'." host)))
	   ("badport"
	    (error-message (format nil "Error: ~a is not a valid IP port." port))))
	 (:tr
	  (:td "Hostname")
	  (:td (input "hostname" *collector-argus-server*)))
	 (:tr
	  (:td "Port")
	  (:td (input "port" *collector-argus-port*)))
	 (:tr
	  (:td "SASL Authentication")
	  (:td (checkbox "sasl")))))
      (submit "Apply Configuration"))))

(define-easy-handler (collector :uri "/collector")
    (action)
  (let ((*redirect-page* "/periscope-config"))
    (string-case action
      ("start"
       (unless (or (null *collector-argus-server*) (collector-running-p))
	 (unless (lookup *collector-argus-server*)
	   (error-redirect "badhost" :host *collector-argus-server*))
	 (bt:make-thread #'collector-thread :name "Collector external process")
	 (sleep 1)))

      ("stop"
       (unless (not (collector-running-p))
	 (bt:with-lock-held (*collector-shutdown-lock*)
	   (setf *collector-shutdown-p* t))
	 (stop-collector *collector-process*)))))

  (hunchentoot:redirect "/periscope-config?error=success"))

(hunchentoot:define-easy-handler (set-periscope-config :uri "/set-periscope-config")
    ((web-port :parameter-type 'integer) dnslookup hostname port)
  (valid-session-or-lose :admin t)
  
  (let ((*redirect-page* "/periscope-config"))
    ;; TODO: Restart server!   
    (when web-port
      (setf *web-port* web-port))
    
    ;; Start and stop DNS lookup thread according to the dnslookup value.
    (cond
      ((and *dns-available-p* (null dnslookup))
       (stop-dns))
      ((and (not *dns-available-p*) (not (null dnslookup)))
       (start-dns)))
    
    ;; Empty hostnames are bad news.
    (unless (empty-string-p hostname)
      (unless (lookup hostname)
    	(error-redirect "badhost" :host hostname))
      (let ((port (handler-case (parse-integer port)
    		    (parse-error () port))))
    	(unless (port-number-p port)
    	  (error-redirect "badport" :port port))
	
	
    	;; If the collector is currently running and we change the hostname,
    	;; we must stop the currently running collector.
    	(when (collector-running-p)
    	  (when (or (/= (lookup hostname) (lookup *collector-argus-server*))
		    (/= port *collector-argus-port*))
	    (stop-collector *collector-process*)))

    	(when (collector-aborted-p)
    	  (setf *collector-process* nil))

	(setf *collector-argus-server* hostname)
	(setf *collector-argus-port* port)))
      
    ;; TODO: need to implement saving sources.
    (save-config)
    (error-redirect "success")))

(defun print-sources (list title)
  (when list
    (with-html-output (*standard-output*)
      (:tr (:th :colspan 6 (:b (fmt "~a Sources" title))))
      (:tr (:th "Hostname") (:th "IP") (:th "Port") (:th "Use SASL") (:th "Status") (:th "Remove"))
      (loop :with i = 0
	 :for source :in list :do
	 (htm
	  (:tr
	   (:td (str (hostname (remote-ip source))))
	   (:td (str (ip-string (remote-ip source))))
	   (:td (str (port source)))
	   ;; TODO: Implement me!
	   (:td "No")
	   (:td (str (if (connected-p source) "Connected" "Not Connected")))
	   (:td
	    (checkbox (format nil "remove[~d]" i) :value (remote-ip source)))))
	 (incf i)))))