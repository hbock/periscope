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
	(htm (:tr (:td :class "error" :colspan 3 (:b (str message)))))
	(htm (:b :class "error" (str message))))))

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
    (error filter)
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
	  (:td (input "filter" (if *collector* (filter *collector*) "") :size 30)))
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
	   (error-message "Error: Port numbers must be separated by spaces or commas."))
	 (:tr
	  (:td "Add notable ports:")
	  (:td (input "ports" "")))))

      (with-config-section ("Add VLAN Label" "addvlan")
	(when (string= error "missingvlan")
	  (error-message "Error setting VLAN label; both a valid VID and non-empty name
must be specified!" :table nil))
	(:table	 
	 (:tr
	  (:td "VLAN ID")
	  (:td (input "newvid" "")))
	 (:tr
	  (:td "VLAN Label")
	  (:td (input "newvname" "")))))

      (with-config-section ("Edit VLAN Labels" "editvlan")
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
	(:br)
	(submit "Apply Configuration")))))

(defun ports-from-string (port-string)
  "Take a string of port numbers and/or service names, separated by
spaces and/or commas, and return a sorted list of integers
corresponding to these numbers.  Duplicate port numbers
are removed, and service names that could not be converted into numbers are
returned in a list as the second return value."
  (let* ((tokens (tokenize port-string '(#\Space #\, #\Tab #\Newline)))
	(ports (mapcar #'service-port tokens)))
    (loop :for port :in ports
       :if (null port) :collect (nth (position nil ports) tokens) :into bad
       :else :collect port :into good
       :finally
       (return (values (sort (remove-duplicates good) #'<)
		       (remove-duplicates bad :test #'equal))))))

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
    (network ports filter
	     (newvid :parameter-type 'integer) newvname
	     (vid :parameter-type 'array)
	     (vname :parameter-type 'array)
	     (delete :parameter-type 'array))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/network-config"))
    (unless *collector*
      (error-redirect "null-collector"))

    (when filter
      (handler-case
	  (setf (filter *collector*) filter)
	(periscope-error ()
	  (error-redirect "badfilter" :filter filter))))
    
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

    (let ((vids (map 'vector (lambda (s) (parse-integer s :junk-allowed t)) vid)))
      (cond
	;; VLAN ID not parseable.
	((some #'null vids)  (error-redirect "badvid"))
	;; VLAN number is set, but name is blank
	((some #'empty-string-p vname) (error-redirect "novname")))
	   
      ;; NOTE: We should only get here if there are NO errors!
      ;; Otherwise we blow away the VLAN list...
      (clrhash *vlan-names*)
      (loop :with ndelete = (length delete)
	 :for i :from 0 :below (length vids) :do
	 (if (and (> ndelete i) (aref delete i))
	     nil
	     (setf (vlan-name (aref vids i)) (escape-string (aref vname i))))))
    
    ;; Add new VLAN identifier
    (cond ((and (null newvid) (empty-string-p newvname))
	   ;; do nossing
	   )

	  ((or (null newvid) (not (vlan-p newvid)))
	   (error-redirect "badvid"))

	  ((empty-string-p newvname)
	   (error-redirect "novname"))

	  (t
	   (setf (vlan-name newvid) (escape-string newvname))))

    (save-config)
    (error-redirect "success")))

(hunchentoot:define-easy-handler (periscope-config :uri "/periscope-config") (error host port)
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
    
      (with-config-section ("Add Argus Server" "add")
	(:table
	 (cond
	   ((string= error "invalidhost")
	    (error-message
	     (format nil "Error: Hostname \"~a:~a\" did not resolve or is a duplicate." host port))))
	 (:tr
	  (:td "Hostname")
	  (:td (input "hostname" "")))
	 (:tr
	  (:td "Port")
	  (:td (input "port" 561)))
	 (:tr
	  (:td "SASL Authentication")
	  (:td (checkbox "sasl")))))
      (submit "Apply Configuration"))))

(defun error-redirect (type &rest more-params)
  (let ((*print-case* :downcase))
    (hunchentoot:redirect
     ;; This is an ABOMINATION, yet it is pretty awesome all the same.
     (format nil "~a?error=~a~:[~;&~:*~{~a=~a~^&~}~]" *redirect-page* type
	     (mapcar (lambda (param)
		       (when (stringp param) (url-encode param))) more-params)))))

(hunchentoot:define-easy-handler (set-periscope-config :uri "/set-periscope-config")
    ((web-port :parameter-type 'integer) dnslookup
     hostname (port :parameter-type 'integer) (remove :parameter-type 'array))
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
      (error-redirect "emptyhost")
       
      ;; An error in this case usually means the host was invalid/not resolvable.
      (handler-case
	  (add-remote *collector* hostname port)
	(simple-error ()
	  (error-redirect "invalidhost" :host hostname :port port))))
      
    ;; ;; Removing an invalid source will cause an error; ignore this and immediately redirect
    ;; ;; to /sources.  This is either a bug or a malicious attempt to access memory.
     
    ;; (handler-case
    ;; 	(loop :for index :from 0 :below (length remove) :do
    ;; 	   (let ((source (find (aref remove index) (available-sources *collector*))))
    ;; 	     (when source (remove-source source *collector*))))
    ;;   (simple-error ()
    ;; 	(hunchentoot:redirect "/sources")))

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