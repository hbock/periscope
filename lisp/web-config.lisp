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
    (:h2 "Manage Argus Sources")
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
	   (:b (:a :href "/config?action=run" "Click here to run the collector.")))))
    
    (when *collector*
      (print-remote-sources *collector*))
    
    (:p
     (:h2 "Sources Configuration")
     (:h3 "Add a source")
     (:form
      :action "/set-config" :method "post"
      (:label :for "source" "Hostname: ")
      (:input :type "text" :size 20 :name "source")
      (:input :type "hidden" :name "action" :value "add")
      (:input :type "submit" :value "Add")
      (:br)))))

(hunchentoot:define-easy-handler (config :uri "/config") ((err :parameter-type 'integer))
  (with-periscope-page ("Control Panel")
    (unless *collector*
      (warning-box
       "Collector not initialized. This is a bug.")
      (return-from config))

    (when err
      (case err
	(#.+config-success+
	 (htm (:p "Configuration values successfully applied!")))))

    (htm
     (:form
      :action "/set-config" :method "post"
      (:div :class "config-header" "Monitoring Configuration")
      (:div
       :class "config-section"
       (:table
	(:tr
	 (:td "Traffic Filter")
	 (:td (input "filter" (if *collector* (filter *collector*) ""))))))
      (:div :class "config-header" "Network Configuration")
      (:div
       :class "config-section"
       (:table
	(:tr
	 (:td "Web interface port")
	 (:td (input "web-port" *web-port*)))
	(:tr
	 (:td "Notable ports")
	 (:td (input "ports" (format nil "~{~a~^, ~}" *notable-ports*))))
	(:tr
	 (:td "Local Network")
	 (:td (input "network" (ip-string *internal-network*))))
	(:tr
	 (:td "Local Netmask")
	 (:td (input "netmask" (ip-string *internal-netmask*))))))
	 
      (:input :type "submit" :value "Apply Configuration")))))

(hunchentoot:define-easy-handler (set-config :uri "/set-config")
    (action source (web-port :parameter-type 'integer) ports filter)
  (when (and (not (running-p *collector*))
	     (string= action "run"))
    (web-run-collector *collector*))
  (cond
    ((string= action "add")
     (add-remote *collector* source)))

  ;; TODO: Restart server!
  (when web-port
    (setf *web-port* web-port))
  
  (save-config)
  (hunchentoot:redirect "/config?error=0"))

(defun print-remote-sources (&optional (collector *collector*))
  (when (remote-sources collector)
    (with-html-output (*standard-output*)
      (:table
       :class "sources"
       (:tr (:th :colspan 3 "Remote Sources"))
       (:tr (:th "Hostname") (:th "Status") (:th "Options"))	 
       (dolist (source (remote-sources collector))
	 (htm
	  (:tr (:td (str (source-path source)))
	       (:td (str
		     (if (connected-p source)
			 "Connected"
			 "Not Connected")))
	       (:td
		(:a :href (format nil "/config?action=remove&source=~a" (source-path source))
		    "Remove") " "
		(:a :href (format nil "/config?action=connect&source=~a" (source-path source))
		    (str
		     (if (connected-p source)
			 "Disconnect"
			 "Connect")))))))))))