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

(defmacro with-html ((&key (prologue nil)) &body body)
  `(who:with-html-output-to-string (*standard-output* nil :prologue ,prologue :indent t)
     ,@body))

(defun start-web (&key (port *web-port*))
  (when (null *web-server*)
    (setf *web-server* (make-instance 'hunchentoot:acceptor :port port)))
  (hunchentoot:start *web-server*)
  (push (hunchentoot:create-folder-dispatcher-and-handler "/content/" "share/")
	hunchentoot:*dispatch-table*))

(defun stop-web ()
  (hunchentoot:stop *web-server*))

(defun web-run-collector (&optional (collector *collector*))
  "Helper function to run a collector from the web interface.
Starts a separate thread to run the collector and handle its callbacks."
  (bt:make-thread
   (lambda ()
     (run collector)) :name "Periscope Collector"))

(defmacro warning-box (&rest forms)
  `(who:with-html-output (*standard-output*)
     (:div :class "warning"
	   (:img :src "/content/warning.png")
	   ,@forms)))

(defun y-or-n-radio (name default &key (on "On") (off "Off"))
  (with-html-output (*standard-output*)
    (:label :for name (str on))
    (:input :type "radio" :name name :value "true" :checked default)
    (:label :for name (str off))
    (:input :type "radio" :name name :value "false" :checked (not default))))

(defun input (name default &key (size 20) label)
  (with-html-output (*standard-output*)
    (when label
      (htm (:label :for name (str label))))
    (:input :type "text" :name name :value default :size size)))

(defun generate-navigation ()
  "Generate Periscope's navigation sidebar."
  (with-html ()
    (:ul
     (:li (:a :href "/" "Periscope Home"))
     (:li (:a :href "/traffic" "Traffic Overview"))
     (:li :class "root"
          "Traffic Pattern Reports"
          (:ul
	   (loop :for (type uri description) :in
	      (sort (copy-seq *report-handler-list*) #'string< :key #'third) :do
	      (htm (:li (:a :href uri (str description)))))))
     (:li :class "root"
          "Periodic Reports"
          (:ul
	   (:li "Nothing to see here yet!")))
     (:li :class "root"
          "Utilities"
          (:ul
	   (:li (:a :href "/service-names" "Service Names"))))
     (:li (:a :href "/search" "Search Logs"))
     (:li (:a :href "/config" "Control Panel"))
     (when *web-show-diag*
       (htm (:li (:a :href "/uuddlrlrbastart" "Diagnostics Panel")))))))

(defmacro with-periscope-page ((title) &body body)
  "Generate a Periscope-template page."
  `(with-html (:prologue t)
     (:html
      (:head
       (:title (who:fmt "Periscope - ~a" ,title))
       (:link :href "/content/periscope.css"
	      :rel "stylesheet"
	      :type "text/css"))
      (:body
       (:table
	(:tr
	 (:td :colspan "2" :id "header"
	      (:h1 "Periscope")
	      (who:fmt "Version ~a" *periscope-version*)))
	(:tr :id "body"
	     (:td :id "sidebar" (who:str (generate-navigation)))
	     (:td :id "wrapper"
		  ,@body))
	(:tr
	 (:td :colspan "2"
	      (:div :id "footer"
		    (:a :href "/about" "About Periscope") " | "
		    (:a :href "http://oshean.org/" :target "_blank" "OSHEAN") " | "
		    (:a :href "http://nautilus.oshean.org/" :target "_blank" "Nautilus") " | "
		    (:a :href "http://nautilus.oshean.org/wiki/Periscope" :target "_blank"
			"Periscope") " | "
		    (:a :href "http://qosient.com/argus" :target "_blank"
			"Argus")))))))))