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
  (push (hunchentoot:create-folder-dispatcher-and-handler "/stylesheets/" "share/")
	hunchentoot:*dispatch-table*))

(defun stop-web ()
  (hunchentoot:stop *web-server*))

(defun generate-navigation ()
  "Generate Periscope's navigation."
  (with-html ()
    (:ul
     (:li (:a :href "/" "Traffic Overview"))
     (:li :class "root"
          (:a :href "#" "Traffic Pattern Reports")
          (:ul
           (:li "Nothing to see here yet!")))
     (:li :class "root"
          (:a :href "#" "Periodic Reports")
          (:ul
	   (:li "Nothing to see here yet!")))
     (:li (:a :href "/search" "Search Logs"))
     (:li (:a :href "/config" "Configuration")))))

(defmacro with-periscope-page ((title) &body body)
  "Generate a Periscope-template page."
  `(with-html (:prologue t)
     (:html
      (:head
       (:title (who:fmt "Periscope - ~a" ,title))
       (:link :href "/stylesheets/periscope.css"
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

(hunchentoot:define-easy-handler (index :uri "/index") ()
  (with-periscope-page ("Testing")
    (:h3 (who:fmt "Welcome to Periscope, version ~a!" *periscope-version*))
    "This is a pre-release version of what will eventually become Periscope 0.10.0, merged with
Argus client support.  For now, you should consider this release PRE-ALPHA software - it is
NOT meant for production use and will not be for some time; YMMV on any and all features within
this piece of software.  OSHEAN makes no guarantee to the functionality of this software at this
time."))
