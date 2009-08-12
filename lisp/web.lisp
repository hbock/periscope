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

(defun start-web (&key (port *web-port*))
  "Start the web interface server on PORT and add a folder dispatcher for the /content directory."
  (when *web-server*
    (hunchentoot:stop *web-server*))

  (setf *web-server* (make-instance 'hunchentoot:acceptor :port port))
  (hunchentoot:start *web-server*)
  (push (hunchentoot:create-folder-dispatcher-and-handler "/content/" "share/")
	hunchentoot:*dispatch-table*))

(defun stop-web ()
  "Stop the web interface server."
  (hunchentoot:stop *web-server*))

(defun restart-web ()
  "Restart the web interface."
  (stop-web)
  (start-web))

(defun web-run-collector (&optional (collector *collector*))
  "Helper function to run a collector from the web interface.
Starts a separate thread to run the collector and handle its callbacks."
  (bt:make-thread
   (lambda ()
     (run collector)) :name "Periscope Collector"))

;;; HTML generation helper functions and macros.
(defmacro with-html ((&key prologue) &body body)
  `(who:with-html-output-to-string (*standard-output* nil :prologue ,prologue :indent t)
     ,@body))

(defun generate-navigation ()
  "Generate Periscope's navigation sidebar."
  (with-html ()
    (when (or (not (login-required-p)) (valid-session-p))
      (cond
	((valid-session-p)
	 (htm (:ul (:li (:a :href "/do-login?action=logout"
			    (fmt "Log out (~A)" (display-name (user))))))))
      
	((login-available-p)
	 (htm (:ul (:li (:a :href "/login" "Login"))))))

      (htm
       (:ul
	(:li (:a :href "/" "Periscope Home"))
	(:li :class "root"
	     "Reports"
	     (:ul
	      (loop :for (type uri description) :in
		 (sort (copy-seq *report-handler-list*) #'string< :key #'third) :do
		 (htm (:li (:a :href uri (str description)))))))
	(:li :class "root"
	     "Utilities"
	     (:ul
	      (:li (:a :href "/service-names" "Service Names"))))
	(when (configure-p)
	  (htm
	   (:li :class "root"
		"Configuration"
		(:ul
		 (:li (:a :href "/periscope-config" "Periscope Settings"))
		 (:li (:a :href "/network-config" "Network Settings"))
		 (:li (:a :href "/users" "Manage User Logins"))

		 (when *web-show-diag*
		   (htm (:li (:a :href "/uuddlrlrbastart" "Diagnostics Panel")))))))))))))

(defmacro with-periscope-page ((title &key login admin onload) &body body)
  "Generate a Periscope-template page."
  `(progn
     ,(if (or admin login)
	  `(valid-session-or-lose :admin ,admin)
	  `(when (login-required-p)
	     (valid-session-or-lose)))
     (with-html (:prologue t)
       (:html
	(:head
	 (:title (who:fmt "Periscope - ~a" ,title))
	 (:link :href "/content/periscope.css"
		:rel "stylesheet"
		:type "text/css")
	 (:script :type "text/javascript" :src "/content/periscope.js"))
	(:body
	 ,@(when onload `(:onload ,onload))
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
			  "Argus"))))))))))

(defmacro with-config-section ((title &optional name) &body body)
  "Output a pretty Periscope configuration form."
  `(with-html-output (*standard-output*)
     (when ,name
       (htm (:a :name ,name)))
     (:div :class "config-header" (str ,title))
     (:div :class "config-section" ,@body)))

(defmacro with-config-form ((uri &key (method :post)) &body body)
  `(with-html-output (*standard-output*)
     (:form
      :action ,uri :method ,(ecase method (:post "post") (:get "get"))
      ,@body)))

(defun error-redirect (type &rest more-params)
  (let ((*print-case* :downcase))
    (hunchentoot:redirect
     ;; This is an ABOMINATION, yet it is pretty awesome all the same.
     (format nil "~a?error=~a~:[~;&~:*~{~a=~a~^&~}~]" *redirect-page* type
	     (mapcar (lambda (param)
		       (if (stringp param) (url-encode param) param)) more-params)))))

(defun empty-string-p (&rest strings)
  "Returns true if string has no useful string data; i.e., it is NIL, empty, or is composed
solely of whitespace."
  (every (lambda (string)
	   (or (null string) (zerop (length (string-trim #(#\Space #\Newline #\Tab) string)))))
	 strings))

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

(defun input-name (name &optional index)
  (format nil "~a~:[~;~:*[~d]~]" name index))

(defun hidden (name value &key index)
  (with-html-output (*standard-output*)
    (:input :type "hidden" :name (input-name name index) :value value)))

(defun checkbox (name &key (value name) (checked nil) index)
  "Generate an HTML checkbox."
  (with-html-output (*standard-output*)
    (:input :type "checkbox" :name (input-name name index) :value value :checked checked)))

(defun submit (&optional text)
  (with-html-output (*standard-output*)
    (:input :type "submit" :value text)))

(defun input (name default &key (size 20) label disabled index id)
  (with-html-output (*standard-output*)
    (when label
      (htm (:label :for name (str label))))
    (:input :type "text" :id id :name (input-name name index)
	    :value default :size size :disabled disabled)))

(defun password-input (name &key default (size 20) index)
  (with-html-output (*standard-output*)
    (:input :type "password" :name (input-name name index) :value default :size size)))

(defun next-token (string &optional (char-bag '(#\Space #\Tab)))
  (let ((string (string-left-trim char-bag string)))
    (loop :for i :from 0 :below (length string)
       :until (member (char string i) char-bag)
       :finally (return (values (subseq string 0 i)
				(subseq string i))))))

(defun tokenize (string &optional (char-bag '(#\Space #\Tab)))
  (let (tokens)
    (loop :until (zerop (length string))
       :do (multiple-value-bind (token rest)
	              (next-token string char-bag)
	          (when (plusp (length token))
		           (push token tokens))
		       (setf string rest)))
    (nreverse tokens)))

(defun parse-integer-list (string regex bad-predicate)
  "Parse string into a list of integers, separated by commas and/or spaces, removing duplicates.
If string is not matched by regex, or any entry matches bad-predicate, this function signals a
PARSE-ERROR."
  (unless (ppcre:scan regex string)
    (error 'parse-error))
  (let ((integers
	 (mapcar (lambda (integer) (parse-integer integer :junk-allowed t))
		 (tokenize string '(#\Space #\, #\Tab #\Newline)))))
    (when (some bad-predicate integers)
      (error 'parse-error))
    (sort (remove-duplicates integers) #'<)))
