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

(defclass web-user ()
  ((username :initarg :username :accessor username)
   (display-name :initarg :display-name :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :initarg :password-hash :accessor password-hash :initform nil)
   (privileges :accessor privileges :initform nil)
   (filters :accessor filters :initform nil)
   (session-id :accessor session-id)))

(defun hash-sequence (sequence)
  (md5:md5sum-sequence sequence))

(defun create-login (username password display-name &key (title "User"))
  (multiple-value-bind (user existsp)
      (gethash username *web-user-db*)
    (declare (ignore user))
    (if existsp
	(error "Username ~a already exists." username)
	(let ((user (make-instance 'web-user
				   :username username
				   :display-name display-name
				   :password-hash (hash-sequence password)
				   :title title)))
	  (setf (gethash username *web-user-db*) user)))))

(defun user (&optional username)
  (if username
      (gethash username *web-user-db*)
      (first (user-list))))

(defun login-available-p ()
  "Return true if logins are available (i.e., at least one user login)."
  (plusp (hash-table-count *web-user-db*)))

(defun valid-session-p ()
  "Return true if the current Periscope login session exists and is valid."
  (let ((username (hunchentoot:session-value 'username))
	(userhash (hunchentoot:session-value 'userhash)))
    (when (and username userhash (equalp userhash (hash-sequence username)))
      (multiple-value-bind (user existsp)
	  (gethash username *web-user-db*)
	(and existsp (not (null (session-id user))))))))

(defun login-required-p ()
  "Returns true if logins are generally required to access the Periscope web interface."
  (and *web-login-required-p* (login-available-p)))

(defun valid-session-or-lose ()
  "If logins are required and no valid session is available, redirect to the login page."
  (unless (or (not (login-available-p)) (valid-session-p))
    (hunchentoot:redirect "/login?denied=login"))
  t)

(defun user-list ()
  "Returns all users in the database."
  (loop :for username :being :the :hash-keys :in *web-user-db* :using (:hash-value user)
     :collect user))

(hunchentoot:define-easy-handler (login :uri "/login")
    (denied redirect)
  
  (unless (login-available-p)
    (hunchentoot:redirect "/"))
  
  (let ((*web-login-required-p* nil))
    (with-periscope-page ("Login")
      (cond
	((string= denied "login")
	 (warning-box (:p :class "denied" "You must be logged in to see this page.")))
	((string= denied "bad")
	 (warning-box (:p :class "denied" "Invalid credentials. Please try again."))))
      (with-config-form ("/do-login" "Log in to Periscope" "login")
	(:table
	 :class "input"
	 (:tr
	  (:td "Username")
	  (:td (input "username" "")))
	 (:tr
	  (:td "Password")
	  (:td (:input :type "password" :name "password" :size 20))))
	(when (and denied redirect)
	  (htm (:input :type "hidden" :name "redirect" :value redirect)))
	(:input :type "submit" :value "Login")))))

(hunchentoot:define-easy-handler (user-config :uri "/users") ()
  (with-periscope-page ("User Login Configuration" :login t)
    (with-config-form ("/set-user-config" "Login Configuration" "configure")
      (:table
       (:tr
	(:td "Require login for all pages")
	(:td (checkbox "required" :checked *web-login-required-p*))))
      (:br)
      (:input :type "submit" :value "Apply Configuration"))

    (when (login-available-p)
      (with-config-form ("/set-user-config" "User Logins" "manage")
	(:table
	 :class "input"
	 (:tr (:th "Username") (:th "Display Name") (:th "Remove User"))
	 (loop
	    :with i = 0
	    :for user :in (user-list) :do
	    (let ((username (username user)))
	      (htm
	       (:tr (:td (str username))
		    (:td (input (format nil "name[i]" i) (display-name user)))
		    (:td (checkbox (format nil "delete[~d]" i) :value username))))
	      (incf i))))
	(:br)
	(:input :type "submit" :value "Apply Configuration")))

    (with-config-form ("/set-user-config" "Add New User" "newuser")
      (:table
       (:tr (:th :colspan 2 "Login Information"))
       (:tr
	(:td "Username")
	(:td (input "username" "")))
       (:tr
	(:td "Display Name")
	(:td (input "displayname" "")))
       (:tr
	(:td "Password")
	(:td (:input :type "password" :name "password1" :size 20)))
       (:tr
	(:td "Password (re-type)")
	(:td (:input :type "password" :name "password2" :size 20)))
       (:tr (:th :colspan 2 "Permissions and Filters"))
       (:tr
	(:td "Subnet Filter (CIDR notation)")
	(:td (input "subnet" "" :size 18)))
       (:tr
	(:td "VLAN Filter")
	(:td (input "vlan" "" :size 4)))
       (:tr
	(:td "Allow Configuration")
	(:td (checkbox "configp"))))
      (:br)
      (:input :type "submit" :value "Add User"))))

(hunchentoot:define-easy-handler (do-login :uri "/do-login")
    (username password redirect action)
  (flet ((bad-login () (hunchentoot:redirect "/login?denied=bad"))
	 (process-login (user password)
	   (when (equalp (hash-sequence password) (password-hash user))
	     (setf (session-id user) (hunchentoot:next-session-id *web-server*)) 
	     (hunchentoot:start-session)
	     (setf (hunchentoot:session-value 'userhash) (hash-sequence username)
		   (hunchentoot:session-value 'username) username))))
    
    (cond
      ((valid-session-p)
       (if (string= action "logout")
	   (progn
	     (setf (session-id (user)) nil)
	     (hunchentoot:reset-sessions))
	   (hunchentoot:redirect "/")))
      
      ((and username password (login-available-p))
       (let ((user (user username)))
	 (if user
	     (unless (process-login user password)
	       (bad-login))
	     (bad-login)))))

    (if (and redirect (valid-session-p))
	(hunchentoot:redirect redirect)
	(hunchentoot:redirect "/"))))

(hunchentoot:define-easy-handler (set-user-config :uri "/set-user-config")
    (action username displayname password1 password2 subnet vlan configp
	    required (delete :parameter-type 'array))
  (valid-session-or-lose)

  (flet ((config-error (type)
	   (hunchentoot:redirect (format nil "/users?error=~a" type))))
  
    (cond
      ((string= action "configure")
       (setf *web-login-required-p* (not (null required))))

      ((string= action "manage")
       (when (and delete (arrayp delete))
	 (loop :with to-delete = (remove nil delete)
	    :for i :from 0 :below (length to-delete) :when (user (aref to-delete i)) :do
	    (when (string= (username (user)) (aref to-delete i))
	      (hunchentoot:remove-session))
	    (remhash (aref to-delete i) *web-user-db*))))

      ((string= action "newuser")
       (unless username (config-error "username"))
       (unless displayname (config-error "dispname"))

       (unless (and password1 password2 (plusp (length password1)) (plusp (length password2)))
	 (config-error "nopassword"))
       
       (unless (string= password1 password2)
	 (config-error "passmatch"))
       
       (when (and subnet (plusp (length subnet)))
	 (handler-case
	     (parse-ip-string subnet)
	   (parse-error (e)
	     (declare (ignore e))
	     (config-error "subnet"))))

       (create-login username password1 displayname))))
  (hunchentoot:redirect "/users"))