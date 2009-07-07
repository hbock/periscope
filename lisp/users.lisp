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

(deftype md5sum ()
  '(simple-array (unsigned-byte 8) (16)))

(defclass web-user ()
  ((username :initarg :username :accessor username)
   (display-name :initarg :display-name :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :initarg :password-hash :accessor password-hash :initform nil)
   (privileges :accessor privileges :initform nil)
   (filters :accessor filters :initform nil)
   (session :accessor session :initform nil)))

(defun hash-sequence (sequence)
  (md5:md5sum-sequence sequence))

(defun create-login (username password display-name &key (title "User"))
  "Create a web-user login.  The password may be a string or an array containing an
MD5 sum of a password.  If passed as a string, the password will be hashed and stored
as an MD5 sum."
  (multiple-value-bind (user existsp)
      (gethash username *web-user-db*)
    (declare (ignore user))
    (if existsp
	(error "Username ~a already exists." username)
	(let ((user (make-instance 'web-user
				   :username username
				   :display-name display-name
				   :password-hash
				   (etypecase password
				     (string (hash-sequence password))
				     (md5sum password))
				   :title title)))
	  (setf (gethash username *web-user-db*) user)))))

(defun user (&optional username)
  (if username
      (gethash username *web-user-db*)
      (when (boundp 'hunchentoot:*session*)
	(gethash (hunchentoot:session-value 'username) *web-user-db*))))

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
	(and existsp (not (null (session user))))))))

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

(defun logout (&optional (user (user)))
  (when user
    (hunchentoot:remove-session (session user))
    (setf (session user) nil)))

(defmethod logged-in-p ((user web-user))
  (not (null (session user))))

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
	  (:td (password-input "password"))))
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
		    (:td (input (format nil "name[~d]" i) (display-name user)))
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
	(:td (password-input "password1")))
       (:tr
	(:td "Password (re-type)")
	(:td (password-input "password2")))

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
	     (setf (session user) (hunchentoot:start-session))
	     (setf (hunchentoot:session-value 'userhash) (hash-sequence username)
		   (hunchentoot:session-value 'username) username))))
    
    (cond
      ((valid-session-p)
       (if (string= action "logout")
	   (logout)
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
	 (let ((to-delete (remove nil delete)))
	   (loop 
	      :for i :from 0 :below (length to-delete) :do
	      (let ((user (user (aref to-delete i))))
		;; If the user deletes a logged-in user, he must be logged off,
		;; so remove session.
		(logout user)
		(remhash (username user) *web-user-db*))))))

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