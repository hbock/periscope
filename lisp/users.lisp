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
  '(simple-vector 16))

(defclass web-user ()
  ((username :initarg :username :accessor username)
   (display-name :initarg :display-name :accessor display-name)
   (title :initarg :title :accessor title)
   (password-hash :initarg :password-hash :accessor password-hash :initform nil)
   (admin :initarg :admin-p :accessor admin-p :initform nil)
   (filters :accessor filters :initform nil)
   (session :accessor session :initform nil)))

(defun hash-sequence (sequence)
  (md5:md5sum-sequence sequence))

(defun create-login (username password display-name &key (title "User") admin)
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
				   :title title
				   :admin-p admin)))
	  (setf (gethash username *web-user-db*) user)))))

(defun user (&optional username)
  (if username
      (gethash username *web-user-db*)
      (when (boundp 'hunchentoot:*session*)
	(gethash (hunchentoot:session-value 'username) *web-user-db*))))

(defun login-available-p ()
  "Return true if logins are available (i.e., at least one user login)."
  (plusp (hash-table-count *web-user-db*)))

(defun valid-session-p (&key admin)
  "Return true if the current Periscope login session exists and is valid."
  (let ((username (hunchentoot:session-value 'username))
	(userhash (hunchentoot:session-value 'userhash)))
    (when (and username userhash (equalp userhash (hash-sequence username)))
      (multiple-value-bind (user existsp)
	  (gethash username *web-user-db*)
	(and existsp (not (null (session user))) (or (not admin) (admin-p user)))))))

(defun login-required-p ()
  "Returns true if logins are generally required to access the Periscope web interface."
  (and *web-login-required-p* (login-available-p)))

(defun valid-session-or-lose (&key admin)
  "If logins are required and no valid session is available, redirect to the login page."
  (when (login-available-p)
    (cond
      ((not (valid-session-p))
       (hunchentoot:redirect (format nil "/login?denied=login&redirect=~a"
				     (hunchentoot:script-name hunchentoot:*request*))))
    
      ((and admin (not (admin-p (user))))
       (hunchentoot:redirect "/nowhere"))))
  t)

(defun user-list ()
  "Returns all users in the database."
  (loop :for username :being :the :hash-keys :in *web-user-db* :using (:hash-value user)
     :collect user))

(defun logout (&optional (user (user)))
  (when (and user (session user))
    (hunchentoot:remove-session (session user))
    (setf (session user) nil)))

(defmethod logged-in-p ((user web-user))
  (not (null (session user))))

(defun create-login-forms (&optional (db *web-user-db*))
  `(progn
     ,@(loop :for username :being :the :hash-keys :in db :using (:hash-value user) :collect
	  `(create-login ,username ,(password-hash user) ,(display-name user)
			 :admin ,(admin-p user)))))

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


(defun edit-user-form (title action &key user error)
  (with-config-form ("/set-user-config" title action)
    (:table
     (:tr (:th :colspan 2 "Login Information"))
     (when (string= error "username")
       (error-message "You must specify a username."))
     (if user
	 (htm (:input :type "hidden" :name "username" :value (username user)))
	 (htm
	  (:tr
	   (:td "Username")
	   (:td (input "username" (if user (username user) "") :disabled (not (null user)))))))
     (when (string= error "dispname")
       (error-message "You must specify a display name (e.g., Don Schattle)."))
     (:tr
      (:td "Display Name")
      (:td (input "displayname" (if user (display-name user) ""))))
     (cond ((string= error "nopassword")
	    (error-message "You must fill in BOTH password fields."))
	   ((string= error "passmatch")
	    (error-message "Passwords do not match!")))
     (:tr
      (:td "Password")
      (:td (password-input "password1")))
     (:tr
      (:td "Password (re-type)")
      (:td (password-input "password2")))

     (:tr (:th :colspan 2 "Permissions and Filters"))
     (when (string= error "subnet")
       (error-message "Invalid CIDR network specification!"))
     (:tr
      (:td "Subnet Filter (CIDR notation)")
      (:td (input "subnet" "" :size 18)))
     (:tr
      (:td "VLAN Filter")
      (:td (input "vlan" "" :size 4)))
     (:tr
      (:td "Administrator privileges")
      (:td (checkbox "configp" :checked (when user (admin-p user))))))
    (:br)
    (:input :type "submit" :value "Commit Changes")))

(hunchentoot:define-easy-handler (edit-user :uri "/edit-user") (error user)
  (with-periscope-page ("Edit User" :admin t)
    (let ((user (user user)))
      (if user
	  (edit-user-form (format nil "Edit User [~a]" (username user)) "edituser"
			  :user user :error error)
	  (hunchentoot:redirect "/users")))))

;;; Errors:
;;;  - "username": Empty username.
;;;  - "dispname": Empty display name.
;;;  - "nopassword": Empty password field(s).
;;;  - "passmatch": Passwords don't match.
;;;  - "subnet": Invalid subnet specifier.
;;;  - "unadminself": Tried to remove administrator from own account.
(hunchentoot:define-easy-handler (user-config :uri "/users") (error edit add)
  (with-periscope-page ("User Login Configuration" :admin t)
    (with-config-form ("/set-user-config" "Login Configuration" "configure")
      (:table
       (:tr
	(:td "Require login for all pages")
	(:td (checkbox "required" :checked *web-login-required-p*))))
      (:br)
      (:input :type "submit" :value "Apply Configuration"))

    (when (login-available-p)
      (with-config-form ("/set-user-config" "User Logins" "manage")
	(cond
	  ((string= error "unadminself")
	   (error-message "Error: You cannot remove administrator privileges from your own
account." :table nil))
	  ((and (string= error "success"))
	   (cond
	     ((not (empty-string-p edit))
	      (htm (:p (:b (fmt "Edited user '~a' successfully!" edit)))))
	     ((not (empty-string-p add))
	      (htm (:p (:b (fmt "Added new user '~a' successfully!" add))))))))
	(:table
	 :class "input"
	 (:tr (:th "Username ") (:th "Display Name") (:th "Administrator")
	      (:th "Edit User") (:th "Remove User"))
	 (loop
	    :with i = 0
	    :for user :in (user-list) :do
	    (let ((username (username user)))
	      (htm
	       (:tr
		(:td
		 (:b (str username))
		 (:input :type "hidden" :name (format nil "user[~d]" i) :value username))
		(:td (str (display-name user)))
		(:td (str (if (admin-p user) "Yes" "No")))
		(:td (:a :href (format nil "/edit-user?user=~a" username) "Edit"))
		(:td (checkbox (format nil "delete[~d]" i) :value username))))
	      (incf i))))
	(:br)
	(:input :type "submit" :value "Apply Configuration")))

    (edit-user-form "Add New User" "newuser" :error error)))

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


(defun vlans-from-string (vlan-string)
  "Take a string of VLAN identifiers, separated by spaces and/or commas, and return a sorted list
of integers corresponding to these numbers.  Duplicate and invalid VLAN IDs are removed."
  (parse-integer-list vlan-string (lambda (vlan) (or (zerop vlan) (> vlan 4095)))))

(hunchentoot:define-easy-handler (set-user-config :uri "/set-user-config")
    (action username displayname password1 password2 subnet vlan configp
	    required
	    (user :parameter-type 'array)
	    (delete :parameter-type 'array)
	    (admin  :parameter-type 'array))
  (valid-session-or-lose :admin t)

  (let ((*redirect-page* "/users"))
    (cond
      ((string= action "configure")
       (setf *web-login-required-p* (not (null required))))

      ((string= action "manage")
       (loop
	  :for i :from 0 :below (length user) :do
	  (let ((u (user (aref user i))))
	    (cond
	      ((and (> (length delete) i) (aref delete i))
	       ;; If the user deletes a logged-in user, he must be logged off,
	       ;; so remove session.
	       (logout u)
	       (remhash (username u) *web-user-db*))))))

      ((string= action "newuser")
       (cond
	 ((empty-string-p username) (error-redirect "username"))
	 ((empty-string-p displayname) (error-redirect "dispname"))

	 ((not (and password1 password2 (plusp (length password1)) (plusp (length password2))))
	  (error-redirect "nopassword"))
       
	 ((string/= password1 password2)
	  (error-redirect "passmatch"))
       
	 ((and subnet (plusp (length subnet)))
	  (handler-case
	      (parse-ip-string subnet)
	    (parse-error (e)
	      (declare (ignore e))
	      (error-redirect "subnet")))))

       (create-login username password1 displayname :admin (not (null configp)))
       (error-redirect "success" :add username))))
  
  (when (string= action "edituser")
    (let ((*redirect-page* "/edit-user")
	  (user (user username)))
      (cond
	((null user)
	 (hunchentoot:redirect "/users"))

	((empty-string-p displayname)
	 (error-redirect "dispname" :user username))

	((not (empty-string-p password1 password2))
	 (unless (string= password1 password2)
	   (error-redirect "passmatch" :user username))
	 (setf (password-hash user) (hash-sequence password1))))

      (if (string= username (username (user)))
	  (error-redirect "unadminself")
	  (setf (admin-p user) (not (null configp))))

      (setf (display-name user) displayname)
      
      (save-config)
      (let ((*redirect-page* "/users"))
	(error-redirect "success" :edit (username user)))))
  
  (save-config)
  (hunchentoot:redirect "/users?error=success"))