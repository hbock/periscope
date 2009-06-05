(in-package :periscope)

(defmacro with-html (&body body)
  `(who:with-html-output (*standard-output* nil :prologue t)
     ,@body))

(defun start-web (&key (port *web-port*))
  (when (null *web-server*)
    (setf *web-server* (make-instance 'hunchentoot:acceptor :port port)))
  (hunchentoot:start *web-server*))

(defun stop-web ()
  (hunchentoot:stop *web-server*))

(hunchentoot:define-easy-handler (index :uri "/index") ()
  (with-html
    (:html
     (:body "Hello, Periscope!"))))