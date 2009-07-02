(require 'asdf)
(require 'periscope)

(defun build-periscope ()
  #+sbcl (sb-ext:save-lisp-and-die "periscope" :toplevel #'periscope::main :executable t
				   :save-runtime-options t)
  #-sbcl (error "Cannot build stand-alone binary on this system!")
  t)