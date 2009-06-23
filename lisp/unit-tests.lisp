;;; Some code borrowed from BABEL-TESTS. 
;;; Copyright (C) 2007-2008, Luis Oliveira  <loliveira@common-lisp.net>

(in-package :periscope)

(defpackage :periscope-test
  (:use :common-lisp :periscope :cffi :stefil))

(in-package :periscope-test)

(in-root-suite)
(defsuite* periscope-tests)

(defmacro returns (form &rest values)
  "Asserts, through EQUALP, that FORM returns VALUES."
  `(is (equalp (multiple-value-list ,form) (list ,@values))))

(defmacro defstest (name form &body return-values)
  "Similar to RT's DEFTEST."
  `(deftest ,name ()
     (returns ,form ,@(mapcar (lambda (x) `',x) return-values))))

(deftest ip-string-equal (ip desired-result)
  (is (string= (periscope::ip-string ip) desired-result)))

(deftest ip-strings ()
  (ip-string-equal #x0a000001 "10.0.0.1")
  (ip-string-equal #xC0A80A0A "192.168.10.10")
  (ip-string-equal #xC0A8FFFE "192.168.255.254"))

(deftest service-name-test ()
  #+linux
  (progn
    (is (string-equal (periscope::service-name 22) "ssh"))
    (is (string-equal (periscope::service-name 21) "ftp"))
    (is (string-equal (periscope::service-name 123 :protocol :tcp) "ntp"))
    (is (string-equal (periscope::service-name 123 :protocol :udp) "ntp"))
    (is (string-equal (periscope::service-name 161) "snmp"))))

(deftest byte-string-equal (bytes desired-result &key (precision 2))
  (is (string= (periscope::byte-string bytes precision) desired-result)))

(deftest byte-string-test ()
  (byte-string-equal 1024 "1.00 kB")
  (byte-string-equal 1023 "1,023 B")
  (byte-string-equal 10240 "10.00000 kB" :precision 5)
  (byte-string-equal 124125161 "118.37 MB"))

(deftest network-member-test ()
  (is (periscope::network-member-p #x0a000001 #x0a000000 #xffffff00))
  (is (not (periscope::network-member-p #x0a010001 #x0a000000 #xffffff00)))
  (is (not (periscope::network-member-p #x0f000001 #x0a000000 #xffffff00)))
  (is (periscope::network-member-p #xc0a80a0f #xc0a80000 #xffff0000)))