;;; Some code borrowed from BABEL-TESTS. 
;;; Copyright (C) 2007-2008, Luis Oliveira  <loliveira@common-lisp.net>

(in-package :periscope)

(defpackage :periscope-test
  (:use :common-lisp :periscope :cffi :stefil))

(in-package :periscope-test)

(in-root-suite)
(defsuite* utility-tests)

(defmacro returns (form &rest values)
  "Asserts, through EQUALP, that FORM returns VALUES."
  `(is (equalp (multiple-value-list ,form) (list ,@values))))

(defmacro defstest (name form &body return-values)
  "Similar to RT's DEFTEST."
  `(deftest ,name ()
     (returns ,form ,@(mapcar (lambda (x) `',x) return-values))))

(defun fail (control-string &rest arguments)
  (stefil::record-failure 'stefil::failed-assertion
                          :format-control control-string
                          :format-arguments arguments))

(defun expected (expected &key got)
  (fail "expected ~A, got ~A instead" expected got))

(deftest ip-string-equal (ip desired-result)
  (is (string= (periscope::ip-string ip) desired-result)))

(deftest ip-netmask-string-equal (ip netmask desired-result)
  (is (string= (periscope::ip-string ip netmask) desired-result)))

(deftest ip-strings ()
  (ip-string-equal #x0a000001 "10.0.0.1")
  (ip-string-equal #xC0A80A0A "192.168.10.10")
  (ip-string-equal #xC0A8FFFE "192.168.255.254")
  (ip-netmask-string-equal #xc0a80a00 #xffffff00 "192.168.10.0/24")
  (ip-netmask-string-equal #xc0a80a00 #xfffffff0 "192.168.10.0/28")
  (ip-netmask-string-equal #x0a000000 #xff000000 "10.0.0.0/8")
  (ip-netmask-string-equal 3322406913 4294901760 "198.7.232.1/16"))

(deftest parse-ip-equals (string expected-network expected-netmask &key expected-error junk-allowed)
  (handler-case
      (multiple-value-bind (network netmask)
	  (periscope::parse-ip-string string :junk-allowed junk-allowed)
	(is (eql network expected-network))
	(is (eql netmask expected-netmask)))
    (parse-error (c)
      (unless expected-error
	(fail "Expected network ~a, netmask ~a, got ~a instead."
	      (periscope::ip-string expected-network)
	      (periscope::ip-string expected-netmask) c)))
    (:no-error (result)
      (when expected-error
	(expected 'parse-error :got result)))))

(deftest parse-ip-test ()
  (parse-ip-equals "192.168.10.0/24" #xc0a80a00 #xffffff00)
  (parse-ip-equals "192.168.10.0" #xc0a80a00 nil)
  (parse-ip-equals "198.7.232.1" #xc607e801 nil)
  (parse-ip-equals "192.168/24" nil nil :expected-error t)
  (parse-ip-equals "10.10.50.1000" nil nil :junk-allowed t)
  (parse-ip-equals "192.168.1000.10/24" nil nil :expected-error t)
  (parse-ip-equals "10.10.50.1000/24" nil nil :expected-error t))

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

(deftest date-string-equal (time expected-result)
  (is (string-equal (periscope::utc-date-string time) expected-result)))

(deftest date-string-test ()
  (date-string-equal 3454759813 "2009-06-23 11:30")
  (date-string-equal 3254059813 "2003-02-12 12:30"))

(deftest vlan-name-tests ()
  (let ((periscope::*vlan-names* (make-hash-table)))
    (is (= 100 (periscope::vlan-name 100)))
    (is (= 2000 (periscope::vlan-name 2000)))
    (is (string= (setf (periscope::vlan-name 400) "TEST1") "TEST1"))
    (is (string= (periscope::vlan-name 400) "TEST1"))
    (setf (periscope::vlan-name 400) nil)
    (is (= 400 (periscope::vlan-name 400)))))