# Find suitable lisp for building Periscope.
ifeq (${LISP},)
  ifeq ($(strip $(shell which clbuild)),)
    LISP = sbcl
  else
    LISP = clbuild lisp
  endif
endif

all: periscope

# TODO: Make this portable across Lisp implementations.
periscope: *.lisp
	${LISP} --load "build.lisp" --eval "(build-periscope)"
	@echo "Build complete!"

clean:
	rm -f *.fasl *~ periscope
