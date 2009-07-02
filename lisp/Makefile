all: periscope

# TODO: Make this portable across Lisp implementations.
periscope: *.lisp
	sbcl --load "build.lisp" --eval "(build-periscope)"
	echo "Build complete!"

clean:
	rm -f *.fasl *~ periscope
