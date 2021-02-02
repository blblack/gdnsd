# trivial PYCHECK and PYCHECK_MODVER just barely suitable for our own uses.
# The similar AX ones all had issues that would need patching anyways.
AC_DEFUN([PYCHECK],[
  AC_MSG_CHECKING([$1])
  AS_IF([test -n "$PYTHON" && AC_RUN_LOG([$PYTHON -c $2])],[
    AC_MSG_RESULT([yes])
    $3
  ],[
    AC_MSG_RESULT([no])
    $4
  ])
])
AC_DEFUN([PYCHECK_MODVER],[
  PYCHECK([for python module $1 >= $2],
    ["import sys, $1; from distutils.version import StrictVersion; sys.exit(StrictVersion($1.__version__) < StrictVersion('$2'))"],
    [$3],[$4]
  )
])
